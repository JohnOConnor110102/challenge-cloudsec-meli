import { setTimeout as sleep } from 'node:timers/promises';
import { isCveId, isNvdApiKey, MAX_PAGE_SIZE, parseNvdPage } from './validation.js';
import type { NvdCve, NvdPage } from './validation.js';

const BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const REQUEST_INTERVAL_MS = 6_100;
const MAX_ATTEMPTS = 3;
const MAX_RETRY_DELAY_MS = 60_000;
const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;

type ErrorCode = 'HTTP' | 'TIMEOUT' | 'NETWORK' | 'INVALID_RESPONSE';
const messages: Record<ErrorCode, string> = {
  HTTP: 'NVD rechazó la solicitud',
  TIMEOUT: 'NVD excedió el tiempo de respuesta',
  NETWORK: 'No se pudo conectar con NVD',
  INVALID_RESPONSE: 'Respuesta NVD inválida',
};

export class NvdError extends Error {
  constructor(
    readonly code: ErrorCode,
    readonly status?: number,
    readonly retryAfterMs?: number,
  ) {
    super(messages[code]);
    this.name = 'NvdError';
  }
}

interface Options {
  apiKey?: string | undefined;
  timeoutMs?: number;
}

interface Runtime {
  fetch: typeof fetch;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
}

interface PageOptions {
  startIndex?: number;
  resultsPerPage?: number;
}

function retryAfter(value: string | null): number | undefined {
  if (value === null) return undefined;
  if (/^\d+$/.test(value)) return Number(value) * 1_000;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? Math.max(0, timestamp - Date.now()) : undefined;
}

async function readJson(response: Response): Promise<unknown> {
  if (response.status !== 200
    || !/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '')
    || response.body === null) {
    await response.body?.cancel();
    throw new NvdError('INVALID_RESPONSE');
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new NvdError('INVALID_RESPONSE');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
  } catch {
    throw new NvdError('INVALID_RESPONSE');
  }
}

export class NvdClient {
  readonly #apiKey: string | undefined;
  readonly #timeoutMs: number;
  readonly #runtime: Runtime;
  #queue: Promise<void> = Promise.resolve();
  #nextRequestAt = 0;
  #cooldownStatus: number | undefined;

  constructor(options: Options = {}, runtime: Partial<Runtime> = {}) {
    if (options.apiKey !== undefined && !isNvdApiKey(options.apiKey)) {
      throw new Error('NVD_API_KEY tiene un valor inválido');
    }
    const timeoutMs = options.timeoutMs ?? 15_000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) {
      throw new Error('El timeout NVD debe estar entre 1 y 60000 ms');
    }
    this.#apiKey = options.apiKey;
    this.#timeoutMs = timeoutMs;
    this.#runtime = { fetch, sleep, now: () => performance.now(), ...runtime };
  }

  async getCve(id: string): Promise<NvdCve | null> {
    if (!isCveId(id)) throw new Error('El identificador CVE tiene un formato inválido');
    const url = new URL(BASE_URL);
    url.searchParams.set('cveId', id);
    const page = await this.#request(url);
    if (page.startIndex !== 0 || page.totalResults > 1 || page.cves.length > 1
      || (page.cves[0] !== undefined && page.cves[0].id !== id)) {
      throw new NvdError('INVALID_RESPONSE');
    }
    return page.cves[0] ?? null;
  }

  async getPage(options: PageOptions = {}): Promise<NvdPage> {
    const startIndex = options.startIndex ?? 0;
    const resultsPerPage = options.resultsPerPage ?? MAX_PAGE_SIZE;
    if (!Number.isSafeInteger(startIndex) || startIndex < 0
      || !Number.isSafeInteger(resultsPerPage) || resultsPerPage < 1 || resultsPerPage > MAX_PAGE_SIZE) {
      throw new Error('Los parámetros de paginación NVD son inválidos');
    }
    const url = new URL(BASE_URL);
    url.searchParams.set('startIndex', String(startIndex));
    url.searchParams.set('resultsPerPage', String(resultsPerPage));
    const page = await this.#request(url);
    if (page.startIndex !== startIndex || page.resultsPerPage > resultsPerPage) {
      throw new NvdError('INVALID_RESPONSE');
    }
    return page;
  }

  async *pages(options: PageOptions = {}): AsyncGenerator<NvdPage> {
    let startIndex = options.startIndex ?? 0;
    while (true) {
      const page = await this.getPage({ ...options, startIndex });
      yield page;
      startIndex += page.cves.length;
      if (startIndex >= page.totalResults) return;
    }
  }

  #request(url: URL): Promise<NvdPage> {
    const result = this.#queue.then(async () => {
      for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        try {
          return await this.#attempt(url);
        } catch (error) {
          if (!(error instanceof NvdError)) throw error;
          const transient = error.code === 'NETWORK' || error.code === 'TIMEOUT'
            || (error.code === 'HTTP' && (error.status === 429 || (error.status !== undefined && error.status >= 500)));
          if (!transient || attempt === MAX_ATTEMPTS - 1) throw error;
          const delay = error.retryAfterMs ?? REQUEST_INTERVAL_MS * 2 ** attempt;
          if (delay > MAX_RETRY_DELAY_MS) throw error;
          this.#nextRequestAt = Math.max(this.#nextRequestAt, this.#runtime.now() + delay);
        }
      }
      throw new NvdError('NETWORK');
    });
    this.#queue = result.then(() => undefined, () => undefined);
    return result;
  }

  async #attempt(url: URL): Promise<NvdPage> {
    const wait = this.#nextRequestAt - this.#runtime.now();
    if (wait > MAX_RETRY_DELAY_MS) {
      throw new NvdError('HTTP', this.#cooldownStatus, wait);
    }
    if (wait > 0) await this.#runtime.sleep(wait);
    this.#nextRequestAt = this.#runtime.now() + REQUEST_INTERVAL_MS;
    const controller = new AbortController();
    const deadline = setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const headers = new Headers({ Accept: 'application/json' });
      if (this.#apiKey !== undefined) headers.set('apiKey', this.#apiKey);
      const response = await this.#runtime.fetch(url, {
        headers,
        signal: controller.signal,
        redirect: 'error',
      });
      if (!response.ok) {
        const delay = retryAfter(response.headers.get('retry-after'));
        if (delay !== undefined && (response.status === 429 || response.status >= 500)) {
          this.#nextRequestAt = Math.max(this.#nextRequestAt, this.#runtime.now() + delay);
          this.#cooldownStatus = response.status;
        }
        await response.body?.cancel();
        throw new NvdError('HTTP', response.status, delay);
      }
      const json = await readJson(response);
      try {
        return parseNvdPage(json);
      } catch {
        throw new NvdError('INVALID_RESPONSE');
      }
    } catch (error) {
      if (controller.signal.aborted) throw new NvdError('TIMEOUT');
      if (error instanceof NvdError) throw error;
      throw new NvdError('NETWORK');
    } finally {
      clearTimeout(deadline);
    }
  }
}
