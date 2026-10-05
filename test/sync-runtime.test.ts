import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { test } from 'node:test';
import { inspect } from 'node:util';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { NvdClient } from '../src/nvd/client.js';
import type { NvdCve, NvdPage } from '../src/nvd/validation.js';
import { CveCatalog } from '../src/sync/catalog.js';
import { InitialSync } from '../src/sync/initial-sync.js';

const DATE = '2026-10-05T12:00:00.000';
function page(startIndex = 0, totalResults = 1): NvdPage {
  const cve: NvdCve = {
    id: `CVE-2024-${1234 + startIndex}`, published: DATE, lastModified: DATE,
    vulnStatus: 'Analyzed', metrics: {},
  };
  return { startIndex, totalResults, resultsPerPage: 1, timestamp: DATE, cves: [cve] };
}

test('ready e inject no inician consultas de red y no informan que el catálogo esté listo', async (t) => {
  let calls = 0;
  const app = buildApp(loadConfig({ NODE_ENV: 'test' }), {
    async getPage() { calls++; return page(); },
  });
  t.after(() => app.close());
  await app.ready();
  const response = await app.inject('/health/ready');
  assert.equal(response.statusCode, 503);
  assert.deepEqual(response.json(), { status: 'not_ready' });
  assert.equal(calls, 0);
  assert.equal(app.getDecorator<CveCatalog>('catalog').size, 0);
});

test('listen carga en segundo plano y readiness pasa a 200 solo después de la última página', async (t) => {
  const pending = Promise.withResolvers<NvdPage>();
  const requested = Promise.withResolvers<void>();
  const calls: number[] = [];
  const app = buildApp(loadConfig({ NODE_ENV: 'test' }), {
    async getPage(options = {}) {
      const start = options.startIndex ?? 0;
      calls.push(start);
      if (start === 0) return page(0, 2);
      requested.resolve();
      return pending.promise;
    },
  });
  t.after(() => app.close());
  await app.listen({ host: '127.0.0.1', port: 0 });
  await requested.promise;
  const sync = app.getDecorator<InitialSync>('initialSync');
  assert.equal(sync.progress.storedRecords, 1);
  assert.equal((await app.inject('/health/live')).statusCode, 200);
  assert.equal((await app.inject('/health/ready')).statusCode, 503);
  pending.resolve(page(1, 2));
  await sync.run();
  const ready = await app.inject('/health/ready');
  assert.equal(ready.statusCode, 200);
  assert.deepEqual(ready.json(), { status: 'ok' });
  assert.deepEqual(calls, [0, 1]);
});

test('un fallo de NVD conserva liveness, readiness 503 y logs sin credenciales ni detalles del error', async (t) => {
  const key = 'private-nvd-key';
  const logged = Promise.withResolvers<void>();
  const logs: unknown[] = [];
  const app = buildApp(loadConfig({ NODE_ENV: 'development', LOG_LEVEL: 'silent', NVD_API_KEY: key }), {
    async getPage() { throw new Error(`private-provider-detail ${key}`); },
  });
  t.after(() => app.close());
  t.mock.method(app.log, 'info', (...args: unknown[]) => { logs.push(args); });
  t.mock.method(app.log, 'error', (...args: unknown[]) => { logs.push(args); logged.resolve(); });
  await app.listen({ host: '127.0.0.1', port: 0 });
  await logged.promise;
  assert.equal(app.getDecorator<InitialSync>('initialSync').progress.status, 'failed');
  assert.equal((await app.inject('/health/live')).statusCode, 200);
  const ready = await app.inject('/health/ready');
  assert.equal(ready.statusCode, 503);
  assert.deepEqual(ready.json(), { status: 'not_ready' });
  assert.equal(inspect(logs).includes('nvd_sync_failed'), true);
  assert.equal(inspect(logs).includes('private-provider-detail'), false);
  assert.equal(inspect(logs).includes(key), false);
  assert.equal(ready.body.includes(key), false);
});

test('cerrar el servidor cancela fetch y deja el checkpoint pausado', async (t) => {
  const started = Promise.withResolvers<AbortSignal>();
  let calls = 0;
  const client = new NvdClient({}, {
    fetch: async (_input, init) => {
      calls++;
      const signal = init!.signal!;
      started.resolve(signal);
      return new Promise<Response>((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      });
    },
  });
  const app = buildApp(loadConfig({ NODE_ENV: 'test' }), client);
  t.after(() => app.close());
  await app.listen({ host: '127.0.0.1', port: 0 });
  const signal = await started.promise;
  await app.close();
  assert.equal(signal.aborted, true);
  const progress = app.getDecorator<InitialSync>('initialSync').progress;
  assert.equal(progress.status, 'paused');
  assert.equal(progress.nextStartIndex, 0);
  assert.equal(progress.storedRecords, 0);
  assert.equal(calls, 1);
});

test('cerrar durante la espera por rate limit no espera los seis segundos ni solicita otra página', async (t) => {
  const waiting = Promise.withResolvers<void>();
  let calls = 0;
  const client = new NvdClient({}, {
    now: () => 0,
    sleep: async (ms, signal) => { waiting.resolve(); await sleep(ms, undefined, { signal }); },
    fetch: async () => {
      calls++;
      const result = page(0, 2);
      return Response.json({
        format: 'NVD_CVE', version: '2.0', timestamp: DATE,
        startIndex: 0, resultsPerPage: 1, totalResults: 2,
        vulnerabilities: result.cves.map((cve) => ({ cve })),
      });
    },
  });
  const app = buildApp(loadConfig({ NODE_ENV: 'test' }), client);
  t.after(() => app.close());
  await app.listen({ host: '127.0.0.1', port: 0 });
  await waiting.promise;
  await app.close();
  const progress = app.getDecorator<InitialSync>('initialSync').progress;
  assert.equal(progress.status, 'paused');
  assert.equal(progress.nextStartIndex, 1);
  assert.equal(progress.storedRecords, 1);
  assert.equal(calls, 1);
});
