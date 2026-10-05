import type { NvdClient } from '../nvd/client.js';
import { MAX_PAGE_SIZE } from '../nvd/validation.js';
import { CveCatalog } from './catalog.js';

export interface SyncProgress {
  status: 'idle' | 'running' | 'paused' | 'failed' | 'completed';
  nextStartIndex: number;
  totalResults: number | null;
  storedRecords: number;
  lastPageTimestamp: string | null;
}

export class InitialSync {
  readonly #client: Pick<NvdClient, 'getPage'>;
  readonly #catalog: CveCatalog;
  readonly #state: Omit<SyncProgress, 'storedRecords'> = {
    status: 'idle', nextStartIndex: 0, totalResults: null, lastPageTimestamp: null,
  };
  #task: Promise<void> | undefined;
  #stopRequested = false;

  constructor(client: Pick<NvdClient, 'getPage'>, catalog: CveCatalog) {
    if (catalog.size !== 0) throw new Error('La carga inicial requiere un catálogo vacío');
    this.#client = client;
    this.#catalog = catalog;
  }

  get progress(): SyncProgress {
    return { ...this.#state, storedRecords: this.#catalog.size };
  }

  run(): Promise<void> {
    if (this.#task !== undefined) return this.#task;
    if (this.#state.status === 'completed') return Promise.resolve();
    this.#stopRequested = false;
    this.#state.status = 'running';
    this.#task = this.#load().finally(() => { this.#task = undefined; });
    return this.#task;
  }

  // Pausa cooperativa: la consulta en curso termina antes de detenerse.
  stop(): void {
    if (this.#state.status === 'running') this.#stopRequested = true;
  }

  async #load(): Promise<void> {
    try {
      while (!this.#stopRequested) {
        const page = await this.#client.getPage({
          startIndex: this.#state.nextStartIndex, resultsPerPage: MAX_PAGE_SIZE,
        });
        if (this.#stopRequested) break;
        if (page.startIndex !== this.#state.nextStartIndex
          || (page.cves.length === 0 && page.startIndex < page.totalResults)) {
          throw new Error('La página NVD no permite avanzar desde el checkpoint');
        }

        for (const cve of page.cves) this.#catalog.upsert(cve);
        // Avanzar solo después de guardar la página completa permite repetirla.
        this.#state.nextStartIndex += page.cves.length;
        this.#state.totalResults = page.totalResults;
        this.#state.lastPageTimestamp = page.timestamp;

        if (this.#state.nextStartIndex >= page.totalResults) {
          if (this.#catalog.size !== page.totalResults) {
            this.#state.nextStartIndex = 0;
            throw new Error('El catálogo no coincide con el total NVD; se debe repetir el recorrido');
          }
          this.#state.status = 'completed';
          return;
        }
      }
      this.#state.status = 'paused';
    } catch (error) {
      this.#state.status = 'failed';
      throw error;
    }
  }
}
