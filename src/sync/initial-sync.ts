import type { NvdClient } from '../nvd/client.js';
import { MAX_PAGE_SIZE } from '../nvd/validation.js';
import type { NvdPage } from '../nvd/validation.js';
import { CveCatalog } from './catalog.js';
import { MemorySyncStore } from './memory-sync-store.js';

export interface SyncProgress {
  status: 'idle' | 'running' | 'paused' | 'failed' | 'completed';
  nextStartIndex: number;
  totalResults: number | null;
  storedRecords: number;
  lastPageTimestamp: string | null;
}

export interface SyncStore {
  getProgress(): Promise<SyncProgress>;
  savePage(page: NvdPage): Promise<SyncProgress>;
  setStatus(status: 'running' | 'paused' | 'failed', expectedIndex: number): Promise<SyncProgress>;
}

export class InitialSync {
  readonly #client: Pick<NvdClient, 'getPage'>;
  readonly #store: SyncStore;
  #state: SyncProgress = {
    status: 'idle', nextStartIndex: 0, totalResults: null, storedRecords: 0, lastPageTimestamp: null,
  };
  #task: Promise<void> | undefined;
  #stopRequested = false;
  #controller: AbortController | undefined;

  constructor(client: Pick<NvdClient, 'getPage'>, store: SyncStore | CveCatalog) {
    this.#client = client;
    this.#store = store instanceof CveCatalog ? new MemorySyncStore(store) : store;
  }

  get progress(): SyncProgress {
    return { ...this.#state };
  }

  run(): Promise<void> {
    if (this.#task !== undefined) return this.#task;
    if (this.#state.status === 'completed') return Promise.resolve();
    this.#stopRequested = false;
    this.#controller = new AbortController();
    this.#state.status = 'running';
    this.#task = this.#load().finally(() => {
      this.#task = undefined;
      this.#controller = undefined;
    });
    return this.#task;
  }

  // Conserva el checkpoint y cancela la consulta o espera en curso.
  stop(): void {
    if (this.#state.status === 'running') {
      this.#stopRequested = true;
      this.#controller?.abort();
    }
  }

  async #load(): Promise<void> {
    let restored = false;
    let phase: 'storage' | 'provider' = 'storage';
    try {
      this.#state = await this.#store.getProgress();
      restored = true;
      if (this.#state.status === 'completed') return;
      this.#state.status = 'running';
      if (!this.#stopRequested) {
        this.#state = await this.#store.setStatus('running', this.#state.nextStartIndex);
      }
      while (!this.#stopRequested) {
        phase = 'provider';
        const page = await this.#client.getPage({
          startIndex: this.#state.nextStartIndex, resultsPerPage: MAX_PAGE_SIZE,
          signal: this.#controller!.signal,
        });
        if (this.#stopRequested) break;
        if (page.startIndex !== this.#state.nextStartIndex
          || (page.cves.length === 0 && page.startIndex < page.totalResults)) {
          throw new Error('La página NVD no permite avanzar desde el checkpoint');
        }

        phase = 'storage';
        // El repositorio confirma datos y checkpoint antes de actualizar el progreso local.
        this.#state = await this.#store.savePage(page);
        if (this.#state.status === 'failed') {
          throw new Error('El catálogo no coincide con el total NVD; se debe repetir el recorrido');
        }
        if (this.#state.status === 'completed') return;
      }
      phase = 'storage';
      this.#state = await this.#store.setStatus('paused', this.#state.nextStartIndex);
    } catch (error) {
      const status = this.#stopRequested && phase === 'provider' ? 'paused' : 'failed';
      this.#state.status = status;
      if (restored) {
        try {
          this.#state = await this.#store.setStatus(status, this.#state.nextStartIndex);
        } catch (statusError) {
          this.#state.status = 'failed';
          if (status === 'paused') throw statusError;
          // Conservar el fallo original; otro proceso pudo avanzar o la DB estar caída.
        }
      }
      if (status === 'paused') return;
      throw error;
    }
  }
}
