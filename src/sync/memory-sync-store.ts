import type { NvdPage } from '../nvd/validation.js';
import { CveCatalog } from './catalog.js';
import type { SyncProgress, SyncStore } from './initial-sync.js';

export class MemorySyncStore implements SyncStore {
  readonly #state: Omit<SyncProgress, 'storedRecords'> = {
    status: 'idle', nextStartIndex: 0, totalResults: null, lastPageTimestamp: null,
  };

  constructor(private readonly catalog: CveCatalog) {
    if (catalog.size !== 0) throw new Error('La carga inicial requiere un catálogo vacío');
  }

  async getProgress(): Promise<SyncProgress> {
    return { ...this.#state, storedRecords: this.catalog.size };
  }

  async setStatus(status: 'running' | 'paused' | 'failed', expectedIndex: number): Promise<SyncProgress> {
    if (expectedIndex !== this.#state.nextStartIndex || this.#state.status === 'completed') {
      throw new Error('El checkpoint cambió antes de actualizar su estado');
    }
    this.#state.status = status;
    return this.getProgress();
  }

  async savePage(page: NvdPage): Promise<SyncProgress> {
    if (page.startIndex !== this.#state.nextStartIndex
      || (page.cves.length === 0 && page.startIndex < page.totalResults)) {
      throw new Error('La página NVD no permite avanzar desde el checkpoint');
    }
    for (const cve of page.cves) this.catalog.upsert(cve);
    this.#state.nextStartIndex += page.cves.length;
    this.#state.totalResults = page.totalResults;
    this.#state.lastPageTimestamp = page.timestamp;
    this.#state.status = 'running';
    if (this.#state.nextStartIndex >= page.totalResults) {
      this.#state.status = this.catalog.size === page.totalResults ? 'completed' : 'failed';
      if (this.#state.status === 'failed') this.#state.nextStartIndex = 0;
    }
    return this.getProgress();
  }
}
