import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { NvdPage } from '../src/nvd/validation.js';
import { CveCatalog } from '../src/sync/catalog.js';
import { InitialSync } from '../src/sync/initial-sync.js';
import type { SyncProgress, SyncStore } from '../src/sync/initial-sync.js';
import { MemorySyncStore } from '../src/sync/memory-sync-store.js';

const empty: NvdPage = {
  startIndex: 0, resultsPerPage: 0, totalResults: 0, timestamp: '2026-10-05T12:00:00.000', cves: [],
};
const noProvider = { async getPage(): Promise<NvdPage> { assert.fail('No debe consultar NVD'); } };

test('detener durante la lectura del checkpoint pausa sin consultar NVD ni inventar un avance', async () => {
  const restored = Promise.withResolvers<SyncProgress>();
  const memory = new MemorySyncStore(new CveCatalog());
  const sync = new InitialSync(noProvider, {
    getProgress: () => restored.promise,
    savePage: (page) => memory.savePage(page),
    setStatus: (status, index) => memory.setStatus(status, index),
  });
  const task = sync.run();
  sync.stop();
  restored.resolve(await memory.getProgress());
  await task;
  assert.equal(sync.progress.status, 'paused');
  assert.equal(sync.progress.nextStartIndex, 0);
});

test('detener mientras se guarda running también pausa antes de consultar NVD', async () => {
  const started = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const memory = new MemorySyncStore(new CveCatalog());
  const store: SyncStore = {
    getProgress: () => memory.getProgress(),
    savePage: (page) => memory.savePage(page),
    async setStatus(status, index) {
      if (status === 'running') { started.resolve(); await release.promise; }
      return memory.setStatus(status, index);
    },
  };
  const sync = new InitialSync(noProvider, store);
  const task = sync.run();
  await started.promise;
  sync.stop();
  release.resolve();
  await task;
  assert.equal((await store.getProgress()).status, 'paused');
});

test('una parada no oculta un fallo de persistencia ni lo transforma en una pausa exitosa', async () => {
  const started = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const memory = new MemorySyncStore(new CveCatalog());
  const sync = new InitialSync({ async getPage() { return empty; } }, {
    getProgress: () => memory.getProgress(),
    async savePage() {
      started.resolve(); await release.promise;
      throw new Error('Fallo al guardar la página');
    },
    setStatus: (status, index) => memory.setStatus(status, index),
  });
  const task = sync.run();
  await started.promise;
  sync.stop();
  const rejected = assert.rejects(task, { message: 'Fallo al guardar la página' });
  release.resolve();
  await rejected;
  assert.equal(sync.progress.status, 'failed');
  assert.equal(sync.progress.nextStartIndex, 0);
});

test('si no puede recuperar el checkpoint no consulta NVD ni sobrescribe el progreso desconocido', async () => {
  const sync = new InitialSync(noProvider, {
    async getProgress() { throw new Error('No se pudo leer el progreso persistido'); },
    async savePage(): Promise<SyncProgress> { assert.fail('No debe escribir una página'); },
    async setStatus(): Promise<SyncProgress> { assert.fail('No debe escribir un estado desconocido'); },
  });
  await assert.rejects(sync.run(), { message: 'No se pudo leer el progreso persistido' });
  assert.equal(sync.progress.status, 'failed');
});
