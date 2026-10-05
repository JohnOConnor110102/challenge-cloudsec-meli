import assert from 'node:assert/strict';
import { test } from 'node:test';
import { NvdClient, NvdError } from '../src/nvd/client.js';
import { MAX_PAGE_SIZE } from '../src/nvd/validation.js';
import type { NvdCve, NvdPage } from '../src/nvd/validation.js';
import { CveCatalog } from '../src/sync/catalog.js';
import { InitialSync } from '../src/sync/initial-sync.js';

const DATE = '2026-10-05T12:00:00.000';
const ID = 'CVE-2024-1234';

function cve(id = ID): NvdCve {
  return { id, published: DATE, lastModified: DATE, vulnStatus: 'Analyzed', metrics: {} };
}

function page(startIndex: number, cves: NvdCve[], totalResults: number): NvdPage {
  return { startIndex, cves, totalResults, resultsPerPage: cves.length, timestamp: DATE };
}

function harness(handler: (startIndex: number) => NvdPage | Promise<NvdPage>, catalog = new CveCatalog()) {
  const calls: number[] = [];
  const client: Pick<NvdClient, 'getPage'> = {
    async getPage(options = {}) {
      const startIndex = options.startIndex ?? 0;
      assert.equal(options.resultsPerPage, MAX_PAGE_SIZE);
      calls.push(startIndex);
      return handler(startIndex);
    },
  };
  return { sync: new InitialSync(client, catalog), catalog, calls };
}

test('comienza sin datos y pagina con los registros recibidos, incluidos unknown y Rejected', async () => {
  const first = page(0, [cve(), { ...cve('CVE-2024-1235'), vulnStatus: 'Rejected' }], 3);
  const { sync, catalog, calls } = harness((start) => start === 0
    ? { ...first, resultsPerPage: MAX_PAGE_SIZE }
    : page(2, [cve('CVE-2024-1236')], 3));
  assert.deepEqual(sync.progress, {
    status: 'idle', nextStartIndex: 0, totalResults: null, storedRecords: 0, lastPageTimestamp: null,
  });
  await sync.run();
  assert.deepEqual(calls, [0, 2]);
  assert.deepEqual(sync.progress, {
    status: 'completed', nextStartIndex: 3, totalResults: 3, storedRecords: 3, lastPageTimestamp: DATE,
  });
  assert.equal(catalog.get(ID)?.classification.severity, 'unknown');
  assert.equal(catalog.get('CVE-2024-1235')?.classification.status, 'rejected');
  await sync.run();
  assert.deepEqual(calls, [0, 2]);
});

test('un catálogo NVD vacío termina con cero registros y sin consultas adicionales', async () => {
  const { sync, calls } = harness(() => page(0, [], 0));
  await sync.run();
  assert.equal(sync.progress.status, 'completed');
  assert.equal(sync.progress.totalResults, 0);
  assert.equal(sync.progress.storedRecords, 0);
  assert.deepEqual(calls, [0]);
});

test('tras un fallo reanuda desde la última página guardada sin duplicar CVEs', async () => {
  let failed = false;
  const { sync, calls } = harness((start) => {
    if (start === 0) return page(0, [cve()], 2);
    if (!failed) { failed = true; throw new NvdError('HTTP', 503); }
    return page(1, [cve('CVE-2024-1235')], 2);
  });
  await assert.rejects(sync.run(), { code: 'HTTP', status: 503 });
  assert.deepEqual(sync.progress, {
    status: 'failed', nextStartIndex: 1, totalResults: 2, storedRecords: 1, lastPageTimestamp: DATE,
  });
  await sync.run();
  assert.deepEqual(calls, [0, 1, 1]);
  assert.equal(sync.progress.status, 'completed');
  assert.equal(sync.progress.storedRecords, 2);
});

test('si falla guardar parte de una página, la reintenta completa y conserva IDs únicos', async () => {
  class FailingCatalog extends CveCatalog {
    fail = true;
    override upsert(record: NvdCve): void {
      if (record.id === 'CVE-2024-1235' && this.fail) {
        this.fail = false;
        throw new Error('Fallo al guardar');
      }
      super.upsert(record);
    }
  }
  const { sync, calls } = harness(() => page(0, [cve(), cve('CVE-2024-1235')], 2), new FailingCatalog());
  await assert.rejects(sync.run(), /Fallo al guardar/);
  assert.equal(sync.progress.nextStartIndex, 0);
  assert.equal(sync.progress.storedRecords, 1);
  assert.equal(sync.progress.totalResults, null);
  await sync.run();
  assert.deepEqual(calls, [0, 0]);
  assert.equal(sync.progress.status, 'completed');
  assert.equal(sync.progress.storedRecords, 2);
});

test('llamadas simultáneas comparten una carga y el progreso devuelve una copia', async () => {
  const response = Promise.withResolvers<NvdPage>();
  const { sync, calls } = harness(() => response.promise);
  const task = sync.run();
  assert.strictEqual(sync.run(), task);
  const progress = sync.progress;
  assert.equal(progress.status, 'running');
  progress.status = 'completed';
  progress.nextStartIndex = 99;
  assert.equal(sync.progress.status, 'running');
  assert.equal(sync.progress.nextStartIndex, 0);
  response.resolve(page(0, [cve()], 1));
  await task;
  assert.deepEqual(calls, [0]);
});

test('pausa durante una consulta y reanuda sin aplicar la respuesta pendiente ni perder el checkpoint', async () => {
  const pending = Promise.withResolvers<NvdPage>();
  const requested = Promise.withResolvers<void>();
  let held = false;
  const { sync, calls } = harness((start) => {
    if (start === 0) return page(0, [cve()], 2);
    if (!held) {
      held = true;
      requested.resolve();
      return pending.promise;
    }
    return page(1, [cve('CVE-2024-1235')], 2);
  });
  sync.stop();
  assert.equal(sync.progress.status, 'idle');
  const task = sync.run();
  await requested.promise;
  assert.equal(sync.progress.nextStartIndex, 1);
  assert.equal(sync.progress.status, 'running');
  sync.stop();
  assert.strictEqual(sync.run(), task);
  pending.resolve(page(1, [cve('CVE-2024-1235')], 2));
  await task;
  assert.equal(sync.progress.status, 'paused');
  assert.equal(sync.progress.nextStartIndex, 1);
  assert.equal(sync.progress.storedRecords, 1);
  await sync.run();
  assert.deepEqual(calls, [0, 1, 1]);
  assert.equal(sync.progress.status, 'completed');
  sync.stop();
  assert.equal(sync.progress.status, 'completed');
});

test('usa el total de cada respuesta si el catálogo NVD crece durante el recorrido', async () => {
  const { sync, calls } = harness((start) => start === 0
    ? page(0, [cve()], 2)
    : page(1, [cve('CVE-2024-1235'), cve('CVE-2024-1236')], 3));
  await sync.run();
  assert.deepEqual(calls, [0, 1]);
  assert.equal(sync.progress.totalResults, 3);
  assert.equal(sync.progress.storedRecords, 3);
});

test('un recorrido con duplicados entre páginas falla y el próximo intento recorre desde cero', async () => {
  let duplicate = true;
  const { sync, calls } = harness((start) => page(start,
    [cve(start === 0 || duplicate ? ID : 'CVE-2024-1235')], 2));
  await assert.rejects(sync.run(), /no coincide con el total NVD/);
  assert.equal(sync.progress.status, 'failed');
  assert.equal(sync.progress.nextStartIndex, 0);
  assert.equal(sync.progress.storedRecords, 1);
  duplicate = false;
  await sync.run();
  assert.deepEqual(calls, [0, 1, 0, 1]);
  assert.equal(sync.progress.status, 'completed');
  assert.equal(sync.progress.storedRecords, 2);
});

test('rechaza páginas que no permiten avanzar y catálogos previamente poblados', async () => {
  for (const response of [page(0, [], 1), page(1, [cve()], 2)]) {
    const { sync, calls } = harness(() => response);
    await assert.rejects(sync.run(), /checkpoint/);
    assert.equal(sync.progress.status, 'failed');
    assert.equal(sync.progress.nextStartIndex, 0);
    assert.deepEqual(calls, [0]);
  }
  const catalog = new CveCatalog();
  catalog.upsert(cve());
  assert.throws(() => harness(() => page(0, [], 0), catalog), /catálogo vacío/);
});

test('integra la carga con el cliente NVD y su pausa entre solicitudes, sin usar la red', async () => {
  let time = 0;
  const waits: number[] = [];
  const client = new NvdClient({}, {
    now: () => time,
    sleep: async (ms) => { time += ms; waits.push(ms); },
    fetch: async (input) => {
      const start = Number(new URL(String(input)).searchParams.get('startIndex'));
      return Response.json({
        format: 'NVD_CVE', version: '2.0', timestamp: DATE,
        startIndex: start, resultsPerPage: 1, totalResults: 2,
        vulnerabilities: [{ cve: cve(start === 0 ? ID : 'CVE-2024-1235') }],
      });
    },
  });
  const sync = new InitialSync(client, new CveCatalog());
  await sync.run();
  assert.equal(sync.progress.status, 'completed');
  assert.equal(sync.progress.storedRecords, 2);
  assert.deepEqual(waits, [6_100]);
});
