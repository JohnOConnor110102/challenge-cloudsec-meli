import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import pg from 'pg';
import { loadConfig } from '../src/config.js';
import { openDatabase, readDatabasePassword } from '../src/db/pool.js';
import { MAX_PAGE_SIZE } from '../src/nvd/validation.js';
import type { NvdCve, NvdPage } from '../src/nvd/validation.js';
import { CatalogCheckpointConflict, PostgresCatalog } from '../src/sync/postgres-catalog.js';
import { InitialSync } from '../src/sync/initial-sync.js';
import { NvdError } from '../src/nvd/client.js';

const DATE = '2026-10-05T12:00:00.000';
const UTC_DATE = `${DATE}Z`;
function cve(id = 'CVE-2024-1234', score?: number): NvdCve {
  return {
    id, published: DATE, lastModified: DATE, vulnStatus: 'Analyzed',
    metrics: score === undefined ? {} : {
      cvssMetricV31: [{ source: 'nvd@nist.gov', type: 'Primary',
        cvssData: { version: '3.1', baseScore: score, vectorString: 'CVSS:3.1/AV:N' } }],
    },
  };
}
function page(startIndex: number, cves: NvdCve[], totalResults: number): NvdPage {
  return { startIndex, cves, totalResults, resultsPerPage: cves.length, timestamp: DATE };
}

test('persistencia transaccional del catálogo con el usuario real de aplicación', { timeout: 30_000 }, async (t) => {
  const config = loadConfig().database;
  assert.ok(config.tls === 'disable' && ['127.0.0.1', '::1'].includes(config.host),
    'Esta prueba requiere el PostgreSQL local de Compose');
  const name = `meli_catalog_test_${randomUUID().replaceAll('-', '')}`;
  const identifier = pg.escapeIdentifier(name);
  const adminOptions = {
    host: config.host, port: config.port, user: 'postgres',
    password: await readDatabasePassword('.secrets/db_admin_password'),
    ssl: false, max: 1, connectionTimeoutMillis: 5_000,
  };
  const admin = new pg.Pool({ ...adminOptions, database: 'postgres' });
  let created = false;
  let owner: pg.Pool | undefined;
  let pool: pg.Pool | undefined;
  // Solo esta base aleatoria se crea, limpia y elimina; nunca la base de desarrollo.
  t.after(async () => {
    try {
      await pool?.end();
      await owner?.end();
      if (created) await admin.query(`DROP DATABASE ${identifier} WITH (FORCE)`);
    } finally {
      await admin.end();
    }
  });
  await admin.query(`CREATE DATABASE ${identifier} OWNER cve_migrator`);
  created = true;
  await admin.query(`REVOKE ALL ON DATABASE ${identifier} FROM PUBLIC`);
  await admin.query(`GRANT CONNECT ON DATABASE ${identifier} TO cve_app, cve_migrator`);
  owner = new pg.Pool({ ...adminOptions, database: name });
  await owner.query(`
    SET ROLE cve_migrator;
    CREATE SCHEMA app AUTHORIZATION cve_migrator;
    GRANT USAGE ON SCHEMA app TO cve_app;
    REVOKE ALL ON SCHEMA public FROM PUBLIC;
  `);
  await owner.query(await readFile(new URL('../db/migrations/001_initial.sql', import.meta.url), 'utf8'));
  await owner.query('RESET ROLE');
  const database = { ...config, name };
  pool = await openDatabase(database, () => assert.fail('Conexión de aplicación perdida'));
  const connection = pool;
  const fixture = owner;
  const catalog = new PostgresCatalog(connection);
  t.beforeEach(async () => { await fixture.query('TRUNCATE app.cves, app.sync_state'); });

  await t.test('lee idle y cero registros sin crear un checkpoint al consultar', async () => {
    assert.deepEqual(await catalog.getProgress(), {
      status: 'idle', nextStartIndex: 0, totalResults: null, storedRecords: 0, lastPageTimestamp: null,
    });
    const result = await connection.query<{ count: string }>('SELECT count(*) FROM app.sync_state');
    assert.equal(result.rows[0]?.count, '0');
  });

  await t.test('guarda clasificación, fechas UTC y checkpoint; otro pool reanuda desde ese índice', async () => {
    await connection.query("SET TIME ZONE 'America/Argentina/Buenos_Aires'");
    const first = await catalog.savePage(page(0, [
      cve(undefined, 9.8), cve('CVE-2024-1235'), { ...cve('CVE-2024-1236', 9.8), vulnStatus: 'Rejected' },
    ], 4));
    assert.deepEqual(first, {
      status: 'running', nextStartIndex: 3, totalResults: 4, storedRecords: 3, lastPageTimestamp: UTC_DATE,
    });
    const result = await connection.query<{
      classification_status: string; severity: string | null;
      published: Date; metric: { baseScore: number; version: string } | null;
    }>('SELECT classification_status, severity, published, metric FROM app.cves ORDER BY id');
    assert.deepEqual(result.rows.map((row) => [row.classification_status, row.severity]), [
      ['scored', 'critical'], ['unscored', 'unknown'], ['rejected', null],
    ]);
    assert.equal(result.rows[0]?.published.toISOString(), UTC_DATE);
    assert.equal(result.rows[0]?.metric?.baseScore, 9.8);
    assert.equal(result.rows[0]?.metric?.version, '3.1');
    assert.equal(result.rows[2]?.metric, null);
    const reopened = await openDatabase(database, () => assert.fail('Conexión reabierta perdida'));
    try {
      const restored = new PostgresCatalog(reopened);
      assert.deepEqual(await restored.getProgress(), first);
      const completed = await restored.savePage(page(first.nextStartIndex, [cve('CVE-2024-1237', 2)], 4));
      assert.equal(completed.status, 'completed');
      assert.equal(completed.storedRecords, 4);
      assert.deepEqual(await catalog.getProgress(), completed);
    } finally { await reopened.end(); }
  });

  await t.test('un fallo al escribir el checkpoint revierte CVEs nuevos y cambios anteriores', async () => {
    const previous = await catalog.savePage(page(0, [cve(undefined, 9.8)], 3));
    // Date.parse tolera este día inexistente; PostgreSQL lo rechaza al actualizar el checkpoint.
    await assert.rejects(catalog.savePage({
      ...page(1, [cve(undefined, 2), cve('CVE-2024-1235')], 3), timestamp: '2026-02-30T12:00:00.000',
    }), { message: 'No se pudo guardar la página y su checkpoint' });
    assert.deepEqual(await catalog.getProgress(), previous);
    const result = await connection.query<{ id: string; severity: string }>('SELECT id, severity FROM app.cves');
    assert.deepEqual(result.rows, [{ id: 'CVE-2024-1234', severity: 'critical' }]);
    const recovered = await catalog.savePage(page(1, [cve('CVE-2024-1235'), cve('CVE-2024-1236')], 3));
    assert.equal(recovered.status, 'completed');
  });

  await t.test('dos escritores del mismo checkpoint producen un único avance; repetirlo no duplica', async () => {
    const input = page(0, [cve()], 2);
    const results = await Promise.allSettled([catalog.savePage(input), new PostgresCatalog(connection).savePage(input)]);
    assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
    const rejected = results.find((result) => result.status === 'rejected');
    assert.ok(rejected?.status === 'rejected' && rejected.reason instanceof CatalogCheckpointConflict);
    const progress = await catalog.getProgress();
    assert.equal(progress.nextStartIndex, 1);
    assert.equal(progress.storedRecords, 1);
    await assert.rejects(catalog.savePage(input), CatalogCheckpointConflict);
    assert.deepEqual(await catalog.getProgress(), progress);
  });

  await t.test('completa un catálogo vacío sin inventar registros', async () => {
    assert.deepEqual(await catalog.savePage(page(0, [], 0)), {
      status: 'completed', nextStartIndex: 0, totalResults: 0, storedRecords: 0, lastPageTimestamp: UTC_DATE,
    });
  });

  await t.test('reclasifica repetidos; un total inconsistente falla y permite repetir desde cero', async () => {
    await catalog.savePage(page(0, [cve(undefined, 9.8)], 2));
    const failed = await catalog.savePage(page(1, [{ ...cve(undefined, 9.8), vulnStatus: 'Rejected' }], 2));
    assert.equal(failed.status, 'failed');
    assert.equal(failed.nextStartIndex, 0);
    assert.equal(failed.storedRecords, 1);
    const row = await connection.query<{ severity: null; metric: null }>('SELECT severity, metric FROM app.cves');
    assert.deepEqual(row.rows, [{ severity: null, metric: null }]);
    const recovered = await catalog.savePage(page(0, [cve(), cve('CVE-2024-1235', 0)], 2));
    assert.equal(recovered.status, 'completed');
    assert.equal(recovered.storedRecords, 2);
    const changed = await connection.query<{ severity: string }>('SELECT severity FROM app.cves ORDER BY id');
    assert.deepEqual(changed.rows, [{ severity: 'unknown' }, { severity: 'none' }]);
  });

  await t.test('guarda una página de 2000 CVEs y recupera su progreso completo', async () => {
    const records = Array.from({ length: MAX_PAGE_SIZE }, (_, index) => cve(`CVE-2024-${10000 + index}`));
    const completed = await catalog.savePage(page(0, records, MAX_PAGE_SIZE));
    assert.equal(completed.status, 'completed');
    assert.equal(completed.nextStartIndex, MAX_PAGE_SIZE);
    assert.equal(completed.storedRecords, MAX_PAGE_SIZE);
    assert.deepEqual(await catalog.getProgress(), completed);
  });

  await t.test('InitialSync conserva un fallo NVD y otro pool reanuda; completed evita nuevas consultas', async () => {
    const calls: number[] = [];
    const sync = new InitialSync({
      async getPage(options = {}) {
        const start = options.startIndex ?? 0;
        calls.push(start);
        if (start === 1) throw new NvdError('HTTP', 503);
        return page(0, [cve()], 2);
      },
    }, catalog);
    await assert.rejects(sync.run(), { code: 'HTTP', status: 503 });
    const failed = await catalog.getProgress();
    assert.equal(failed.status, 'failed');
    assert.equal(failed.nextStartIndex, 1);
    assert.equal(failed.storedRecords, 1);
    const reopened = await openDatabase(database, () => assert.fail('Conexión reabierta perdida'));
    try {
      const store = new PostgresCatalog(reopened);
      const resumed = new InitialSync({ async getPage(options = {}) {
        const start = options.startIndex ?? 0;
        calls.push(start);
        assert.equal(start, 1);
        return page(start, [cve('CVE-2024-1235')], 2);
      } }, store);
      await resumed.run();
      assert.deepEqual(calls, [0, 1, 1]);
      assert.equal(resumed.progress.status, 'completed');
      assert.equal(resumed.progress.storedRecords, 2);
      const finished = new InitialSync({ async getPage(): Promise<NvdPage> {
        assert.fail('Un catálogo completed no debe consultar NVD');
      } }, store);
      await finished.run();
      assert.deepEqual(finished.progress, resumed.progress);
      await assert.rejects(store.setStatus('failed', 2), CatalogCheckpointConflict);
      assert.equal((await store.getProgress()).status, 'completed');
    } finally { await reopened.end(); }
  });

  await t.test('pausar NVD guarda paused y otra instancia retoma el checkpoint confirmado', async () => {
    const started = Promise.withResolvers<void>();
    const sync = new InitialSync({ async getPage(options = {}) {
      if (options.startIndex === 0) return page(0, [cve()], 2);
      return new Promise<NvdPage>((_resolve, reject) => {
        options.signal!.addEventListener('abort', () => reject(new NvdError('CANCELLED')), { once: true });
        started.resolve();
      });
    } }, catalog);
    const task = sync.run();
    await started.promise;
    sync.stop();
    await task;
    assert.equal((await catalog.getProgress()).status, 'paused');
    assert.equal(sync.progress.nextStartIndex, 1);
    const resumed = new InitialSync({ async getPage(options = {}) {
      assert.equal(options.startIndex, 1);
      return page(1, [cve('CVE-2024-1235')], 2);
    } }, new PostgresCatalog(connection));
    await resumed.run();
    assert.equal(resumed.progress.status, 'completed');
  });

  await t.test('parar durante un guardado conserva la página confirmada y su checkpoint', async () => {
    const committed = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    let calls = 0;
    const sync = new InitialSync({ async getPage() { calls++; return page(0, [cve()], 2); } }, {
      getProgress: () => catalog.getProgress(),
      setStatus: (status, index) => catalog.setStatus(status, index),
      async savePage(input) {
        const saved = await catalog.savePage(input);
        committed.resolve(); await release.promise;
        return saved;
      },
    });
    const task = sync.run();
    await committed.promise;
    sync.stop();
    release.resolve();
    await task;
    assert.equal(calls, 1);
    assert.equal((await catalog.getProgress()).status, 'paused');
    assert.equal(sync.progress.nextStartIndex, 1);
    assert.equal(sync.progress.storedRecords, 1);
  });

  await t.test('si se pierde la confirmación después de COMMIT, no pisa el checkpoint y al reintentar lo recupera', async () => {
    let lost = false;
    const calls: number[] = [];
    const sync = new InitialSync({ async getPage(options = {}) {
      const start = options.startIndex ?? 0;
      calls.push(start);
      return page(start, [cve(`CVE-2024-${1234 + start}`)], 2);
    } }, {
      getProgress: () => catalog.getProgress(),
      setStatus: (status, index) => catalog.setStatus(status, index),
      async savePage(input) {
        const saved = await catalog.savePage(input);
        if (!lost) { lost = true; throw new Error('Confirmación perdida'); }
        return saved;
      },
    });
    await assert.rejects(sync.run(), { message: 'Confirmación perdida' });
    assert.equal(sync.progress.status, 'failed');
    assert.equal((await catalog.getProgress()).nextStartIndex, 1);
    await sync.run();
    assert.deepEqual(calls, [0, 1]);
    assert.equal(sync.progress.storedRecords, 2);
    assert.equal(sync.progress.status, 'completed');
  });
});
