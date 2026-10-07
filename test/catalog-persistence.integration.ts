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
import { buildPersistentApp } from '../src/app.js';

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

  await t.test('SQL cuenta todas las categorías y excluye solo remediaciones elegibles, sin duplicados ni interpolación', async () => {
    const records = [
      cve('CVE-2024-1234', 0), cve('CVE-2024-1235', 1), cve('CVE-2024-1236', 4),
      cve('CVE-2024-1237', 7), cve('CVE-2024-1238', 9.8), cve('CVE-2024-1239'),
      { ...cve('CVE-2024-1240', 9.8), vulnStatus: 'Rejected' },
    ];
    await catalog.savePage(page(0, records.slice(0, 2), 7));
    assert.equal((await catalog.readSummary()).status, 'running');
    await catalog.savePage(page(2, records.slice(2), 7));
    assert.deepEqual(await catalog.readSummary(), {
      status: 'completed', lastPageTimestamp: UTC_DATE,
      summary: {
        total: 6, excludedRejected: 1, excludedRemediated: 0,
        bySeverity: { none: 1, low: 1, medium: 1, high: 1, critical: 1, unknown: 1 },
      },
    });
    const pending = await catalog.readSummary([
      'CVE-2024-1238', 'CVE-2024-1238', 'CVE-2024-1239', 'CVE-2024-1240', 'CVE-2024-9999',
      "'); DROP TABLE app.cves; --",
    ]);
    assert.deepEqual(pending.summary, {
      total: 4, excludedRejected: 1, excludedRemediated: 2,
      bySeverity: { none: 1, low: 1, medium: 1, high: 1, critical: 0, unknown: 0 },
    });
    assert.equal((await catalog.getProgress()).storedRecords, 7);
  });

  await t.test('el servidor publica resúmenes SQL y al reabrir recupera completed sin descargar nuevamente', async () => {
    const started = Promise.withResolvers<void>();
    const release = Promise.withResolvers<NvdPage>();
    const appConfig = { ...loadConfig({ NODE_ENV: 'test' }), database };
    const app = await buildPersistentApp(appConfig, {
      async getCve(id) { return cve(id, 9.8); },
      async getPage(options = {}) {
        if (options.startIndex === 0) return page(0, [cve(undefined, 9.8)], 2);
        started.resolve(); return release.promise;
      },
    });
    try {
      await app.listen({ host: '127.0.0.1', port: 0 });
      await started.promise;
      assert.equal((await app.inject('/health/ready')).statusCode, 503);
      assert.equal((await app.inject('/api/v1/vulnerabilities/summary')).statusCode, 503);
      release.resolve(page(1, [cve('CVE-2024-1235')], 2));
      await app.getDecorator<InitialSync>('initialSync').run();
      assert.equal((await app.inject('/health/ready')).statusCode, 200);
      const total = await app.inject('/api/v1/vulnerabilities/summary');
      assert.equal(total.statusCode, 200);
      assert.deepEqual(total.json(), {
        total: 2, excludedRejected: 0,
        bySeverity: { none: 0, low: 0, medium: 0, high: 0, critical: 1, unknown: 1 },
        meta: { syncStatus: 'completed', lastPageTimestamp: UTC_DATE },
      });
      assert.equal((await app.inject({ method: 'PUT', url: '/api/v1/remediations/CVE-2024-1234' })).statusCode, 201);
      const pending = await app.inject('/api/v1/vulnerabilities/pending/summary');
      assert.equal(pending.statusCode, 200);
      assert.equal(pending.json().total, 1);
      assert.equal(pending.json().excludedRemediated, 1);
      assert.equal(pending.json().bySeverity.critical, 0);
    } finally {
      release.resolve(page(1, [cve('CVE-2024-1235')], 2));
      await app.close();
    }
    const reopened = await buildPersistentApp(appConfig, {
      async getCve(): Promise<NvdCve | null> { assert.fail('No debe consultar NVD'); },
      async getPage(): Promise<NvdPage> { assert.fail('No debe descargar un catálogo completed'); },
    });
    try {
      await reopened.listen({ host: '127.0.0.1', port: 0 });
      await reopened.getDecorator<InitialSync>('initialSync').run();
      assert.equal((await reopened.inject('/health/ready')).statusCode, 200);
      assert.equal((await reopened.inject('/api/v1/vulnerabilities/summary')).json().total, 2);
      // El registro persistente de remediaciones corresponde al próximo incremento.
      const pending = await reopened.inject('/api/v1/vulnerabilities/pending/summary');
      assert.equal(pending.json().total, 2);
      assert.equal(pending.json().excludedRemediated, 0);
    } finally { await reopened.close(); }
  });

  await t.test('un fallo de almacenamiento devuelve 503 seguro, conserva live y se recupera al restaurar la tabla', async () => {
    await catalog.savePage(page(0, [], 0));
    const app = await buildPersistentApp({ ...loadConfig({ NODE_ENV: 'test' }), database }, {
      async getCve(): Promise<NvdCve | null> { assert.fail('No debe consultar NVD'); },
      async getPage(): Promise<NvdPage> { assert.fail('No debe consultar NVD'); },
    });
    try {
      await app.getDecorator<InitialSync>('initialSync').run();
      await fixture.query('ALTER TABLE app.sync_state RENAME TO sync_state_unavailable');
      try {
        assert.equal((await app.inject('/health/live')).statusCode, 200);
        assert.deepEqual((await app.inject('/health/ready')).json(), { status: 'not_ready' });
        assert.equal((await app.inject('/health/ready')).statusCode, 503);
        for (const url of ['/api/v1/vulnerabilities/summary', '/api/v1/vulnerabilities/pending/summary']) {
          const response = await app.inject(url);
          assert.equal(response.statusCode, 503);
          assert.deepEqual(response.json(), { error: 'storage_unavailable' });
          assert.equal(response.headers['cache-control'], 'no-store');
        }
      } finally { await fixture.query('ALTER TABLE app.sync_state_unavailable RENAME TO sync_state'); }
      const response = await app.inject('/api/v1/vulnerabilities/summary');
      assert.equal(response.statusCode, 200);
      assert.equal(response.json().total, 0);
      assert.equal(response.json().bySeverity.unknown, 0);
      assert.equal((await app.inject('/health/ready')).statusCode, 200);
    } finally { await app.close(); }
  });

  await t.test('cerrar el servidor espera el checkpoint paused antes de liberar el pool', async () => {
    const started = Promise.withResolvers<void>();
    const sessionsBefore = await fixture.query<{ count: string }>(`
      SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND application_name = 'meli-cloudsec'
    `, [name]);
    const app = await buildPersistentApp({ ...loadConfig({ NODE_ENV: 'test' }), database }, {
      async getCve(): Promise<NvdCve | null> { assert.fail('No debe consultar CVEs individuales'); },
      async getPage(options = {}) {
        if (options.startIndex === 0) return page(0, [cve()], 2);
        return new Promise<NvdPage>((_resolve, reject) => {
          options.signal!.addEventListener('abort', () => reject(new NvdError('CANCELLED')), { once: true });
          started.resolve();
        });
      },
    });
    try {
      await app.listen({ host: '127.0.0.1', port: 0 });
      await started.promise;
    } finally { await app.close(); }
    const saved = await catalog.getProgress();
    assert.equal(saved.status, 'paused');
    assert.equal(saved.nextStartIndex, 1);
    assert.equal(saved.storedRecords, 1);
    const sessions = await fixture.query<{ count: string }>(`
      SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND application_name = 'meli-cloudsec'
    `, [name]);
    assert.equal(sessions.rows[0]?.count, sessionsBefore.rows[0]?.count,
      'El servidor liberó su pool; solo quedan las conexiones anteriores de la fixture');
  });
});
