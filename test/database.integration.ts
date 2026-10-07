import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { loadConfig } from '../src/config.js';
import { openDatabase } from '../src/db/pool.js';

const config = loadConfig().database;
const failure = 'No se pudo conectar PostgreSQL con el usuario y esquema de aplicación';

test('Node conecta con cve_app, parámetros seguros y consultas parametrizadas; libera el pool', async () => {
  const pool = await openDatabase(config, () => assert.fail('Conexión inactiva perdida'));
  try {
    const session = await pool.query<{
      role: string; search_path: string; statement_timeout: string; lock_timeout: string;
      idle_timeout: string; app_name: string;
    }>(`SELECT current_user AS role, current_setting('search_path') AS search_path,
      current_setting('statement_timeout') AS statement_timeout,
      current_setting('lock_timeout') AS lock_timeout,
      current_setting('idle_in_transaction_session_timeout') AS idle_timeout,
      current_setting('application_name') AS app_name`);
    assert.deepEqual(session.rows[0], {
      role: 'cve_app', search_path: 'pg_catalog,app', statement_timeout: '10s',
      lock_timeout: '5s', idle_timeout: '10s', app_name: 'meli-cloudsec',
    });
    const value = "'; DROP TABLE app.cves; --";
    const result = await pool.query<{ value: string }>('SELECT $1::text AS value', [value]);
    assert.equal(result.rows[0]?.value, value);
    const check = await pool.query<{ intact: boolean }>("SELECT to_regclass('app.cves') IS NOT NULL AS intact");
    assert.equal(check.rows[0]?.intact, true);
  } finally {
    await pool.end();
  }
  assert.equal(pool.totalCount, 0);
});

test('una contraseña incorrecta falla sin devolver el secreto ni el error crudo del proveedor', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'meli-db-auth-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = join(directory, 'password');
  await writeFile(file, randomBytes(32).toString('hex'), { mode: 0o600 });
  await assert.rejects(openDatabase({ ...config, passwordFile: file }, () => {}), { message: failure });
});

test('exigir TLS a PostgreSQL local sin TLS falla sin degradar a texto plano', async () => {
  await assert.rejects(openDatabase({ ...config, tls: 'verify-full' }, () => {}), { message: failure });
});

test('una conexión inactiva perdida informa un evento sin datos crudos y la siguiente consulta reconecta',
  { timeout: 5_000 }, async (t) => {
    const notification = Promise.withResolvers<void>();
    const pool = await openDatabase(config, (...args: unknown[]) => {
      assert.equal(args.length, 0);
      notification.resolve();
    });
    t.after(() => pool.end());
    const other = await openDatabase(config, () => assert.fail('Conexión secundaria perdida'));
    t.after(() => other.end());
    const initial = await pool.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
    const pid = initial.rows[0]!.pid;
    // PostgreSQL permite terminar conexiones del propio rol, sin superusuario.
    await other.query('SELECT pg_terminate_backend($1)', [pid]);
    await notification.promise;
    const recovered = await pool.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
    assert.notEqual(recovered.rows[0]?.pid, pid);
  });
