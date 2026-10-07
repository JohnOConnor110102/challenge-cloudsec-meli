import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadConfig } from '../src/config.js';

test('configura PostgreSQL local sin incorporar una contraseña al objeto de configuración', () => {
  assert.deepEqual(loadConfig({}).database, {
    host: '127.0.0.1', port: 5432, name: 'cves', passwordFile: '.secrets/db_app_password',
    tls: 'disable', caFile: undefined,
  });
  const database = loadConfig({
    DB_HOST: 'database.example.org', DB_PORT: '55432', DB_NAME: 'other_cves',
    DB_PASSWORD_FILE: '/run/secrets/database', DB_CA_FILE: '/certs/ca.pem',
  }).database;
  assert.equal(database.host, 'database.example.org');
  assert.equal(database.port, 55432);
  assert.equal(database.tls, 'verify-full');
  assert.equal(database.caFile, '/certs/ca.pem');
});

test('rechaza configuración DB inválida sin incluir valores en el mensaje', () => {
  for (const [variable, values] of [
    ['DB_HOST', ['', 'host with spaces', 'postgres://example.org/db', '/tmp/socket', 'host..org', '-host']],
    ['DB_PORT', ['', '0', '65536', '1e3', '3.5', 'private-value']],
    ['DB_NAME', ['', 'name with spaces', 'private-value;', 'x'.repeat(64)]],
    ['DB_PASSWORD_FILE', ['', '   ', 'private-value\n']],
    ['DB_CA_FILE', ['', 'private-value\0']],
    ['DB_TLS', ['', 'require', 'no-verify', 'private-value']],
  ] as const) {
    for (const value of values) {
      assert.throws(() => loadConfig({ [variable]: value }), (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.ok(error.message.startsWith(variable));
        assert.ok(!error.message.includes('private-value'));
        return true;
      });
    }
  }
});

test('exige TLS verificado fuera de loopback local y en producción, sin fallback', () => {
  assert.equal(loadConfig({ NODE_ENV: 'production' }).database.tls, 'verify-full');
  assert.equal(loadConfig({ DB_HOST: 'db' }).database.tls, 'verify-full');
  assert.equal(loadConfig({ NODE_ENV: 'test', DB_HOST: '::1' }).database.tls, 'disable');
  for (const env of [
    { NODE_ENV: 'production', DB_TLS: 'disable' },
    { DB_HOST: 'db', DB_TLS: 'disable' },
    { DB_HOST: '192.0.2.1', DB_TLS: 'disable' },
  ]) assert.throws(() => loadConfig(env), /DB_TLS solo permite disable/);
  assert.throws(() => loadConfig({ DB_CA_FILE: '/certs/ca.pem' }), /DB_CA_FILE requiere/);
});
