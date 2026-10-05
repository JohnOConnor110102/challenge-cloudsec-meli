import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

test('valida configuración y rechaza valores inválidos sin exponerlos', () => {
  const config = loadConfig({ NODE_ENV: 'production', HOST: '0.0.0.0', PORT: '8080', LOG_LEVEL: 'warn' });
  assert.equal(config.port, 8080);
  assert.equal(config.host, '0.0.0.0');

  for (const port of ['', '0', '65536', '-1', '3.5', '1e3', '0x10', 'not-a-port']) {
    assert.throws(() => loadConfig({ PORT: port }), /PORT debe ser un entero/);
  }
  assert.throws(() => loadConfig({ HOST: '' }), /HOST/);
  assert.throws(() => loadConfig({ NODE_ENV: 'invalid' }), /NODE_ENV/);
  assert.throws(() => loadConfig({ LOG_LEVEL: 'secret-value' }), {
    message: 'LOG_LEVEL tiene un valor inválido',
  });
});

test('health checks responden sin revelar configuración', async (t) => {
  const app = buildApp(loadConfig({ NODE_ENV: 'test' }));
  t.after(() => app.close());

  for (const [path, statusCode, status] of [
    ['/health/live', 200, 'ok'], ['/health/ready', 503, 'not_ready'],
  ] as const) {
    const response = await app.inject({ method: 'GET', url: path });
    assert.equal(response.statusCode, statusCode);
    assert.deepEqual(response.json(), { status });
    assert.match(response.headers['content-type'] ?? '', /application\/json/);
  }
  const unknownRoute = await app.inject({ method: 'GET', url: '/api/v1/vulnerabilities' });
  assert.equal(unknownRoute.statusCode, 404);
});
