import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { test } from 'node:test';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { NvdError } from '../src/nvd/client.js';
import type { NvdClient } from '../src/nvd/client.js';
import type { NvdCve } from '../src/nvd/validation.js';
import { RemediationStore } from '../src/remediations/store.js';
import { CveCatalog } from '../src/sync/catalog.js';

const ID = 'CVE-2024-1234';
const URL = `/api/v1/remediations/${ID}`;
const DATE = '2026-10-06T12:00:00.000Z';
function cve(vulnStatus = 'Analyzed'): NvdCve {
  return { id: ID, published: DATE, lastModified: DATE, vulnStatus, metrics: {} };
}
function appFor(getCve: Pick<NvdClient, 'getCve'>['getCve']) {
  return buildApp(loadConfig({ NODE_ENV: 'test' }), {
    getCve,
    async getPage() {
      return { startIndex: 0, resultsPerPage: 0, totalResults: 0, timestamp: DATE, cves: [] };
    },
  });
}

test('PUT crea con 201 y Location, repetirlo devuelve 200 sin otra consulta ni alterar el catálogo', async (t) => {
  let calls = 0;
  const app = appFor(async (id) => { calls++; assert.equal(id, ID); return cve(); });
  t.after(() => app.close());
  const logs: unknown[] = [];
  t.mock.method(app.log, 'child', () => app.log);
  t.mock.method(app.log, 'info', (fields: { event?: string }) => {
    if (fields.event === 'remediation_registered') logs.push(fields);
  });
  const first = await app.inject({ method: 'PUT', url: URL });
  assert.equal(first.statusCode, 201);
  assert.equal(first.headers.location, URL);
  assert.equal(first.headers['cache-control'], 'no-store');
  assert.match(first.headers['content-type'] ?? '', /application\/json/);
  const record = first.json<{ cveId: string; registeredAt: string }>();
  assert.equal(record.cveId, ID);
  assert.equal(new Date(record.registeredAt).toISOString(), record.registeredAt);
  const repeated = await app.inject({ method: 'PUT', url: URL });
  assert.equal(repeated.statusCode, 200);
  assert.deepEqual(repeated.json(), record);
  assert.equal(calls, 1);
  assert.equal(app.getDecorator<RemediationStore>('remediations').size, 1);
  assert.equal(app.getDecorator<CveCatalog>('catalog').size, 0);
  assert.equal((await app.inject('/health/ready')).statusCode, 503);
  assert.equal(logs.length, 1);
  assert.deepEqual(logs[0], {
    event: 'remediation_registered', requestId: (logs[0] as { requestId: string }).requestId,
    cveId: ID, registeredAt: record.registeredAt,
  });
  assert.match((logs[0] as { requestId: string }).requestId, /^[0-9a-f-]{36}$/);
});

test('rechaza IDs inválidos, cuerpos y errores de parseo sin consultar NVD', async (t) => {
  let calls = 0;
  const app = appFor(async () => { calls++; return cve(); });
  t.after(() => app.close());
  for (const id of ['secret-value', 'cve-2024-1234', 'CVE-2024-123']) {
    const response = await app.inject({ method: 'PUT', url: `/api/v1/remediations/${id}` });
    assert.equal(response.statusCode, 400);
    assert.deepEqual(response.json(), { error: 'invalid_request' });
  }
  const longId = await app.inject({ method: 'PUT', url: `/api/v1/remediations/CVE-2024-${'1'.repeat(120)}` });
  assert.equal(longId.statusCode, 414);
  for (const payload of ['{}', 'null', '[]', '{"registeredAt":"private-input"}', '{invalid-json']) {
    const response = await app.inject({ method: 'PUT', url: URL, headers: { 'content-type': 'application/json' }, payload });
    assert.equal(response.statusCode, 400);
    assert.deepEqual(response.json(), { error: 'invalid_request' });
  }
  const oversized = await app.inject({ method: 'PUT', url: URL, headers: { 'content-type': 'application/json' }, payload: ' '.repeat(1_025) });
  assert.equal(oversized.statusCode, 413);
  assert.deepEqual(oversized.json(), { error: 'payload_too_large' });
  const unsupported = await app.inject({ method: 'PUT', url: URL, headers: { 'content-type': 'application/xml' }, payload: '<cve />' });
  assert.equal(unsupported.statusCode, 415);
  assert.deepEqual(unsupported.json(), { error: 'unsupported_media_type' });
  assert.equal(calls, 0);
  assert.equal(app.getDecorator<RemediationStore>('remediations').size, 0);
});

test('CVE inexistente devuelve 404 y Rejected devuelve 409, sin registrar ni auditar una creación', async (t) => {
  for (const [record, status, error] of [
    [null, 404, 'cve_not_found'], [cve('Rejected'), 409, 'cve_rejected'],
  ] as const) {
    const app = appFor(async () => record);
    t.after(() => app.close());
    const audit: unknown[] = [];
    t.mock.method(app.log, 'child', () => app.log);
    t.mock.method(app.log, 'info', (fields: { event?: string }) => {
      if (fields.event === 'remediation_registered') audit.push(fields);
    });
    const response = await app.inject({ method: 'PUT', url: URL });
    assert.equal(response.statusCode, status);
    assert.deepEqual(response.json(), { error });
    assert.equal(app.getDecorator<RemediationStore>('remediations').size, 0);
    assert.deepEqual(audit, []);
  }
});

test('traduce los errores NVD e internos sin exponer detalles del proveedor en respuestas ni logs propios', async (t) => {
  for (const [failure, status, error] of [
    [new NvdError('HTTP', 404), 502, 'nvd_unavailable'],
    [new NvdError('HTTP', 403), 502, 'nvd_unavailable'],
    [new NvdError('HTTP', 429), 503, 'service_unavailable'],
    [new NvdError('HTTP', 503), 503, 'service_unavailable'],
    [new NvdError('NETWORK'), 502, 'nvd_unavailable'],
    [new NvdError('INVALID_RESPONSE'), 502, 'nvd_unavailable'],
    [new NvdError('TIMEOUT'), 504, 'nvd_timeout'],
    [new NvdError('CANCELLED'), 503, 'service_unavailable'],
    [new Error('private-provider-detail private-nvd-key'), 500, 'internal_error'],
  ] as const) {
    const app = appFor(async () => { throw failure; });
    t.after(() => app.close());
    const logs: unknown[] = [];
    t.mock.method(app.log, 'child', () => app.log);
    t.mock.method(app.log, 'warn', (fields: unknown) => { logs.push(fields); });
    t.mock.method(app.log, 'error', (fields: unknown) => { logs.push(fields); });
    const response = await app.inject({ method: 'PUT', url: URL });
    assert.equal(response.statusCode, status);
    assert.deepEqual(response.json(), { error });
    assert.equal(response.headers['cache-control'], 'no-store');
    const output = response.body + JSON.stringify(logs);
    assert.equal(output.includes('private-provider-detail'), false);
    assert.equal(output.includes('private-nvd-key'), false);
    assert.equal(app.getDecorator<RemediationStore>('remediations').size, 0);
  }
});

test('dos PUT concurrentes generan un único registro, un 201, un 200 y un evento de creación', async (t) => {
  const queries = [Promise.withResolvers<NvdCve>(), Promise.withResolvers<NvdCve>()];
  const started = Promise.withResolvers<void>();
  let calls = 0;
  const app = appFor(async () => {
    const query = queries[calls++]!;
    if (calls === 2) started.resolve();
    return query.promise;
  });
  t.after(() => app.close());
  const logs: unknown[] = [];
  t.mock.method(app.log, 'child', () => app.log);
  t.mock.method(app.log, 'info', (fields: { event?: string }) => {
    if (fields.event === 'remediation_registered') logs.push(fields);
  });
  const first = app.inject({ method: 'PUT', url: URL }).then((response) => response);
  const second = app.inject({ method: 'PUT', url: URL }).then((response) => response);
  await started.promise;
  queries[1]!.resolve(cve());
  const secondResponse = await second;
  queries[0]!.resolve(cve());
  const firstResponse = await first;
  assert.deepEqual([firstResponse.statusCode, secondResponse.statusCode].sort(), [200, 201]);
  assert.deepEqual(firstResponse.json(), secondResponse.json());
  assert.equal(app.getDecorator<RemediationStore>('remediations').size, 1);
  assert.equal(logs.length, 1);
});

test('el plazo total cancela la consulta y devuelve 504 sin guardar la remediación', async (t) => {
  const started = Promise.withResolvers<AbortSignal>();
  const app = appFor(async (_id, options = {}) => {
    const signal = options.signal!;
    started.resolve(signal);
    return new Promise<NvdCve>((_resolve, reject) => {
      signal.addEventListener('abort', () => reject(new NvdError('CANCELLED')), { once: true });
    });
  });
  t.after(() => app.close());
  await app.ready();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const response = app.inject({ method: 'PUT', url: URL }).then((result) => result);
  const signal = await started.promise;
  t.mock.timers.tick(30_000);
  const result = await response;
  assert.equal(signal.aborted, true);
  assert.equal(result.statusCode, 504);
  assert.deepEqual(result.json(), { error: 'nvd_timeout' });
  assert.equal(app.getDecorator<RemediationStore>('remediations').size, 0);
});

test('cerrar la app cancela una validación activa y evita la escritura', async (t) => {
  const started = Promise.withResolvers<AbortSignal>();
  const app = appFor(async (_id, options = {}) => {
    const signal = options.signal!;
    started.resolve(signal);
    return new Promise<NvdCve>((_resolve, reject) => {
      signal.addEventListener('abort', () => reject(new NvdError('CANCELLED')), { once: true });
    });
  });
  t.after(() => app.close());
  const response = app.inject({ method: 'PUT', url: URL }).then((result) => result);
  const signal = await started.promise;
  await app.close();
  assert.equal(signal.aborted, true);
  assert.equal((await response).statusCode, 503);
  assert.equal(app.getDecorator<RemediationStore>('remediations').size, 0);
});

test('desconectar un cliente HTTP cancela la validación NVD y evita registrar', { timeout: 5_000 }, async (t) => {
  const started = Promise.withResolvers<AbortSignal>();
  const cancelled = Promise.withResolvers<void>();
  const app = appFor(async (_id, options = {}) => {
    const signal = options.signal!;
    started.resolve(signal);
    return new Promise<NvdCve>((_resolve, reject) => {
      signal.addEventListener('abort', () => { cancelled.resolve(); reject(new NvdError('CANCELLED')); }, { once: true });
    });
  });
  t.after(() => app.close());
  const address = await app.listen({ host: '127.0.0.1', port: 0 });
  const request = httpRequest(`${address}${URL}`, { method: 'PUT' });
  request.on('error', () => {});
  t.after(() => request.destroy());
  request.end();
  const signal = await started.promise;
  assert.equal(signal.aborted, false);
  request.destroy();
  await cancelled.promise;
  await app.close();
  assert.equal(signal.aborted, true);
  assert.equal(app.getDecorator<RemediationStore>('remediations').size, 0);
});
