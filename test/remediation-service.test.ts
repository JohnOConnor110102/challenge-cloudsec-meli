import assert from 'node:assert/strict';
import { test } from 'node:test';
import { NvdClient, NvdError } from '../src/nvd/client.js';
import type { NvdCve } from '../src/nvd/validation.js';
import { RemediationError, RemediationService } from '../src/remediations/service.js';
import { RemediationStore } from '../src/remediations/store.js';

const ID = 'CVE-2024-1234';
const DATE = '2026-10-06T12:00:00.000Z';

function cve(vulnStatus = 'Analyzed'): NvdCve {
  return { id: ID, published: DATE, lastModified: DATE, vulnStatus, metrics: {} };
}

test('consulta el ID solicitado y registra un CVE existente, incluso sin score', async () => {
  const store = new RemediationStore(() => new Date(DATE));
  const calls: string[] = [];
  const service = new RemediationService(store, {
    async getCve(id) { calls.push(id); return cve('Awaiting Analysis'); },
  });
  assert.deepEqual(await service.register(ID), {
    created: true, remediation: { cveId: ID, registeredAt: DATE },
  });
  assert.deepEqual(calls, [ID]);
  assert.equal(store.size, 1);
});

test('un ID inválido no consulta NVD ni guarda datos y el error no incluye su valor', async () => {
  const store = new RemediationStore();
  let calls = 0;
  const service = new RemediationService(store, {
    async getCve() { calls++; return cve(); },
  });
  for (const id of ['', 'secret-value', 'cve-2024-1234', ' CVE-2024-1234', 'CVE-2024-1234\n']) {
    await assert.rejects(service.register(id), {
      name: 'RemediationError', code: 'INVALID_CVE_ID', message: 'El ID debe tener formato CVE-AAAA-NNNN',
    });
  }
  assert.equal(calls, 0);
  assert.equal(store.size, 0);
});

test('un CVE inexistente no se registra y puede intentarse nuevamente si aparece en NVD', async () => {
  const store = new RemediationStore();
  let calls = 0;
  const service = new RemediationService(store, {
    async getCve() { return ++calls === 1 ? null : cve(); },
  });
  await assert.rejects(service.register(ID), (error: unknown) =>
    error instanceof RemediationError && error.code === 'CVE_NOT_FOUND');
  assert.equal(store.size, 0);
  assert.equal((await service.register(ID)).created, true);
  assert.equal(calls, 2);
});

test('un CVE Rejected no se registra como remediado', async () => {
  const store = new RemediationStore();
  const service = new RemediationService(store, { async getCve() { return cve('Rejected'); } });
  await assert.rejects(service.register(ID), (error: unknown) =>
    error instanceof RemediationError && error.code === 'CVE_REJECTED');
  assert.equal(store.size, 0);
});

test('un duplicado devuelve la remediación original sin depender de la disponibilidad de NVD', async () => {
  const store = new RemediationStore(() => new Date(DATE));
  let calls = 0;
  const service = new RemediationService(store, {
    async getCve() {
      if (++calls > 1) throw new NvdError('NETWORK');
      return cve();
    },
  });
  const first = await service.register(ID);
  const repeated = await service.register(ID);
  assert.equal(first.created, true);
  assert.equal(repeated.created, false);
  assert.deepEqual(repeated.remediation, first.remediation);
  repeated.remediation.registeredAt = 'changed';
  assert.equal(store.get(ID)?.registeredAt, DATE);
  assert.equal(calls, 1);
});

test('los fallos del proveedor conservan su tipo y nunca se interpretan como CVE inexistente', async () => {
  for (const failure of [
    new NvdError('HTTP', 404), new NvdError('HTTP', 429), new NvdError('HTTP', 503),
    new NvdError('NETWORK'), new NvdError('TIMEOUT'), new NvdError('INVALID_RESPONSE'), new NvdError('CANCELLED'),
  ]) {
    const store = new RemediationStore();
    const service = new RemediationService(store, { async getCve() { throw failure; } });
    await assert.rejects(service.register(ID), (error: unknown) => error === failure);
    assert.equal(store.size, 0);
  }
});

test('consultas concurrentes completadas en distinto orden crean un único registro', async () => {
  const firstQuery = Promise.withResolvers<NvdCve>();
  const secondQuery = Promise.withResolvers<NvdCve>();
  const store = new RemediationStore(() => new Date(DATE));
  let calls = 0;
  const started = Promise.withResolvers<void>();
  const service = new RemediationService(store, {
    async getCve() {
      if (++calls === 2) started.resolve();
      return calls === 1 ? firstQuery.promise : secondQuery.promise;
    },
  });
  const first = service.register(ID);
  const second = service.register(ID);
  await started.promise;
  assert.equal(calls, 2);
  assert.equal(store.size, 0);
  secondQuery.resolve(cve());
  const secondResult = await second;
  firstQuery.resolve(cve());
  const firstResult = await first;
  assert.equal(secondResult.created, true);
  assert.equal(firstResult.created, false);
  assert.deepEqual(firstResult.remediation, secondResult.remediation);
  assert.equal(store.size, 1);
});

test('una señal cancelada antes de la consulta no accede al proveedor ni registra datos', async () => {
  const store = new RemediationStore();
  let calls = 0;
  const service = new RemediationService(store, {
    async getCve() { calls++; return cve(); },
  });
  await assert.rejects(service.register(ID, { signal: AbortSignal.abort('private-detail') }), {
    name: 'NvdError', code: 'CANCELLED', message: 'Consulta NVD cancelada',
  });
  assert.equal(calls, 0);
  assert.equal(store.size, 0);
});

test('cancelar durante la consulta impide registrar incluso si el proveedor devuelve el CVE', async () => {
  const pending = Promise.withResolvers<NvdCve>();
  const store = new RemediationStore();
  const controller = new AbortController();
  const started = Promise.withResolvers<void>();
  const service = new RemediationService(store, {
    async getCve(_id, options = {}) {
      assert.equal(options.signal, controller.signal);
      started.resolve();
      return pending.promise;
    },
  });
  const task = service.register(ID, { signal: controller.signal });
  await started.promise;
  controller.abort();
  pending.resolve(cve());
  await assert.rejects(task, { name: 'NvdError', code: 'CANCELLED' });
  assert.equal(store.size, 0);
});

test('propaga requestId y cancelación al repositorio y espera la persistencia antes de informar una creación', async () => {
  const saved = Promise.withResolvers<ReturnType<RemediationStore['register']>>();
  const started = Promise.withResolvers<void>();
  const requestId = '88a5e984-4d5d-4a14-8e79-651efc00e653';
  const controller = new AbortController();
  const service = new RemediationService({
    async get() { return undefined; },
    async register(id, context) {
      assert.equal(id, ID);
      assert.deepEqual(context, { requestId, signal: controller.signal });
      started.resolve(); return saved.promise;
    },
  }, { async getCve() { return cve(); } });
  let finished = false;
  const task = service.register(ID, { requestId, signal: controller.signal }).then((result) => {
    finished = true; return result;
  });
  await started.promise;
  assert.equal(finished, false);
  saved.resolve({ created: true, remediation: { cveId: ID, registeredAt: DATE } });
  assert.equal((await task).created, true);
});

test('cancelar mientras se lee una remediación impide consultar NVD o devolver el duplicado', async () => {
  const existing = Promise.withResolvers<ReturnType<RemediationStore['get']>>();
  const controller = new AbortController();
  const service = new RemediationService({
    get: () => existing.promise,
    register() { assert.fail('No debe guardar'); },
  }, { async getCve() { assert.fail('No debe consultar NVD'); } });
  const task = service.register(ID, { signal: controller.signal });
  controller.abort();
  existing.resolve({ cveId: ID, registeredAt: DATE });
  await assert.rejects(task, { code: 'CANCELLED' });
});

test('el servicio integrado con el cliente rechaza una respuesta con otro CVE sin escribir', async () => {
  const store = new RemediationStore();
  const client = new NvdClient({}, {
    fetch: async () => Response.json({
      format: 'NVD_CVE', version: '2.0', timestamp: DATE,
      startIndex: 0, resultsPerPage: 1, totalResults: 1,
      vulnerabilities: [{ cve: { ...cve(), id: 'CVE-2024-9999' } }],
    }),
  });
  const service = new RemediationService(store, client);
  await assert.rejects(service.register(ID), { name: 'NvdError', code: 'INVALID_RESPONSE' });
  assert.equal(store.size, 0);
});
