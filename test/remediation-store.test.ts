import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RemediationStore } from '../src/remediations/store.js';

const ID = 'CVE-2024-1234';
const DATE = '2026-10-05T12:00:00.000Z';

test('las remediaciones inician vacías y cada instancia conserva su propio estado', () => {
  const store = new RemediationStore();
  assert.equal(store.size, 0);
  assert.equal(store.get(ID), undefined);
  store.register(ID);
  assert.equal(store.size, 1);
  assert.equal(new RemediationStore().get(ID), undefined);
});

test('registra el CVE con la fecha del servidor en UTC', () => {
  const store = new RemediationStore(() => new Date('2026-10-05T09:00:00.000-03:00'));
  assert.deepEqual(store.register(ID), {
    created: true, remediation: { cveId: ID, registeredAt: DATE },
  });
  assert.deepEqual(store.get(ID), { cveId: ID, registeredAt: DATE });
  assert.equal(store.size, 1);
});

test('repetir un registro conserva la primera fecha sin consultar nuevamente el reloj', () => {
  let calls = 0;
  const store = new RemediationStore(() => {
    calls++;
    return new Date(calls === 1 ? DATE : '2026-10-06T12:00:00.000Z');
  });
  const first = store.register(ID);
  const repeated = store.register(ID);
  assert.equal(first.created, true);
  assert.equal(repeated.created, false);
  assert.deepEqual(repeated.remediation, first.remediation);
  assert.equal(store.size, 1);
  assert.equal(calls, 1);
});

test('registros concurrentes del mismo ID tienen una sola creación y otros IDs son independientes', async () => {
  const store = new RemediationStore(() => new Date(DATE));
  const results = await Promise.all(Array.from({ length: 10 }, async () => store.register(ID)));
  assert.equal(results.filter((result) => result.created).length, 1);
  for (const result of results) {
    assert.deepEqual(result.remediation, { cveId: ID, registeredAt: DATE });
  }
  assert.equal(store.register('CVE-2024-12345').created, true);
  assert.equal(store.size, 2);
});

test('modificar los resultados no cambia el registro guardado ni su ID', () => {
  const store = new RemediationStore(() => new Date(DATE));
  const created = store.register(ID);
  created.remediation.cveId = 'CVE-2024-9999';
  created.remediation.registeredAt = 'changed';
  const retrieved = store.get(ID)!;
  retrieved.registeredAt = 'changed';
  const repeated = store.register(ID);
  repeated.remediation.registeredAt = 'changed';
  assert.deepEqual(store.get(ID), { cveId: ID, registeredAt: DATE });
  assert.equal(store.get('CVE-2024-9999'), undefined);
  assert.equal(store.size, 1);
});

test('rechaza IDs mal formados sin guardarlos ni incluirlos en el error', () => {
  const store = new RemediationStore(() => { throw new Error('El reloj no debe consultarse'); });
  for (const id of ['', 'cve-2024-1234', ' CVE-2024-1234', 'CVE-2024-1234\n', 'CVE-2024-123', 'secret-value']) {
    assert.throws(() => store.register(id), { message: 'El ID debe tener formato CVE-AAAA-NNNN' });
  }
  assert.equal(store.size, 0);
});
