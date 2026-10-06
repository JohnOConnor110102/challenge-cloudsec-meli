import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import type { NvdCve, NvdPage } from '../src/nvd/validation.js';
import { InitialSync } from '../src/sync/initial-sync.js';
import type { PendingVulnerabilitySummary } from '../src/vulnerabilities/pending-summary.js';
import type { VulnerabilitySummary } from '../src/vulnerabilities/summary.js';

const URL = '/api/v1/vulnerabilities/pending/summary';
const TOTAL_URL = '/api/v1/vulnerabilities/summary';
const DATE = '2026-10-06T12:00:00.000Z';
const CATEGORIES = ['none', 'low', 'medium', 'high', 'critical', 'unknown'] as const;
function cve(id: string, score?: number, vulnStatus = 'Analyzed'): NvdCve {
  return {
    id, published: DATE, lastModified: DATE, vulnStatus,
    metrics: score === undefined ? {} : {
      cvssMetricV31: [{
        source: 'nvd@nist.gov', type: 'Primary',
        cvssData: { version: '3.1', baseScore: score, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
      }],
    },
  };
}
function page(cves: NvdCve[], startIndex = 0, totalResults = cves.length): NvdPage {
  return { cves, startIndex, totalResults, resultsPerPage: cves.length, timestamp: DATE };
}

test('un catálogo vacío cargado devuelve pendientes en cero con metadatos y sin consultar NVD de nuevo', async (t) => {
  let calls = 0;
  const app = buildApp(loadConfig({ NODE_ENV: 'test' }), {
    async getPage() { calls++; return page([]); },
    async getCve() { throw new Error('Consulta individual no esperada'); },
  });
  t.after(() => app.close());
  await app.getDecorator<InitialSync>('initialSync').run();
  const response = await app.inject(URL);
  assert.equal(response.statusCode, 200);
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.match(response.headers['content-type'] ?? '', /application\/json/);
  assert.deepEqual(response.json(), {
    total: 0, excludedRejected: 0, excludedRemediated: 0,
    bySeverity: { none: 0, low: 0, medium: 0, high: 0, critical: 0, unknown: 0 },
    meta: { syncStatus: 'completed', lastPageTimestamp: DATE },
  });
  assert.equal(calls, 1);
});

test('GET y PUT reflejan remediaciones por severidad sin alterar el total ni restar CVEs fuera del catálogo', async (t) => {
  const records = [0, 1, 4, 7, 9.8, undefined].flatMap((score, index) => [
    cve(`CVE-2024-${1234 + index * 2}`, score), cve(`CVE-2024-${1235 + index * 2}`, score),
  ]);
  records.push(cve('CVE-2024-1246', 9.8, 'Rejected'));
  let pageCalls = 0;
  let individualCalls = 0;
  const app = buildApp(loadConfig({ NODE_ENV: 'test' }), {
    async getPage() { pageCalls++; return page(records); },
    async getCve(id) {
      individualCalls++;
      return id === 'CVE-2024-9999' ? cve(id) : records.find((record) => record.id === id) ?? null;
    },
  });
  t.after(() => app.close());
  await app.getDecorator<InitialSync>('initialSync').run();
  const totalBefore = (await app.inject(TOTAL_URL)).json<VulnerabilitySummary>();
  const before = (await app.inject(URL)).json<PendingVulnerabilitySummary>();
  assert.deepEqual(before, { ...totalBefore, excludedRemediated: 0 });
  for (let index = 0; index < 6; index++) {
    const response = await app.inject({ method: 'PUT', url: `/api/v1/remediations/CVE-2024-${1234 + index * 2}` });
    assert.equal(response.statusCode, 201);
  }
  assert.equal((await app.inject({ method: 'PUT', url: '/api/v1/remediations/CVE-2024-9999' })).statusCode, 201);
  const response = await app.inject(URL);
  assert.equal(response.statusCode, 200);
  assert.equal(response.headers['cache-control'], 'no-store');
  const pending = response.json<PendingVulnerabilitySummary>();
  assert.deepEqual(pending, {
    total: 6, excludedRejected: 1, excludedRemediated: 6,
    bySeverity: { none: 1, low: 1, medium: 1, high: 1, critical: 1, unknown: 1 },
    meta: { syncStatus: 'completed', lastPageTimestamp: DATE },
  });
  const totalAfter = (await app.inject(TOTAL_URL)).json<VulnerabilitySummary>();
  assert.deepEqual(totalAfter, totalBefore);
  assert.equal(totalAfter.total, pending.total + pending.excludedRemediated);
  for (const severity of CATEGORIES) assert.equal(totalAfter.bySeverity[severity], pending.bySeverity[severity] + 1);
  assert.equal((await app.inject({ method: 'PUT', url: '/api/v1/remediations/CVE-2024-1234' })).statusCode, 200);
  assert.deepEqual((await app.inject(URL)).json(), pending);
  assert.equal(pageCalls, 1);
  assert.equal(individualCalls, 7);
});

test('una remediación registrada antes de llegar su página se excluye solo al completar la carga', async (t) => {
  const requested = Promise.withResolvers<void>();
  const lastPage = Promise.withResolvers<NvdPage>();
  const first = cve('CVE-2024-1234', 4);
  const second = cve('CVE-2024-1235', 9.8);
  const app = buildApp(loadConfig({ NODE_ENV: 'test' }), {
    async getCve(id) { return id === second.id ? second : null; },
    async getPage(options = {}) {
      if (options.startIndex === 0) return page([first], 0, 2);
      requested.resolve();
      return lastPage.promise;
    },
  });
  t.after(() => app.close());
  const task = app.getDecorator<InitialSync>('initialSync').run();
  await requested.promise;
  assert.equal((await app.inject({ method: 'PUT', url: `/api/v1/remediations/${second.id}` })).statusCode, 201);
  const loading = await app.inject(URL);
  assert.equal(loading.statusCode, 503);
  assert.deepEqual(loading.json(), { error: 'catalog_not_ready', syncStatus: 'running' });
  lastPage.resolve(page([second], 1, 2));
  await task;
  assert.deepEqual((await app.inject(URL)).json(), {
    total: 1, excludedRejected: 0, excludedRemediated: 1,
    bySeverity: { none: 0, low: 0, medium: 1, high: 0, critical: 0, unknown: 0 },
    meta: { syncStatus: 'completed', lastPageTimestamp: DATE },
  });
});

test('una validación PUT en curso o fallida no reduce pendientes; una creación confirmada sí', async (t) => {
  const record = cve('CVE-2024-1234', 9.8);
  const requested = Promise.withResolvers<void>();
  const validation = Promise.withResolvers<NvdCve>();
  const app = buildApp(loadConfig({ NODE_ENV: 'test' }), {
    async getPage() { return page([record]); },
    async getCve(id) {
      if (id !== record.id) return null;
      requested.resolve();
      return validation.promise;
    },
  });
  t.after(() => app.close());
  await app.getDecorator<InitialSync>('initialSync').run();
  const before = (await app.inject(URL)).json<PendingVulnerabilitySummary>();
  assert.equal(before.total, 1);
  assert.equal(before.excludedRemediated, 0);
  assert.equal((await app.inject({ method: 'PUT', url: '/api/v1/remediations/CVE-2024-9999' })).statusCode, 404);
  assert.deepEqual((await app.inject(URL)).json(), before);
  const registration = app.inject({ method: 'PUT', url: `/api/v1/remediations/${record.id}` }).then((response) => response);
  await requested.promise;
  assert.deepEqual((await app.inject(URL)).json(), before);
  validation.resolve(record);
  assert.equal((await registration).statusCode, 201);
  assert.deepEqual((await app.inject(URL)).json(), {
    total: 0, excludedRejected: 0, excludedRemediated: 1,
    bySeverity: { none: 0, low: 0, medium: 0, high: 0, critical: 0, unknown: 0 },
    meta: { syncStatus: 'completed', lastPageTimestamp: DATE },
  });
  assert.equal((await app.inject(TOTAL_URL)).json<VulnerabilitySummary>().total, 1);
});
