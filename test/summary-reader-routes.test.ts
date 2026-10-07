import assert from 'node:assert/strict';
import { test } from 'node:test';
import Fastify from 'fastify';
import { CveCatalog } from '../src/sync/catalog.js';
import { InitialSync } from '../src/sync/initial-sync.js';
import { registerVulnerabilityRoutes } from '../src/vulnerabilities/routes.js';

const urls = ['/api/v1/vulnerabilities/summary', '/api/v1/vulnerabilities/pending/summary'];
const summary = {
  total: 1, excludedRejected: 0, excludedRemediated: 0,
  bySeverity: { none: 0, low: 0, medium: 0, high: 0, critical: 0, unknown: 1 },
};

async function completedSync() {
  const sync = new InitialSync({ async getPage() {
    return { startIndex: 0, resultsPerPage: 0, totalResults: 0, timestamp: '2026-10-05T12:00:00.000', cves: [] };
  } }, new CveCatalog());
  await sync.run();
  return sync;
}

test('el estado leído con el resumen prevalece sobre un completed local desactualizado', async (t) => {
  const app = Fastify({ logger: false });
  t.after(() => app.close());
  registerVulnerabilityRoutes(app, await completedSync(), async () => ({
    status: 'running', lastPageTimestamp: null, summary,
  }));
  for (const url of urls) {
    const response = await app.inject(url);
    assert.equal(response.statusCode, 503);
    assert.deepEqual(response.json(), { error: 'catalog_not_ready', syncStatus: 'running' });
  }
});

test('un error crudo del lector no se expone en respuestas ni en logs del resumen', async (t) => {
  const app = Fastify({ logger: false });
  t.after(() => app.close());
  const logs: unknown[] = [];
  t.mock.method(app.log, 'error', (...args: unknown[]) => { logs.push(args); });
  registerVulnerabilityRoutes(app, await completedSync(), async () => {
    throw new Error('private-password private-host private-provider-detail');
  });
  for (const url of urls) {
    const response = await app.inject(url);
    assert.equal(response.statusCode, 503);
    assert.deepEqual(response.json(), { error: 'storage_unavailable' });
  }
  assert.equal(logs.length, 2);
  assert.equal(JSON.stringify(logs).includes('private-'), false);
  assert.equal(JSON.stringify(logs).includes('vulnerability_summary_failed'), true);
});
