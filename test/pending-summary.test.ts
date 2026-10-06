import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { CveClassification } from '../src/cvss/classification.js';
import type { NvdCve } from '../src/nvd/validation.js';
import { RemediationStore } from '../src/remediations/store.js';
import { CveCatalog } from '../src/sync/catalog.js';
import { summarizePendingVulnerabilities } from '../src/vulnerabilities/pending-summary.js';

const DATE = '2026-10-06T12:00:00.000Z';
const CATEGORIES = ['none', 'low', 'medium', 'high', 'critical', 'unknown'] as const;
const ZERO_COUNTS = { none: 0, low: 0, medium: 0, high: 0, critical: 0, unknown: 0 };

function cve(id: string, score?: number, vulnStatus = 'Analyzed'): NvdCve {
  return {
    id, published: DATE, lastModified: DATE, vulnStatus,
    metrics: score === undefined ? {} : {
      cvssMetricV31: [{
        source: 'nvd@nist.gov', type: 'Primary',
        cvssData: {
          version: '3.1', baseScore: score,
          vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        },
      }],
    },
  };
}

test('un catálogo vacío conserva categorías en cero aunque existan remediaciones fuera de él', () => {
  const catalog = new CveCatalog();
  const remediations = new RemediationStore();
  remediations.register('CVE-2024-1234');
  assert.deepEqual(catalog.pendingSummary((id) => remediations.has(id)), {
    total: 0, excludedRejected: 0, excludedRemediated: 0, bySeverity: ZERO_COUNTS,
  });
});

test('sin remediaciones el resumen pendiente coincide con el total y conserva los rechazados aparte', () => {
  const catalog = new CveCatalog();
  const remediations = new RemediationStore();
  catalog.upsert(cve('CVE-2024-1234', 9.8));
  catalog.upsert(cve('CVE-2024-1235'));
  catalog.upsert(cve('CVE-2024-1236', 9.8, 'Rejected'));
  assert.deepEqual(catalog.pendingSummary((id) => remediations.has(id)), {
    ...catalog.summary(), excludedRemediated: 0,
  });
});

test('total es igual a pendientes más remediadas elegibles, por cantidad y por severidad', () => {
  const catalog = new CveCatalog();
  const remediations = new RemediationStore();
  for (const [index, score] of [0, 1, 4, 7, 9.8, undefined].entries()) {
    const remediatedId = `CVE-2024-${1234 + index * 2}`;
    const pendingId = `CVE-2024-${1235 + index * 2}`;
    catalog.upsert(cve(remediatedId, score));
    catalog.upsert(cve(pendingId, score));
    remediations.register(remediatedId);
  }
  catalog.upsert(cve('CVE-2024-1246', 9.8, 'Rejected'));
  remediations.register('CVE-2024-9999');

  const total = catalog.summary();
  const pending = catalog.pendingSummary((id) => remediations.has(id));
  assert.deepEqual(pending, {
    total: 6, excludedRejected: 1, excludedRemediated: 6,
    bySeverity: { none: 1, low: 1, medium: 1, high: 1, critical: 1, unknown: 1 },
  });
  assert.equal(total.total, 12);
  assert.equal(total.total, pending.total + pending.excludedRemediated);
  for (const severity of CATEGORIES) {
    assert.equal(total.bySeverity[severity], pending.bySeverity[severity] + 1);
  }
  assert.equal(pending.total, Object.values(pending.bySeverity).reduce((sum, count) => sum + count, 0));
  assert.equal(pending.excludedRejected, total.excludedRejected);
  assert.equal(remediations.size, 7);
});

test('si todos están remediados los pendientes son cero y repetir cargas o registros no duplica exclusiones', () => {
  const catalog = new CveCatalog();
  const remediations = new RemediationStore();
  for (const record of [cve('CVE-2024-1234', 9.8), cve('CVE-2024-1235')]) {
    catalog.upsert(record);
    catalog.upsert(record);
    remediations.register(record.id);
    remediations.register(record.id);
  }
  assert.deepEqual(catalog.pendingSummary((id) => remediations.has(id)), {
    total: 0, excludedRejected: 0, excludedRemediated: 2, bySeverity: ZERO_COUNTS,
  });
  assert.equal(catalog.size, 2);
  assert.equal(remediations.size, 2);
});

test('usa la clasificación actual y no cuenta como remediado elegible un CVE que luego pasa a Rejected', () => {
  const catalog = new CveCatalog();
  const remediations = new RemediationStore();
  const remediatedId = 'CVE-2024-1234';
  const pendingId = 'CVE-2024-1235';
  catalog.upsert(cve(remediatedId, 9.8));
  catalog.upsert(cve(pendingId, 4));
  remediations.register(remediatedId);
  const first = catalog.pendingSummary((id) => remediations.has(id));
  assert.equal(first.bySeverity.medium, 1);
  assert.equal(first.excludedRemediated, 1);

  catalog.upsert(cve(remediatedId, 1));
  catalog.upsert(cve(pendingId));
  const updated = catalog.pendingSummary((id) => remediations.has(id));
  assert.equal(updated.total, 1);
  assert.equal(updated.bySeverity.unknown, 1);
  assert.equal(updated.bySeverity.low, 0);
  assert.equal(updated.excludedRemediated, 1);

  catalog.upsert(cve(remediatedId, 1, 'Rejected'));
  const rejected = catalog.pendingSummary((id) => remediations.has(id));
  assert.equal(rejected.total, 1);
  assert.equal(rejected.excludedRemediated, 0);
  assert.equal(rejected.excludedRejected, 1);
  assert.equal(catalog.summary().total, rejected.total + rejected.excludedRemediated);
  assert.equal(remediations.has(remediatedId), true);
  assert.equal(first.bySeverity.medium, 1);

  updated.total = 999;
  updated.bySeverity.unknown = 999;
  assert.equal(catalog.pendingSummary((id) => remediations.has(id)).total, 1);
  assert.equal(catalog.pendingSummary((id) => remediations.has(id)).bySeverity.unknown, 1);
});

test('recorre un iterador una sola vez y separa Rejected antes de consultar remediaciones', () => {
  let reads = 0;
  function* entries(): Generator<{ id: string; classification: CveClassification }> {
    reads++;
    yield { id: 'rejected', classification: { status: 'rejected', severity: null, metric: null } };
    yield { id: 'remediated', classification: { status: 'unscored', severity: 'unknown', metric: null } };
    yield { id: 'pending', classification: { status: 'unscored', severity: 'unknown', metric: null } };
  }
  const queried: string[] = [];
  const summary = summarizePendingVulnerabilities(entries(), (id) => {
    queried.push(id);
    return id === 'remediated';
  });
  assert.deepEqual(summary, {
    total: 1, excludedRejected: 1, excludedRemediated: 1,
    bySeverity: { ...ZERO_COUNTS, unknown: 1 },
  });
  assert.deepEqual(queried, ['remediated', 'pending']);
  assert.equal(reads, 1);
});
