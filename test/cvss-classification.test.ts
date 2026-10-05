import assert from 'node:assert/strict';
import { test } from 'node:test';
import { classifyCve } from '../src/cvss/classification.js';
import { parseNvdPage } from '../src/nvd/validation.js';
import type { NvdCve } from '../src/nvd/validation.js';

const DATE = '2026-10-05T12:00:00.000';
const VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';

function metrics(baseScore = 9.8) {
  return {
    cvssMetricV31: [{
      source: 'nvd@nist.gov', type: 'Primary',
      cvssData: { version: '3.1', baseScore, vectorString: VECTOR },
    }],
  };
}

function cve(overrides: Partial<NvdCve> = {}): NvdCve {
  return {
    id: 'CVE-2024-1234', published: DATE, lastModified: DATE,
    vulnStatus: 'Analyzed', metrics: metrics(), ...overrides,
  };
}

test('clasifica un CVE con score y conserva la evidencia de la evaluación seleccionada', () => {
  assert.deepEqual(classifyCve(cve()), {
    status: 'scored', severity: 'critical',
    metric: {
      version: '3.1', source: 'nvd@nist.gov', type: 'Primary',
      baseScore: 9.8, severity: 'critical', vectorString: VECTOR,
    },
  });
});

test('los CVE sin métricas utilizables quedan como unknown, incluso si figuran Analyzed', () => {
  const invalidMetrics = {
    cvssMetricV31: [{
      source: 'nvd@nist.gov', type: 'Primary',
      cvssData: { version: '3.1', baseScore: '9.8', vectorString: VECTOR },
    }],
  };
  for (const value of [{}, { cvssMetricV31: [] }, invalidMetrics, { ssvcV203: [] }]) {
    assert.deepEqual(classifyCve(cve({ metrics: value })), {
      status: 'unscored', severity: 'unknown', metric: null,
    });
  }
});

test('los estados no rechazados usan las métricas disponibles sin exigir Analyzed', () => {
  for (const vulnStatus of [
    'Received', 'Awaiting Analysis', 'Undergoing Analysis', 'Analyzed', 'Modified',
    'Deferred', 'New', 'Enriched', 'Modified After Enrichment', 'Future Status',
  ]) {
    assert.equal(classifyCve(cve({ vulnStatus })).severity, 'critical', vulnStatus);
    assert.equal(classifyCve(cve({ vulnStatus, metrics: {} })).severity, 'unknown', vulnStatus);
  }
});

test('Rejected prevalece incluso con métricas presentes y evita interpretarlas', () => {
  for (const value of [metrics(), {}, { cvssMetricV31: [null] }]) {
    assert.deepEqual(classifyCve(cve({ vulnStatus: 'Rejected', metrics: value })), {
      status: 'rejected', severity: null, metric: null,
    });
  }
  const rejected = cve({ vulnStatus: 'Rejected' });
  Object.defineProperty(rejected, 'metrics', {
    get() { throw new Error('No se deben leer métricas de un CVE rechazado'); },
  });
  assert.equal(classifyCve(rejected).status, 'rejected');
});

test('un score cero es una evaluación válida y se distingue de unknown y rejected', () => {
  const zero = classifyCve(cve({ metrics: metrics(0) }));
  assert.equal(zero.status, 'scored');
  assert.equal(zero.severity, 'none');
  assert.equal(zero.metric?.baseScore, 0);

  const legacy = classifyCve(cve({ metrics: {
    cvssMetricV2: [{
      source: 'nvd@nist.gov', type: 'Primary',
      cvssData: { version: '2.0', baseScore: 0, vectorString: 'AV:N/AC:L/Au:N/C:N/I:N/A:N' },
    }],
  } }));
  assert.equal(legacy.status, 'scored');
  assert.equal(legacy.severity, 'low');
});

test('reclasifica cambios de score y estado sin conservar resultados anteriores ni modificar el CVE', () => {
  const original = cve();
  const snapshot = structuredClone(original);
  Object.freeze(original);
  const initial = classifyCve(original);
  assert.equal(initial.severity, 'critical');
  assert.equal(classifyCve({ ...original, metrics: metrics(4) }).severity, 'medium');
  assert.equal(classifyCve({ ...original, metrics: {} }).severity, 'unknown');
  assert.equal(classifyCve({ ...original, vulnStatus: 'Rejected' }).status, 'rejected');
  assert.deepEqual(classifyCve(original), initial);
  assert.deepEqual(original, snapshot);
});

test('clasifica registros normalizados por el cliente, incluyendo métricas omitidas y Rejected', () => {
  const parsed = parseNvdPage({
    format: 'NVD_CVE', version: '2.0', timestamp: DATE,
    startIndex: 0, resultsPerPage: 3, totalResults: 3,
    vulnerabilities: [
      { cve: cve() },
      { cve: { ...cve({ id: 'CVE-2024-1235', vulnStatus: 'Awaiting Analysis' }), metrics: undefined } },
      { cve: cve({ id: 'CVE-2024-1236', vulnStatus: 'Rejected' }) },
    ],
  });
  const classified = parsed.cves.map(classifyCve);
  assert.deepEqual(classified.map((result) => result.status), ['scored', 'unscored', 'rejected']);
  assert.deepEqual(classified.map((result) => result.severity), ['critical', 'unknown', null]);
});
