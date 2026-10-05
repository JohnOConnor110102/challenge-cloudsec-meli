import assert from 'node:assert/strict';
import { test } from 'node:test';
import { CveCatalog } from '../src/sync/catalog.js';
import type { NvdCve } from '../src/nvd/validation.js';

const ID = 'CVE-2024-1234';
const DATE = '2026-10-05T12:00:00.000';
const VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';

function cve(id = ID, score = 9.8): NvdCve {
  return {
    id, published: DATE, lastModified: DATE, vulnStatus: 'Analyzed',
    metrics: {
      cvssMetricV31: [{
        source: 'nvd@nist.gov', type: 'Primary',
        cvssData: { version: '3.1', baseScore: score, vectorString: VECTOR },
      }],
    },
  };
}

test('el catálogo inicia vacío y cada instancia mantiene sus propios registros', () => {
  const catalog = new CveCatalog();
  assert.equal(catalog.size, 0);
  assert.equal(catalog.get(ID), undefined);
  assert.deepEqual([...catalog.values()], []);
  catalog.upsert(cve());
  assert.equal(new CveCatalog().size, 0);
});

test('guarda registros por ID y repetir la carga no genera duplicados', () => {
  const catalog = new CveCatalog();
  catalog.upsert(cve());
  catalog.upsert(cve('CVE-2024-1235'));
  catalog.upsert(cve());
  assert.equal(catalog.size, 2);
  assert.deepEqual([...catalog.values()].map((entry) => entry.id), [ID, 'CVE-2024-1235']);
  assert.deepEqual(catalog.get(ID), {
    id: ID, published: DATE, lastModified: DATE, vulnStatus: 'Analyzed',
    classification: {
      status: 'scored', severity: 'critical',
      metric: {
        version: '3.1', source: 'nvd@nist.gov', type: 'Primary',
        baseScore: 9.8, severity: 'critical', vectorString: VECTOR,
      },
    },
  });
});

test('una nueva carga reemplaza los datos y la clasificación sin incrementar la cantidad', () => {
  const catalog = new CveCatalog();
  catalog.upsert(cve());
  const previous = catalog.get(ID);
  const modified = '2026-10-05T13:00:00.000';
  catalog.upsert({ ...cve(ID, 4), lastModified: modified, vulnStatus: 'Modified' });
  assert.equal(catalog.size, 1);
  assert.equal(catalog.get(ID)?.classification.severity, 'medium');
  assert.equal(catalog.get(ID)?.lastModified, modified);
  assert.equal(catalog.get(ID)?.vulnStatus, 'Modified');
  assert.equal(previous?.classification.severity, 'critical');
});

test('conserva CVEs sin score y rechazados, y permite reclasificarlos', () => {
  const catalog = new CveCatalog();
  catalog.upsert({ ...cve(), metrics: {} });
  assert.equal(catalog.get(ID)?.classification.severity, 'unknown');
  catalog.upsert(cve());
  assert.equal(catalog.get(ID)?.classification.severity, 'critical');
  catalog.upsert({ ...cve(), vulnStatus: 'Rejected' });
  assert.deepEqual(catalog.get(ID)?.classification, {
    status: 'rejected', severity: null, metric: null,
  });
  assert.equal(catalog.size, 1);
  assert.equal([...catalog.values()].length, 1);
});

test('la entrada y los resultados de consulta no exponen referencias al estado interno', () => {
  const catalog = new CveCatalog();
  const input = cve();
  catalog.upsert(input);
  input.id = 'CVE-2024-9999';
  input.metrics.cvssMetricV31 = [];
  const retrieved = catalog.get(ID)!;
  assert.ok(retrieved.classification.status === 'scored');
  retrieved.id = 'CVE-2024-8888';
  retrieved.classification.metric.source = 'modified@example.org';
  retrieved.classification.severity = 'low';
  const iterated = [...catalog.values()][0]!;
  iterated.vulnStatus = 'Rejected';
  assert.ok(iterated.classification.status === 'scored');
  iterated.classification.metric.baseScore = 0;
  const stored = catalog.get(ID)!;
  assert.equal(catalog.size, 1);
  assert.equal(stored.id, ID);
  assert.equal(stored.vulnStatus, 'Analyzed');
  assert.equal(stored.classification.severity, 'critical');
  assert.ok(stored.classification.status === 'scored');
  assert.equal(stored.classification.metric.source, 'nvd@nist.gov');
  assert.equal(stored.classification.metric.baseScore, 9.8);
  assert.equal(catalog.get(input.id), undefined);
  assert.equal(catalog.get(retrieved.id), undefined);
});
