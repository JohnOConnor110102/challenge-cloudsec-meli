import assert from 'node:assert/strict';
import { test } from 'node:test';
import { selectCvssMetric } from '../src/cvss/selection.js';
import type { CvssVersion } from '../src/cvss/selection.js';

function metric(
  version: CvssVersion = '3.1', baseScore = 9.8,
  source = 'nvd@nist.gov', type = 'Primary',
) {
  const vectorString = version === '2.0'
    ? 'AV:N/AC:L/Au:N/C:C/I:C/A:C'
    : version === '4.0'
      ? 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
      : `CVSS:${version}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`;
  return { source, type, cvssData: { version, baseScore, vectorString } };
}

test('prioriza la versión más reciente antes que la fuente y el score', () => {
  const metrics = {
    cvssMetricV2: [metric('2.0', 10)],
    cvssMetricV30: [metric('3.0', 9.8)],
    cvssMetricV31: [metric('3.1', 9.8)],
    cvssMetricV40: [metric('4.0', 4, 'cna@example.org', 'Secondary')],
  };
  assert.deepEqual(selectCvssMetric(metrics), {
    version: '4.0', source: 'cna@example.org', type: 'Secondary',
    baseScore: 4, severity: 'medium', vectorString: metrics.cvssMetricV40[0]!.cvssData.vectorString,
  });
  assert.equal(selectCvssMetric({ ...metrics, cvssMetricV40: [] })?.version, '3.1');
  assert.equal(selectCvssMetric({ ...metrics, cvssMetricV40: [], cvssMetricV31: [] })?.version, '3.0');
  assert.equal(selectCvssMetric({ cvssMetricV2: metrics.cvssMetricV2 })?.severity, 'high');
});

test('prioriza NVD y luego Primary dentro de la misma versión', () => {
  const nvd = metric('3.1', 4, 'nvd@nist.gov', 'Secondary');
  const primary = metric('3.1', 7, 'primary@example.org');
  const secondary = metric('3.1', 10, 'secondary@example.org', 'Secondary');
  assert.equal(selectCvssMetric({ cvssMetricV31: [secondary, primary, nvd] })?.source, 'nvd@nist.gov');
  assert.equal(selectCvssMetric({ cvssMetricV31: [secondary, primary] })?.source, 'primary@example.org');
  assert.equal(selectCvssMetric({ cvssMetricV31: [secondary] })?.baseScore, 10);
  assert.equal(selectCvssMetric({
    cvssMetricV31: [nvd, metric('3.1', 3, 'nvd@nist.gov', 'Primary')],
  })?.baseScore, 3);
});

test('desempata por score, fuente y vector sin depender del orden ni modificar la entrada', () => {
  const low = metric('3.1', 4, 'a@example.org');
  const high = metric('3.1', 9.8, 'z@example.org');
  const tied = metric('3.1', 9.8, 'a@example.org');
  const alternate = {
    ...tied,
    cvssData: { ...tied.cvssData, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' },
  };
  const entries = [low, high, alternate, tied];
  const snapshot = structuredClone(entries);
  const expected = selectCvssMetric({ cvssMetricV31: Object.freeze(entries) });
  assert.equal(expected?.baseScore, 9.8);
  assert.equal(expected?.source, 'a@example.org');
  assert.equal(expected?.vectorString, alternate.cvssData.vectorString);
  for (let offset = 0; offset < entries.length; offset++) {
    const rotated = [...entries.slice(offset), ...entries.slice(0, offset)];
    assert.deepEqual(selectCvssMetric({ cvssMetricV31: rotated }), expected);
    assert.deepEqual(selectCvssMetric({ cvssMetricV31: rotated.reverse() }), expected);
  }
  assert.deepEqual(entries, snapshot);
});

test('descarta entradas inválidas individualmente y permite recurrir a una versión anterior', () => {
  const valid = metric();
  const invalid: unknown[] = [
    null, [], 'metric', {},
    { ...valid, source: '' }, { ...valid, source: ' nvd@nist.gov' },
    { ...valid, source: 'nvd@nist.gov\n' },
    { ...valid, type: undefined }, { ...valid, type: 'primary' },
    { ...valid, cvssData: null }, { ...valid, cvssData: [] },
    { ...valid, cvssData: { ...valid.cvssData, version: '4.0' } },
    ...[undefined, null, '9.8', NaN, Infinity, -1, 10.1, 8.99].map((baseScore) => ({
      ...valid, cvssData: { ...valid.cvssData, baseScore },
    })),
    ...[undefined, '', ' ', 'CVSS:3.0/AV:N', valid.cvssData.vectorString + '\n'].map((vectorString) => ({
      ...valid, cvssData: { ...valid.cvssData, vectorString },
    })),
  ];
  for (const entry of invalid) {
    assert.equal(selectCvssMetric({ cvssMetricV31: [entry] }), null);
    assert.equal(selectCvssMetric({ cvssMetricV31: [entry, valid] })?.baseScore, 9.8);
    assert.equal(selectCvssMetric({
      cvssMetricV31: [entry], cvssMetricV2: [metric('2.0', 7)],
    })?.version, '2.0');
  }
  assert.equal(selectCvssMetric({ cvssMetricV40: [valid], cvssMetricV31: [valid] })?.version, '3.1');
});

test('tolera métricas ajenas a CVSS, grupos ausentes o inválidos y campos adicionales', () => {
  for (const metrics of [undefined, null, [], {}, 'metrics', { cvssMetricV31: {} }, {
    cvssMetricV50: [metric()], ssvcV203: [{ score: 10 }],
  }]) {
    assert.equal(selectCvssMetric(metrics), null);
  }
  const valid = metric();
  assert.deepEqual(selectCvssMetric({
    cvssMetricV40: 'invalid',
    ssvcV203: [{ score: 10 }],
    cvssMetricV31: [{ ...valid, futureField: true, cvssData: { ...valid.cvssData, futureField: true } }],
  }), selectCvssMetric({ cvssMetricV31: [valid] }));
});

test('calcula la categoría desde el score y distingue el score cero de una métrica ausente', () => {
  const valid = metric('3.1', 9.8);
  assert.equal(selectCvssMetric({
    cvssMetricV31: [{ ...valid, cvssData: { ...valid.cvssData, baseSeverity: 'LOW' } }],
  })?.severity, 'critical');
  assert.equal(selectCvssMetric({ cvssMetricV31: [metric('3.1', 0)] })?.severity, 'none');
  assert.equal(selectCvssMetric({ cvssMetricV2: [metric('2.0', 0)] })?.severity, 'low');
  assert.equal(selectCvssMetric({ cvssMetricV31: [] }), null);
});
