import assert from 'node:assert/strict';
import { test } from 'node:test';
import { classifyCvssScore } from '../src/cvss/severity.js';
import type { CvssSeverity } from '../src/cvss/severity.js';

test('clasifica los límites de severidad en CVSS v3.0, v3.1 y v4.0', () => {
  const cases: [number, CvssSeverity][] = [
    [0, 'none'],
    [0.1, 'low'], [3.9, 'low'],
    [4, 'medium'], [6.9, 'medium'],
    [7, 'high'], [8.9, 'high'],
    [9, 'critical'], [9.8, 'critical'], [10, 'critical'],
  ];
  for (const version of ['3.0', '3.1', '4.0']) {
    for (const [score, severity] of cases) {
      assert.equal(classifyCvssScore(version, score), severity, `${version}: ${score}`);
    }
  }
});

test('conserva la escala de CVSS v2.0: cero es low y no existe critical', () => {
  const cases: [number, CvssSeverity][] = [
    [0, 'low'], [0.1, 'low'], [3.9, 'low'],
    [4, 'medium'], [6.9, 'medium'],
    [7, 'high'], [8.9, 'high'], [9, 'high'], [9.8, 'high'], [10, 'high'],
  ];
  for (const [score, severity] of cases) {
    assert.equal(classifyCvssScore('2.0', score), severity, `2.0: ${score}`);
  }
});

test('rechaza scores inválidos sin coerción, redondeo ni severidad predeterminada', () => {
  const invalidScores: unknown[] = [
    undefined, null, '', '0', '9.8', true, false, {}, [], [9.8],
    NaN, Infinity, -Infinity, -0.1, 10.1, 0.01, 3.99, 6.99, 8.99,
  ];
  for (const version of ['2.0', '3.0', '3.1', '4.0']) {
    for (const score of invalidScores) {
      assert.equal(classifyCvssScore(version, score), null);
    }
  }
});

test('rechaza versiones ausentes, desconocidas o mal formadas', () => {
  for (const version of [undefined, null, '', 3.1, '3', '3.2', '5.0', ' 3.1', '3.1\n', {}, []]) {
    assert.equal(classifyCvssScore(version, 9.8), null);
  }
});
