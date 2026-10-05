import { classifyCvssScore } from './severity.js';
import type { CvssSeverity } from './severity.js';

export type CvssVersion = '2.0' | '3.0' | '3.1' | '4.0';

export interface CvssMetric {
  version: CvssVersion;
  source: string;
  type: 'Primary' | 'Secondary';
  baseScore: number;
  severity: CvssSeverity;
  vectorString: string;
}

const groups: readonly [string, CvssVersion][] = [
  ['cvssMetricV40', '4.0'],
  ['cvssMetricV31', '3.1'],
  ['cvssMetricV30', '3.0'],
  ['cvssMetricV2', '2.0'],
];

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isVisibleText(value: unknown): value is string {
  return typeof value === 'string' && /^[\x21-\x7e]+$/.test(value);
}

function parseMetric(value: unknown, version: CvssVersion): CvssMetric | null {
  if (!isObject(value) || !isVisibleText(value.source)
    || (value.type !== 'Primary' && value.type !== 'Secondary')
    || !isObject(value.cvssData)) {
    return null;
  }
  const data = value.cvssData;
  if (data.version !== version || typeof data.baseScore !== 'number'
    || !isVisibleText(data.vectorString)
    || !data.vectorString.startsWith(version === '2.0' ? 'AV:' : `CVSS:${version}/`)) {
    return null;
  }
  const severity = classifyCvssScore(version, data.baseScore);
  if (severity === null) return null;

  return {
    version, source: value.source, type: value.type,
    baseScore: data.baseScore, severity, vectorString: data.vectorString,
  };
}

// Comparación ordinal: el resultado no depende del idioma del sistema.
function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareMetrics(left: CvssMetric, right: CvssMetric): number {
  return Number(right.source === 'nvd@nist.gov') - Number(left.source === 'nvd@nist.gov')
    || Number(right.type === 'Primary') - Number(left.type === 'Primary')
    || right.baseScore - left.baseScore
    || compareText(left.source, right.source)
    || compareText(left.vectorString, right.vectorString);
}

// Selecciona una métrica; ignora campos ajenos a CVSS y entradas inválidas.
export function selectCvssMetric(metrics: unknown): CvssMetric | null {
  if (!isObject(metrics)) return null;

  for (const [key, version] of groups) {
    const entries = metrics[key];
    if (!Array.isArray(entries)) continue;
    const candidates: CvssMetric[] = [];
    for (const entry of entries) {
      const metric = parseMetric(entry, version);
      if (metric !== null) candidates.push(metric);
    }
    if (candidates.length > 0) return candidates.sort(compareMetrics)[0]!;
  }
  return null;
}
