export type CvssSeverity = 'none' | 'low' | 'medium' | 'high' | 'critical';

// Clasifica un score publicado; no calcula el score a partir del vector CVSS.
export function classifyCvssScore(version: unknown, baseScore: unknown): CvssSeverity | null {
  if (version !== '2.0' && version !== '3.0' && version !== '3.1' && version !== '4.0') {
    return null;
  }
  if (typeof baseScore !== 'number' || !Number.isFinite(baseScore)
    || baseScore < 0 || baseScore > 10 || !Number.isInteger(baseScore * 10)) {
    return null;
  }

  if (version === '2.0') {
    if (baseScore < 4) return 'low';
    if (baseScore < 7) return 'medium';
    return 'high';
  }

  if (baseScore === 0) return 'none';
  if (baseScore < 4) return 'low';
  if (baseScore < 7) return 'medium';
  if (baseScore < 9) return 'high';
  return 'critical';
}
