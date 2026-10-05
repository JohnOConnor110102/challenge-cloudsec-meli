import type { CveClassification } from '../cvss/classification.js';
import type { CvssSeverity } from '../cvss/severity.js';

export interface VulnerabilitySummary {
  total: number;
  excludedRejected: number;
  bySeverity: Record<CvssSeverity | 'unknown', number>;
}

export function summarizeVulnerabilities(
  entries: Iterable<{ readonly classification: CveClassification }>,
): VulnerabilitySummary {
  const summary: VulnerabilitySummary = {
    total: 0,
    excludedRejected: 0,
    bySeverity: { none: 0, low: 0, medium: 0, high: 0, critical: 0, unknown: 0 },
  };

  for (const { classification } of entries) {
    if (classification.status === 'rejected') {
      summary.excludedRejected++;
    } else {
      summary.total++;
      summary.bySeverity[classification.severity]++;
    }
  }
  return summary;
}
