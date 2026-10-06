import type { CveClassification } from '../cvss/classification.js';
import { summarizeVulnerabilities } from './summary.js';
import type { VulnerabilitySummary } from './summary.js';

export interface PendingVulnerabilitySummary extends VulnerabilitySummary {
  excludedRemediated: number;
}

export function summarizePendingVulnerabilities(
  entries: Iterable<{ readonly id: string; readonly classification: CveClassification }>,
  isRemediated: (cveId: string) => boolean,
): PendingVulnerabilitySummary {
  let excludedRemediated = 0;
  function* pendingEntries() {
    for (const entry of entries) {
      if (entry.classification.status !== 'rejected' && isRemediated(entry.id)) {
        excludedRemediated++;
      } else {
        yield entry;
      }
    }
  }

  const summary = summarizeVulnerabilities(pendingEntries());
  return { ...summary, excludedRemediated };
}
