import type { NvdCve } from '../nvd/validation.js';
import { selectCvssMetric } from './selection.js';
import type { CvssMetric } from './selection.js';
import type { CvssSeverity } from './severity.js';

export type CveClassification =
  | { status: 'scored'; severity: CvssSeverity; metric: CvssMetric }
  | { status: 'unscored'; severity: 'unknown'; metric: null }
  | { status: 'rejected'; severity: null; metric: null };

// Recibe un CVE validado por el cliente NVD y devuelve solo su clasificación.
export function classifyCve(cve: NvdCve): CveClassification {
  if (cve.vulnStatus === 'Rejected') {
    return { status: 'rejected', severity: null, metric: null };
  }

  const metric = selectCvssMetric(cve.metrics);
  if (metric === null) {
    return { status: 'unscored', severity: 'unknown', metric: null };
  }
  return { status: 'scored', severity: metric.severity, metric };
}
