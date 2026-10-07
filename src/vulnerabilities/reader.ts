import type { SyncProgress } from '../sync/initial-sync.js';
import type { PendingVulnerabilitySummary } from './pending-summary.js';

export interface SummarySnapshot {
  status: SyncProgress['status'];
  lastPageTimestamp: string | null;
  summary: PendingVulnerabilitySummary;
}

export type ReadSummary = (pending: boolean) => Promise<SummarySnapshot>;
