import { classifyCve } from '../cvss/classification.js';
import type { CveClassification } from '../cvss/classification.js';
import type { NvdCve } from '../nvd/validation.js';
import { summarizeVulnerabilities } from '../vulnerabilities/summary.js';
import type { VulnerabilitySummary } from '../vulnerabilities/summary.js';
import { summarizePendingVulnerabilities } from '../vulnerabilities/pending-summary.js';
import type { PendingVulnerabilitySummary } from '../vulnerabilities/pending-summary.js';

export interface CatalogEntry {
  id: string;
  published: string;
  lastModified: string;
  vulnStatus: string;
  classification: CveClassification;
}

export class CveCatalog {
  readonly #records = new Map<string, CatalogEntry>();

  get size(): number {
    return this.#records.size;
  }

  // Cada registro validado reemplaza al anterior del mismo ID.
  upsert(cve: NvdCve): void {
    const classification = classifyCve(cve);
    this.#records.set(cve.id, {
      id: cve.id, published: cve.published,
      lastModified: cve.lastModified, vulnStatus: cve.vulnStatus, classification,
    });
  }

  get(id: string): CatalogEntry | undefined {
    const entry = this.#records.get(id);
    return entry === undefined ? undefined : structuredClone(entry);
  }

  summary(): VulnerabilitySummary {
    // El cálculo solo lee los registros; evita clonar todo el catálogo.
    return summarizeVulnerabilities(this.#records.values());
  }

  pendingSummary(isRemediated: (cveId: string) => boolean): PendingVulnerabilitySummary {
    return summarizePendingVulnerabilities(this.#records.values(), isRemediated);
  }

  *values(): IterableIterator<CatalogEntry> {
    for (const entry of this.#records.values()) {
      yield structuredClone(entry);
    }
  }
}
