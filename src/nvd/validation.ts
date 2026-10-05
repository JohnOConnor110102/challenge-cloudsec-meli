export const MAX_PAGE_SIZE = 2_000;

export interface NvdCve {
  id: string;
  published: string;
  lastModified: string;
  vulnStatus: string;
  metrics: Record<string, unknown>;
}

export interface NvdPage {
  startIndex: number;
  resultsPerPage: number;
  totalResults: number;
  timestamp: string;
  cves: NvdCve[];
}

export function isCveId(value: unknown): value is string {
  return typeof value === 'string' && value === value.trim() && /^CVE-\d{4}-\d{4,}$/.test(value);
}

export function isNvdApiKey(value: string): boolean {
  return value.length <= 256 && /^[\x21-\x7e]+$/.test(value);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isDate(value: unknown): value is string {
  return typeof value === 'string'
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})?$/.test(value)
    && Number.isFinite(Date.parse(value));
}

// Valida lo que usa el cliente y tolera campos adicionales del proveedor.
export function parseNvdPage(value: unknown): NvdPage {
  const invalid = () => new Error('Respuesta NVD inválida');
  if (!isObject(value) || value.format !== 'NVD_CVE' || value.version !== '2.0'
    || !isCount(value.startIndex) || !isCount(value.resultsPerPage)
    || value.resultsPerPage > MAX_PAGE_SIZE || !isCount(value.totalResults)
    || !isDate(value.timestamp) || !Array.isArray(value.vulnerabilities)) {
    throw invalid();
  }

  const ids = new Set<string>();
  const cves = value.vulnerabilities.map((entry: unknown): NvdCve => {
    if (!isObject(entry) || !isObject(entry.cve)) throw invalid();
    const cve = entry.cve;
    if (!isCveId(cve.id) || !isDate(cve.published) || !isDate(cve.lastModified)
      || typeof cve.vulnStatus !== 'string' || cve.vulnStatus.length === 0
      || (cve.metrics !== undefined && !isObject(cve.metrics)) || ids.has(cve.id)) {
      throw invalid();
    }
    ids.add(cve.id);
    return {
      id: cve.id,
      published: cve.published,
      lastModified: cve.lastModified,
      vulnStatus: cve.vulnStatus,
      metrics: cve.metrics ?? {},
    };
  });

  if (cves.length > value.resultsPerPage
    || (cves.length > 0 && value.startIndex + cves.length > value.totalResults)
    || (cves.length === 0 && value.startIndex < value.totalResults)) {
    throw invalid();
  }

  return {
    startIndex: value.startIndex,
    resultsPerPage: value.resultsPerPage,
    totalResults: value.totalResults,
    timestamp: value.timestamp,
    cves,
  };
}
