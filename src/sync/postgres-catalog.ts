import type { Pool, PoolClient } from 'pg';
import { classifyCve } from '../cvss/classification.js';
import type { NvdPage } from '../nvd/validation.js';
import { parseNvdPage } from '../nvd/validation.js';
import type { SyncProgress, SyncStore } from './initial-sync.js';
import type { SummarySnapshot } from '../vulnerabilities/reader.js';
import type { PendingVulnerabilitySummary } from '../vulnerabilities/pending-summary.js';

interface ProgressRow {
  status: SyncProgress['status'] | null;
  next_start_index: string | null;
  total_results: string | null;
  stored_records: string;
  last_page_timestamp: Date | null;
}

function count(value: string): number {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw new Error('Conteo persistido inválido');
  return number;
}

// NVD también devuelve fechas UTC sin sufijo: explicitarlo antes de enviarlas a PostgreSQL.
function utc(value: string): string {
  return /(?:Z|[+-]\d{2}:\d{2})$/.test(value) ? value : `${value}Z`;
}

export class CatalogCheckpointConflict extends Error {
  constructor() {
    super('La página no corresponde al checkpoint persistido');
    this.name = 'CatalogCheckpointConflict';
  }
}

function progress(row: ProgressRow): SyncProgress {
  return {
    status: row.status ?? 'idle', nextStartIndex: count(row.next_start_index ?? '0'),
    totalResults: row.total_results === null ? null : count(row.total_results),
    storedRecords: count(row.stored_records), lastPageTimestamp: row.last_page_timestamp?.toISOString() ?? null,
  };
}

export class PostgresCatalog implements SyncStore {
  constructor(private readonly pool: Pool) {}

  async readSummary(remediatedIds: readonly string[] = []): Promise<SummarySnapshot> {
    try {
      // Estado y conteos comparten una instantánea; el catálogo permanece en PostgreSQL.
      const result = await this.pool.query<{
        status: SyncProgress['status'] | null;
        last_page_timestamp: Date | null;
        classification_status: string | null;
        severity: keyof PendingVulnerabilitySummary['bySeverity'] | null;
        remediated: boolean | null;
        count: string | null;
      }>(`
        WITH counts AS (
          SELECT classification_status, severity, id = ANY($1::text[]) AS remediated, count(*) AS count
          FROM app.cves
          GROUP BY classification_status, severity, id = ANY($1::text[])
        )
        SELECT state.status, state.last_page_timestamp, counts.*
        FROM (VALUES (1)) AS singleton(id)
        LEFT JOIN app.sync_state AS state USING (id)
        LEFT JOIN counts ON true
      `, [remediatedIds]);
      const summary: PendingVulnerabilitySummary = {
        total: 0, excludedRejected: 0, excludedRemediated: 0,
        bySeverity: { none: 0, low: 0, medium: 0, high: 0, critical: 0, unknown: 0 },
      };
      for (const row of result.rows) {
        if (row.count === null) continue;
        const amount = count(row.count);
        if (row.classification_status === 'rejected') summary.excludedRejected += amount;
        else if (row.remediated) summary.excludedRemediated += amount;
        else {
          summary.total += amount;
          summary.bySeverity[row.severity!] += amount;
        }
      }
      const state = result.rows[0]!;
      return {
        status: state.status ?? 'idle', lastPageTimestamp: state.last_page_timestamp?.toISOString() ?? null,
        summary,
      };
    } catch {
      throw new Error('No se pudo leer el resumen persistido');
    }
  }

  async getProgress(): Promise<SyncProgress> {
    try {
      // Una sola consulta lee datos y checkpoint desde la misma instantánea local.
      const result = await this.pool.query<ProgressRow>(`
        SELECT state.status, state.next_start_index, state.total_results, state.last_page_timestamp,
          (SELECT count(*) FROM app.cves) AS stored_records
        FROM (VALUES (1)) AS singleton(id)
        LEFT JOIN app.sync_state AS state USING (id)
      `);
      return progress(result.rows[0]!);
    } catch {
      throw new Error('No se pudo leer el progreso persistido');
    }
  }

  async setStatus(status: 'running' | 'paused' | 'failed', expectedIndex: number): Promise<SyncProgress> {
    try {
      const result = await this.pool.query<ProgressRow>(`
        WITH updated AS (
          INSERT INTO app.sync_state (id, status, next_start_index) VALUES (1, $1, $2)
          ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, updated_at = now()
          WHERE app.sync_state.next_start_index = EXCLUDED.next_start_index
            AND app.sync_state.status <> 'completed'
          RETURNING status, next_start_index, total_results, last_page_timestamp
        )
        SELECT updated.*, (SELECT count(*) FROM app.cves) AS stored_records FROM updated
      `, [status, expectedIndex]);
      if (result.rows[0] === undefined) throw new CatalogCheckpointConflict();
      return progress(result.rows[0]);
    } catch (error) {
      if (error instanceof CatalogCheckpointConflict) throw error;
      throw new Error('No se pudo guardar el estado de sincronización');
    }
  }

  async savePage(input: NvdPage): Promise<SyncProgress> {
    // Reutilizar la validación del cliente en la frontera de persistencia.
    const page = parseNvdPage({
      format: 'NVD_CVE', version: '2.0', startIndex: input.startIndex,
      resultsPerPage: input.resultsPerPage, totalResults: input.totalResults,
      timestamp: input.timestamp, vulnerabilities: input.cves.map((cve) => ({ cve })),
    });
    const records = page.cves.map((cve) => {
      const classification = classifyCve(cve);
      return {
        id: cve.id, published: utc(cve.published), last_modified: utc(cve.lastModified),
        vuln_status: cve.vulnStatus, classification_status: classification.status,
        severity: classification.severity, metric: classification.metric,
      };
    });
    let client: PoolClient | undefined;
    let destroy = false;
    try {
      client = await this.pool.connect();
      await client.query('BEGIN');
      await client.query(`
        INSERT INTO app.sync_state (id, status, next_start_index)
        VALUES (1, 'idle', 0) ON CONFLICT (id) DO NOTHING
      `);
      const checkpoint = await client.query<{ next_start_index: string }>(
        'SELECT next_start_index FROM app.sync_state WHERE id = 1 FOR UPDATE',
      );
      if (count(checkpoint.rows[0]!.next_start_index) !== page.startIndex) {
        throw new CatalogCheckpointConflict();
      }
      // Un único upsert por página; todos los valores viajan como parámetros.
      await client.query(`
        INSERT INTO app.cves (id, published, last_modified, vuln_status, classification_status, severity, metric)
        SELECT id, published, last_modified, vuln_status, classification_status, severity, metric
        FROM jsonb_to_recordset($1::jsonb) AS records (
          id text, published timestamptz, last_modified timestamptz, vuln_status text,
          classification_status text, severity text, metric jsonb
        )
        ON CONFLICT (id) DO UPDATE SET
          published = EXCLUDED.published, last_modified = EXCLUDED.last_modified,
          vuln_status = EXCLUDED.vuln_status, classification_status = EXCLUDED.classification_status,
          severity = EXCLUDED.severity, metric = EXCLUDED.metric
      `, [JSON.stringify(records)]);
      const result = await client.query<{ count: string }>('SELECT count(*) FROM app.cves');
      const storedRecords = count(result.rows[0]!.count);
      const next = page.startIndex + page.cves.length;
      const status = next < page.totalResults ? 'running'
        : storedRecords === page.totalResults ? 'completed' : 'failed';
      const nextStartIndex = status === 'failed' ? 0 : next;
      await client.query(`
        UPDATE app.sync_state SET status = $1, next_start_index = $2, total_results = $3,
          last_page_timestamp = $4, updated_at = now() WHERE id = 1
      `, [status, nextStartIndex, page.totalResults, utc(page.timestamp)]);
      const progress: SyncProgress = {
        status, nextStartIndex, totalResults: page.totalResults, storedRecords,
        lastPageTimestamp: new Date(utc(page.timestamp)).toISOString(),
      };
      await client.query('COMMIT');
      return progress;
    } catch (error) {
      if (client !== undefined) {
        try { await client.query('ROLLBACK'); } catch { destroy = true; }
      }
      if (error instanceof CatalogCheckpointConflict) throw error;
      throw new Error('No se pudo guardar la página y su checkpoint');
    } finally {
      client?.release(destroy);
    }
  }
}
