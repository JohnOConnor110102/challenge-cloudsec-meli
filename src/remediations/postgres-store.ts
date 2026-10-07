import type { Pool, PoolClient } from 'pg';
import { NvdError } from '../nvd/client.js';
import { isCveId } from '../nvd/validation.js';
import type { RegistrationContext, Remediation, RemediationRegistration, RemediationRepository } from './store.js';

interface RemediationRow {
  cve_id: string;
  registered_at: Date;
}

export class RemediationPersistenceError extends Error {
  constructor() {
    super('No se pudo consultar o guardar la remediación persistida');
    this.name = 'RemediationPersistenceError';
  }
}

function record(row: RemediationRow): Remediation {
  return { cveId: row.cve_id, registeredAt: row.registered_at.toISOString() };
}

function checkCancellation(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new NvdError('CANCELLED');
}

export class PostgresRemediationStore implements RemediationRepository {
  constructor(private readonly pool: Pool) {}

  async get(cveId: string): Promise<Remediation | undefined> {
    if (!isCveId(cveId)) throw new Error('El ID debe tener formato CVE-AAAA-NNNN');
    try {
      const result = await this.pool.query<RemediationRow>(
        'SELECT cve_id, registered_at FROM app.remediations WHERE cve_id = $1', [cveId],
      );
      return result.rows[0] === undefined ? undefined : record(result.rows[0]);
    } catch {
      throw new RemediationPersistenceError();
    }
  }

  // El servicio comprueba la existencia en NVD antes de una nueva alta.
  async register(cveId: string, context: RegistrationContext): Promise<RemediationRegistration> {
    if (!isCveId(cveId)) throw new Error('El ID debe tener formato CVE-AAAA-NNNN');
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(context.requestId)) {
      throw new Error('El requestId debe ser un UUID');
    }
    checkCancellation(context.signal);
    let client: PoolClient | undefined;
    let destroy = false;
    try {
      client = await this.pool.connect();
      checkCancellation(context.signal);
      await client.query('BEGIN');
      checkCancellation(context.signal);
      const inserted = await client.query<RemediationRow>(`
        INSERT INTO app.remediations (cve_id) VALUES ($1)
        ON CONFLICT (cve_id) DO NOTHING RETURNING cve_id, registered_at
      `, [cveId]);
      checkCancellation(context.signal);
      const created = inserted.rows[0] !== undefined;
      let row = inserted.rows[0];
      if (created) {
        await client.query(`
          INSERT INTO app.audit_events (event, cve_id, request_id)
          VALUES ('remediation_registered', $1, $2)
        `, [cveId, context.requestId]);
      } else {
        // Otra sentencia ve la fila confirmada por el escritor concurrente que hizo ganar el conflicto.
        const existing = await client.query<RemediationRow>(
          'SELECT cve_id, registered_at FROM app.remediations WHERE cve_id = $1', [cveId],
        );
        row = existing.rows[0];
      }
      if (row === undefined) throw new RemediationPersistenceError();
      const remediation = record(row);
      checkCancellation(context.signal);
      // Una vez enviado COMMIT puede confirmarse aunque el cliente se desconecte; repetir PUT es seguro.
      await client.query('COMMIT');
      return { created, remediation };
    } catch (error) {
      if (client !== undefined) {
        try { await client.query('ROLLBACK'); } catch { destroy = true; }
      }
      if (error instanceof NvdError) throw error;
      throw new RemediationPersistenceError();
    } finally {
      client?.release(destroy);
    }
  }
}
