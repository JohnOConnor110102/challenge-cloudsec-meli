import { randomUUID } from 'node:crypto';
import Fastify from 'fastify';
import type { Pool } from 'pg';
import type { Config } from './config.js';
import { openDatabase } from './db/pool.js';
import { NvdClient } from './nvd/client.js';
import { registerRemediationRoutes } from './remediations/routes.js';
import { RemediationService } from './remediations/service.js';
import { RemediationStore } from './remediations/store.js';
import { PostgresRemediationStore } from './remediations/postgres-store.js';
import { CveCatalog } from './sync/catalog.js';
import { InitialSync } from './sync/initial-sync.js';
import { PostgresCatalog } from './sync/postgres-catalog.js';
import { registerSyncRuntime } from './sync/runtime.js';
import { registerVulnerabilityRoutes } from './vulnerabilities/routes.js';

const healthSchema = {
  response: {
    200: {
      type: 'object',
      additionalProperties: false,
      required: ['status'],
      properties: { status: { type: 'string', const: 'ok' } },
    },
  },
};

export function buildApp(
  config: Config,
  client: Pick<NvdClient, 'getPage' | 'getCve'> = new NvdClient({ apiKey: config.nvdApiKey }),
  pool?: Pool,
) {
  const app = Fastify({
    logger: config.nodeEnv === 'test' ? false : {
      level: config.logLevel,
      redact: ['req.headers.authorization', 'req.headers.cookie', 'req.headers["x-api-key"]'],
      serializers: {
        req(request) {
          return { method: request.method, url: request.url.split('?')[0] ?? '/' };
        },
      },
    },
    genReqId: () => randomUUID(),
    requestIdHeader: false,
    trustProxy: false,
    bodyLimit: 64 * 1024,
    requestTimeout: 15_000,
  });

  const catalog = pool === undefined ? new CveCatalog() : new PostgresCatalog(pool);
  const sync = new InitialSync(client, catalog);
  app.decorate<CveCatalog | PostgresCatalog>('catalog', catalog);
  app.decorate('initialSync', sync);
  const remediations = pool === undefined ? new RemediationStore() : new PostgresRemediationStore(pool);
  app.decorate<RemediationStore | PostgresRemediationStore>('remediations', remediations);
  // onClose ejecuta los hooks en orden inverso: esperar la sincronización antes de cerrar el pool.
  if (pool !== undefined) app.addHook('onClose', async () => { await pool.end(); });
  registerSyncRuntime(app, sync);
  registerVulnerabilityRoutes(app, sync, async (pending) => {
    if (catalog instanceof PostgresCatalog) {
      return catalog.readSummary(pending);
    }
    return {
      status: sync.progress.status, lastPageTimestamp: sync.progress.lastPageTimestamp,
      summary: pending ? catalog.pendingSummary((id) => remediations instanceof RemediationStore && remediations.has(id))
        : { ...catalog.summary(), excludedRemediated: 0 },
    };
  });
  registerRemediationRoutes(app, new RemediationService(remediations, client));

  app.get('/health/live', { schema: healthSchema }, async () => ({ status: 'ok' }));
  app.get('/health/ready', {
    schema: { response: {
      ...healthSchema.response,
      503: {
        type: 'object', additionalProperties: false, required: ['status'],
        properties: { status: { type: 'string', const: 'not_ready' } },
      },
    } },
  }, async (_request, reply) => {
    if (sync.progress.status !== 'completed') {
      return reply.code(503).send({ status: 'not_ready' });
    }
    if (pool !== undefined) {
      try {
        const result = await pool.query<{ status: string }>('SELECT status FROM app.sync_state WHERE id = 1');
        if (result.rows[0]?.status !== 'completed') return reply.code(503).send({ status: 'not_ready' });
      } catch {
        return reply.code(503).send({ status: 'not_ready' });
      }
    }
    return { status: 'ok' };
  });

  return app;
}

// El servidor usa persistencia; buildApp sin pool queda para pruebas aisladas en memoria.
export async function buildPersistentApp(
  config: Config,
  client?: Pick<NvdClient, 'getPage' | 'getCve'>,
) {
  let app: ReturnType<typeof buildApp> | undefined;
  const pool = await openDatabase(config.database, () => {
    app?.log.warn({ event: 'database_idle_connection_failed' }, 'Se perdió una conexión inactiva de PostgreSQL');
  });
  try {
    app = buildApp(config, client, pool);
    return app;
  } catch (error) {
    await pool.end().catch(() => {});
    throw error;
  }
}
