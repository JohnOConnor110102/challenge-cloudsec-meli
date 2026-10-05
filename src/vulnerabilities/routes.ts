import type { FastifyInstance } from 'fastify';
import type { CveCatalog } from '../sync/catalog.js';
import type { InitialSync } from '../sync/initial-sync.js';

const countSchema = { type: 'integer', minimum: 0 };
const summarySchema = {
  response: {
    200: {
      type: 'object', additionalProperties: false,
      required: ['total', 'excludedRejected', 'bySeverity', 'meta'],
      properties: {
        total: countSchema,
        excludedRejected: countSchema,
        bySeverity: {
          type: 'object', additionalProperties: false,
          required: ['none', 'low', 'medium', 'high', 'critical', 'unknown'],
          properties: {
            none: countSchema, low: countSchema, medium: countSchema,
            high: countSchema, critical: countSchema, unknown: countSchema,
          },
        },
        meta: {
          type: 'object', additionalProperties: false,
          required: ['syncStatus', 'lastPageTimestamp'],
          properties: {
            syncStatus: { type: 'string', const: 'completed' },
            lastPageTimestamp: { type: ['string', 'null'] },
          },
        },
      },
    },
    503: {
      type: 'object', additionalProperties: false,
      required: ['error', 'syncStatus'],
      properties: {
        error: { type: 'string', const: 'catalog_not_ready' },
        syncStatus: { type: 'string', enum: ['idle', 'running', 'paused', 'failed'] },
      },
    },
  },
};

export function registerVulnerabilityRoutes(
  app: FastifyInstance,
  catalog: CveCatalog,
  sync: InitialSync,
): void {
  app.get('/api/v1/vulnerabilities/summary', { schema: summarySchema }, async (_request, reply) => {
    reply.header('Cache-Control', 'no-store');
    const progress = sync.progress;
    if (progress.status !== 'completed') {
      return reply.code(503).send({ error: 'catalog_not_ready', syncStatus: progress.status });
    }
    return {
      ...catalog.summary(),
      meta: { syncStatus: progress.status, lastPageTimestamp: progress.lastPageTimestamp },
    };
  });
}
