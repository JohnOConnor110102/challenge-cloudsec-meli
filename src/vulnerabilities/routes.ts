import type { FastifyInstance } from 'fastify';
import type { InitialSync } from '../sync/initial-sync.js';
import type { ReadSummary } from './reader.js';

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
      oneOf: [
        {
          type: 'object', additionalProperties: false, required: ['error', 'syncStatus'],
          properties: {
            error: { type: 'string', const: 'catalog_not_ready' },
            syncStatus: { type: 'string', enum: ['idle', 'running', 'paused', 'failed'] },
          },
        },
        {
          type: 'object', additionalProperties: false, required: ['error'],
          properties: { error: { type: 'string', const: 'storage_unavailable' } },
        },
      ],
    },
  },
};

const pendingSummarySchema = {
  response: {
    ...summarySchema.response,
    200: {
      ...summarySchema.response[200],
      required: [...summarySchema.response[200].required, 'excludedRemediated'],
      properties: { ...summarySchema.response[200].properties, excludedRemediated: countSchema },
    },
  },
};

export function registerVulnerabilityRoutes(
  app: FastifyInstance,
  sync: InitialSync,
  readSummary: ReadSummary,
): void {
  for (const route of [
    { path: '/api/v1/vulnerabilities/summary', schema: summarySchema, pending: false },
    {
      path: '/api/v1/vulnerabilities/pending/summary', schema: pendingSummarySchema,
      pending: true,
    },
  ]) {
    app.get(route.path, { schema: route.schema }, async (request, reply) => {
      reply.header('Cache-Control', 'no-store');
      const progress = sync.progress;
      if (progress.status !== 'completed') {
        return reply.code(503).send({ error: 'catalog_not_ready', syncStatus: progress.status });
      }
      try {
        const snapshot = await readSummary(route.pending);
        if (snapshot.status !== 'completed') {
          return reply.code(503).send({ error: 'catalog_not_ready', syncStatus: snapshot.status });
        }
        return {
          ...snapshot.summary,
          meta: { syncStatus: snapshot.status, lastPageTimestamp: snapshot.lastPageTimestamp },
        };
      } catch {
        request.log.error({ event: 'vulnerability_summary_failed' }, 'No se pudo consultar el resumen');
        return reply.code(503).send({ error: 'storage_unavailable' });
      }
    });
  }
}
