import { randomUUID } from 'node:crypto';
import Fastify from 'fastify';
import type { Config } from './config.js';
import { NvdClient } from './nvd/client.js';
import { CveCatalog } from './sync/catalog.js';
import { InitialSync } from './sync/initial-sync.js';
import { registerSyncRuntime } from './sync/runtime.js';

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
  client: Pick<NvdClient, 'getPage'> = new NvdClient({ apiKey: config.nvdApiKey }),
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

  const catalog = new CveCatalog();
  const sync = new InitialSync(client, catalog);
  app.decorate('catalog', catalog);
  app.decorate('initialSync', sync);
  registerSyncRuntime(app, sync);

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
    return { status: 'ok' };
  });

  return app;
}
