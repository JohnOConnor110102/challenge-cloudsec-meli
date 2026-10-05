import { randomUUID } from 'node:crypto';
import Fastify from 'fastify';
import type { Config } from './config.js';

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

export function buildApp(config: Config) {
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

  app.get('/health/live', { schema: healthSchema }, async () => ({ status: 'ok' }));
  app.get('/health/ready', { schema: healthSchema }, async () => ({ status: 'ok' }));

  return app;
}
