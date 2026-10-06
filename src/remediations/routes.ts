import type { FastifyInstance } from 'fastify';
import { NvdError } from '../nvd/client.js';
import { RemediationError } from './service.js';
import type { RemediationService } from './service.js';

const remediationSchema = {
  type: 'object', additionalProperties: false, required: ['cveId', 'registeredAt'],
  properties: { cveId: { type: 'string' }, registeredAt: { type: 'string' } },
};
const errorSchema = {
  type: 'object', additionalProperties: false, required: ['error'],
  properties: { error: { type: 'string' } },
};

export function registerRemediationRoutes(app: FastifyInstance, service: RemediationService): void {
  const shutdown = new AbortController();
  app.addHook('preClose', async () => { shutdown.abort(); });

  app.put<{ Params: { cveId: string } }>('/api/v1/remediations/:cveId', {
    bodyLimit: 1_024,
    schema: {
      params: {
        type: 'object', additionalProperties: false, required: ['cveId'],
        properties: { cveId: { type: 'string', maxLength: 100, pattern: '^CVE-\\d{4}-\\d{4,}$' } },
      },
      response: {
        200: remediationSchema, 201: remediationSchema,
        400: errorSchema, 404: errorSchema, 409: errorSchema, 413: errorSchema,
        415: errorSchema, 500: errorSchema, 502: errorSchema, 503: errorSchema, 504: errorSchema,
      },
    },
    onRequest: async (_request, reply) => { reply.header('Cache-Control', 'no-store'); },
    preValidation: async (request, reply) => {
      if (request.body !== undefined) return reply.code(400).send({ error: 'invalid_request' });
    },
    errorHandler(error, request, reply) {
      if (error instanceof RemediationError) {
        const failures = {
          INVALID_CVE_ID: { status: 400, error: 'invalid_cve_id' },
          CVE_NOT_FOUND: { status: 404, error: 'cve_not_found' },
          CVE_REJECTED: { status: 409, error: 'cve_rejected' },
        };
        const failure = failures[error.code];
        return reply.code(failure.status).send({ error: failure.error });
      }
      if (error instanceof NvdError) {
        request.log.warn({ event: 'remediation_provider_failed', providerCode: error.code }, 'Falló la validación NVD');
        if (error.code === 'TIMEOUT') return reply.code(504).send({ error: 'nvd_timeout' });
        const unavailable = error.code === 'CANCELLED'
          || (error.code === 'HTTP' && (error.status === 429 || (error.status !== undefined && error.status >= 500)));
        return reply.code(unavailable ? 503 : 502).send({ error: unavailable ? 'service_unavailable' : 'nvd_unavailable' });
      }
      if (error.statusCode === 413) return reply.code(413).send({ error: 'payload_too_large' });
      if (error.statusCode === 415) return reply.code(415).send({ error: 'unsupported_media_type' });
      if (error.statusCode === 400) return reply.code(400).send({ error: 'invalid_request' });
      request.log.error({ event: 'remediation_registration_failed' }, 'Falló el registro de remediación');
      return reply.code(500).send({ error: 'internal_error' });
    },
  }, async (request, reply) => {
    const controller = new AbortController();
    const signal = AbortSignal.any([controller.signal, shutdown.signal]);
    const cancel = () => { controller.abort(); };
    reply.raw.once('close', cancel);
    let timedOut = false;
    const deadline = setTimeout(() => { timedOut = true; controller.abort(); }, 30_000);
    deadline.unref();
    try {
      const result = await service.register(request.params.cveId, { signal });
      if (result.created) {
        request.log.info({
          event: 'remediation_registered', requestId: request.id,
          cveId: result.remediation.cveId, registeredAt: result.remediation.registeredAt,
        }, 'Remediación registrada');
        reply.header('Location', `/api/v1/remediations/${result.remediation.cveId}`);
      }
      return reply.code(result.created ? 201 : 200).send(result.remediation);
    } catch (error) {
      if (timedOut) throw new NvdError('TIMEOUT');
      throw error;
    } finally {
      clearTimeout(deadline);
      reply.raw.removeListener('close', cancel);
    }
  });
}
