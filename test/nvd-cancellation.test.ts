import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { test } from 'node:test';
import { inspect } from 'node:util';
import { NvdClient } from '../src/nvd/client.js';

function emptyResponse() {
  return Response.json({
    format: 'NVD_CVE', version: '2.0', timestamp: '2026-10-05T12:00:00.000',
    startIndex: 0, resultsPerPage: 0, totalResults: 0, vulnerabilities: [],
  });
}

test('una señal ya cancelada no consulta NVD ni bloquea la cola posterior', async () => {
  let calls = 0;
  const client = new NvdClient({}, { fetch: async () => { calls++; return emptyResponse(); } });
  const signal = AbortSignal.abort(new Error('private-cancellation-reason'));
  await assert.rejects(client.getPage({ signal }), (error: unknown) => {
    assert.equal(inspect(error).includes('private-cancellation-reason'), false);
    assert.match(inspect(error), /CANCELLED/);
    return true;
  });
  await assert.rejects(client.getCve('CVE-2024-1234', { signal }), { code: 'CANCELLED' });
  assert.equal(calls, 0);
  await client.getPage();
  assert.equal(calls, 1);
});

test('cancelar una consulta activa aborta fetch y no reintenta ni devuelve TIMEOUT', async () => {
  const started = Promise.withResolvers<AbortSignal>();
  let calls = 0;
  const client = new NvdClient({}, {
    fetch: async (_input, init) => {
      calls++;
      const signal = init!.signal!;
      started.resolve(signal);
      return new Promise<Response>((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(new Error('private-fetch-detail')), { once: true });
      });
    },
  });
  const controller = new AbortController();
  const task = client.getPage({ signal: controller.signal });
  const fetchSignal = await started.promise;
  controller.abort();
  await assert.rejects(task, { code: 'CANCELLED' });
  assert.equal(fetchSignal.aborted, true);
  assert.equal(calls, 1);
});

test('cancela una solicitud en cola sin esperar la consulta anterior ni enviarla después', async () => {
  const response = Promise.withResolvers<Response>();
  const started = Promise.withResolvers<void>();
  let calls = 0;
  const client = new NvdClient({}, {
    now: () => 0, sleep: async () => {},
    fetch: async () => {
      calls++;
      started.resolve();
      return calls === 1 ? response.promise : emptyResponse();
    },
  });
  const first = client.getPage();
  await started.promise;
  const controller = new AbortController();
  const queued = client.getPage({ signal: controller.signal });
  controller.abort();
  await assert.rejects(queued, { code: 'CANCELLED' });
  assert.equal(calls, 1);
  response.resolve(emptyResponse());
  await first;
  await client.getPage();
  assert.equal(calls, 2);
});

test('la cancelación interrumpe esperas por rate limit y backoff', async () => {
  for (const retry of [false, true]) {
    const waiting = Promise.withResolvers<void>();
    let calls = 0;
    const client = new NvdClient({}, {
      now: () => 0,
      sleep: async (ms, signal) => {
        waiting.resolve();
        await sleep(ms, undefined, { signal });
      },
      fetch: async () => {
        calls++;
        return retry ? new Response(null, { status: 503 }) : emptyResponse();
      },
    });
    if (!retry) await client.getPage();
    const controller = new AbortController();
    const task = client.getPage({ signal: controller.signal });
    await waiting.promise;
    controller.abort();
    await assert.rejects(task, { code: 'CANCELLED' });
    assert.equal(calls, 1);
  }
});

test('la señal también cancela la lectura del cuerpo de la respuesta', async () => {
  const started = Promise.withResolvers<void>();
  const client = new NvdClient({}, {
    fetch: async (_input, init) => new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{'));
        init!.signal!.addEventListener('abort', () => controller.error(new Error('aborted')), { once: true });
        started.resolve();
      },
    }), { headers: { 'content-type': 'application/json' } }),
  });
  const controller = new AbortController();
  const task = client.getPage({ signal: controller.signal });
  await started.promise;
  controller.abort();
  await assert.rejects(task, { code: 'CANCELLED' });
});
