import assert from 'node:assert/strict';
import { test } from 'node:test';
import { inspect } from 'node:util';
import { loadConfig } from '../src/config.js';
import { NvdClient, NvdError } from '../src/nvd/client.js';

const ID = 'CVE-2024-1234';
const DATE = '2026-10-05T12:00:00.000';

function cve(id = ID) {
  return { id, published: DATE, lastModified: DATE, vulnStatus: 'Analyzed', metrics: {} };
}

function page(cves = [cve()], startIndex = 0, totalResults = cves.length) {
  return {
    format: 'NVD_CVE', version: '2.0', timestamp: DATE,
    startIndex, resultsPerPage: cves.length, totalResults,
    vulnerabilities: cves.map((record) => ({ cve: record })),
  };
}

function harness(
  handler: (url: URL, init: RequestInit) => Response | Promise<Response>,
  options: ConstructorParameters<typeof NvdClient>[0] = {},
) {
  let time = 0;
  const calls: { url: URL; init: RequestInit; time: number }[] = [];
  const waits: number[] = [];
  const client = new NvdClient(options, {
    fetch: async (input, init = {}) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      calls.push({ url, init, time });
      return handler(url, init);
    },
    sleep: async (ms) => { waits.push(ms); time += ms; },
    now: () => time,
  });
  return { client, calls, waits, advance: (ms: number) => { time += ms; } };
}

test('consulta un CVE y envía la key solo por encabezado, sin seguir redirects', async () => {
  const key = 'test-key';
  const { client, calls } = harness(() => Response.json(page()), { apiKey: key });
  assert.deepEqual(await client.getCve(ID), cve());
  const call = calls[0]!;
  assert.equal(call.url.origin, 'https://services.nvd.nist.gov');
  assert.equal(call.url.pathname, '/rest/json/cves/2.0');
  assert.equal(call.url.searchParams.get('cveId'), ID);
  assert.equal(call.url.href.includes(key), false);
  assert.equal(new Headers(call.init.headers).get('apiKey'), key);
  assert.equal(call.init.redirect, 'error');
  assert.equal(inspect(client, { showHidden: true }).includes(key), false);
});

test('solo un HTTP 200 válido sin resultados significa CVE no encontrado', async () => {
  const empty = harness(() => Response.json(page([])));
  assert.equal(await empty.client.getCve(ID), null);
  assert.equal(new Headers(empty.calls[0]!.init.headers).has('apiKey'), false);

  for (const status of [400, 401, 403, 404]) {
    const { client, calls } = harness(() => new Response('provider-private-detail', {
      status, headers: { message: 'provider-private-detail' },
    }));
    await assert.rejects(client.getCve(ID), (error: unknown) => {
      assert.ok(error instanceof NvdError);
      assert.equal(error.code, 'HTTP');
      assert.equal(error.status, status);
      assert.equal(inspect(error).includes('provider-private-detail'), false);
      return true;
    });
    assert.equal(calls.length, 1);
  }
});

test('rechaza entradas inválidas antes de consultar NVD', async () => {
  const { client, calls } = harness(() => Response.json(page()));
  for (const id of ['cve-2024-1234', 'CVE-24-1234', 'CVE-2024-123', ID + '\n', ID + '&x=1']) {
    await assert.rejects(client.getCve(id), /formato inválido/);
  }
  for (const resultsPerPage of [0, 2_001, 1.5, NaN]) {
    await assert.rejects(client.getPage({ resultsPerPage }), /paginación/);
  }
  for (const startIndex of [-1, 0.5, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    await assert.rejects(client.getPage({ startIndex }), /paginación/);
  }
  for (const apiKey of ['', ' ', 'secret\r\nheader', 'x'.repeat(257)]) {
    assert.throws(() => new NvdClient({ apiKey }), { message: 'NVD_API_KEY tiene un valor inválido' });
    assert.throws(() => loadConfig({ NVD_API_KEY: apiKey }), { message: 'NVD_API_KEY tiene un valor inválido' });
  }
  assert.equal(loadConfig({}).nvdApiKey, undefined);
  assert.equal(loadConfig({ NVD_API_KEY: 'test-key' }).nvdApiKey, 'test-key');
  assert.throws(() => new NvdClient({ timeoutMs: 0 }), /timeout/);
  assert.equal(calls.length, 0);
});

test('pagina con el número de registros recibidos y termina sin acumular el catálogo', async () => {
  const { client, calls, waits } = harness((url) => {
    const start = Number(url.searchParams.get('startIndex'));
    return Response.json(start === 0
      ? { ...page([cve(), cve('CVE-2024-1235')], 0, 3), resultsPerPage: 5 }
      : page([cve('CVE-2024-1236')], 2, 3));
  });
  const ids: string[] = [];
  for await (const result of client.pages({ resultsPerPage: 5 })) {
    ids.push(...result.cves.map((record) => record.id));
  }
  assert.deepEqual(ids, [ID, 'CVE-2024-1235', 'CVE-2024-1236']);
  assert.deepEqual(calls.map((call) => call.url.searchParams.get('startIndex')), ['0', '2']);
  assert.ok(calls.every((call) => call.url.searchParams.get('resultsPerPage') === '5'));
  assert.deepEqual(waits, [6_100]);
});

test('permite un catálogo vacío y detener la iteración sin pedir otra página', async () => {
  const empty = harness(() => Response.json(page([])));
  let pages = 0;
  for await (const result of empty.client.pages()) {
    assert.deepEqual(result.cves, []);
    pages++;
  }
  assert.equal(pages, 1);
  assert.equal(empty.calls.length, 1);

  const partial = harness(() => Response.json(page([cve()], 0, 100)));
  for await (const result of partial.client.pages()) {
    assert.equal(result.totalResults, 100);
    break;
  }
  assert.equal(partial.calls.length, 1);
});

test('serializa llamadas concurrentes y una solicitud fallida no bloquea la cola', async () => {
  let active = 0;
  let maxActive = 0;
  const { client, calls } = harness(async (url) => {
    active++;
    maxActive = Math.max(maxActive, active);
    await Promise.resolve();
    active--;
    return url.searchParams.get('cveId') === ID
      ? new Response(null, { status: 403 })
      : Response.json(page([cve('CVE-2024-1235')]));
  }, { apiKey: 'test-key' });
  const results = await Promise.allSettled([client.getCve(ID), client.getCve('CVE-2024-1235')]);
  assert.equal(results[0]!.status, 'rejected');
  assert.equal(results[1]!.status, 'fulfilled');
  assert.equal(maxActive, 1);
  assert.deepEqual(calls.map((call) => call.time), [0, 6_100]);
});

test('rechaza JSON inválido, HTML, metadatos inconsistentes y CVE inesperados sin reintentar', async () => {
  const responses = [
    () => new Response('{', { headers: { 'content-type': 'application/json' } }),
    () => new Response('<html>error</html>'),
    () => new Response(null, { status: 204 }),
    () => Response.json(page(), { status: 201 }),
    () => Response.json({ ...page(), version: '1.0' }),
    () => Response.json({ ...page(), startIndex: -1 }),
    () => Response.json({ ...page(), timestamp: 'not-a-date' }),
    () => Response.json({ ...page(), vulnerabilities: [{ cve: { ...cve(), metrics: [] } }] }),
    () => Response.json({ ...page(), vulnerabilities: [{ cve: { ...cve(), id: 'invalid' } }] }),
    () => Response.json(page([], 0, 1)),
    () => Response.json(page([cve(), cve()], 0, 2)),
    () => Response.json(page([cve('CVE-2024-9999')])),
  ];
  for (const response of responses) {
    const { client, calls } = harness(response);
    await assert.rejects(client.getCve(ID), { code: 'INVALID_RESPONSE' });
    assert.equal(calls.length, 1);
  }
  const wrongOffset = harness(() => Response.json(page([cve()], 0, 3)));
  await assert.rejects(wrongOffset.client.getPage({ startIndex: 1 }), { code: 'INVALID_RESPONSE' });
});

test('tolera campos nuevos y conserva métricas múltiples, ausentes y estado Rejected', async () => {
  const metrics = { cvssMetricV31: [{ source: 'example', cvssData: { baseScore: 9.8 } }], futureMetric: [] };
  const extra = harness(() => Response.json({
    ...page(), extra: true,
    vulnerabilities: [{ cve: { ...cve(), extra: true, metrics } }],
  }));
  assert.deepEqual((await extra.client.getCve(ID))?.metrics, metrics);
  const rejected = harness(() => Response.json({
    ...page(), vulnerabilities: [{ cve: { ...cve(), vulnStatus: 'Rejected', metrics: undefined } }],
  }));
  assert.equal((await rejected.client.getCve(ID))?.vulnStatus, 'Rejected');
});

test('reintenta 429 y 5xx con Retry-After y backoff, hasta tres intentos', async () => {
  let attempt = 0;
  const { client, calls, waits } = harness(() => {
    attempt++;
    if (attempt === 1) return new Response(null, { status: 429, headers: { 'retry-after': '20' } });
    if (attempt === 2) return new Response(null, { status: 503 });
    return Response.json(page());
  });
  assert.equal((await client.getCve(ID))?.id, ID);
  assert.deepEqual(calls.map((call) => call.time), [0, 20_000, 32_200]);
  assert.deepEqual(waits, [20_000, 12_200]);

  const unavailable = harness(() => new Response(null, { status: 503 }));
  await assert.rejects(unavailable.client.getCve(ID), { code: 'HTTP', status: 503 });
  assert.equal(unavailable.calls.length, 3);
});

test('respeta Retry-After HTTP-date y no reintenta antes de una espera mayor al límite', async (t) => {
  const epoch = Date.UTC(2026, 9, 5, 12);
  t.mock.method(Date, 'now', () => epoch);
  let attempt = 0;
  const dated = harness(() => ++attempt === 1
    ? new Response(null, { status: 429, headers: { 'retry-after': new Date(epoch + 20_000).toUTCString() } })
    : Response.json(page()));
  await dated.client.getCve(ID);
  assert.deepEqual(dated.waits, [20_000]);

  const longWait = harness(() => new Response(null, { status: 429, headers: { 'retry-after': '120' } }));
  await assert.rejects(longWait.client.getCve(ID), { code: 'HTTP', status: 429 });
  assert.equal(longWait.calls.length, 1);
  assert.deepEqual(longWait.waits, []);

  // El cooldown también protege llamadas posteriores de la misma instancia.
  await assert.rejects(longWait.client.getCve(ID), { code: 'HTTP', status: 429 });
  assert.equal(longWait.calls.length, 1);
  longWait.advance(120_000);
  await assert.rejects(longWait.client.getCve(ID), { code: 'HTTP', status: 429 });
  assert.equal(longWait.calls.length, 2);
});

test('acota errores de red y timeouts sin exponer el error original', async () => {
  const network = harness(() => { throw new Error('private-network-detail'); });
  await assert.rejects(network.client.getCve(ID), (error: unknown) => {
    assert.ok(error instanceof NvdError);
    assert.equal(error.code, 'NETWORK');
    assert.equal(inspect(error).includes('private-network-detail'), false);
    return true;
  });
  assert.equal(network.calls.length, 3);

  const timeout = harness((_url, init) => new Promise<Response>((_resolve, reject) => {
    init.signal!.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
  }), { timeoutMs: 5 });
  await assert.rejects(timeout.client.getCve(ID), { code: 'TIMEOUT' });
  assert.equal(timeout.calls.length, 3);
});

test('el timeout cubre la lectura del cuerpo y el límite de bytes cancela respuestas excesivas', async () => {
  const slowBody = harness((_url, init) => new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('{'));
      init.signal!.addEventListener('abort', () => controller.error(new Error('aborted')), { once: true });
    },
  }), { headers: { 'content-type': 'application/json' } }), { timeoutMs: 5 });
  await assert.rejects(slowBody.client.getCve(ID), { code: 'TIMEOUT' });
  assert.equal(slowBody.calls.length, 3);

  let cancelled = false;
  const large = harness(() => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(32 * 1024 * 1024 + 1)); },
    cancel() { cancelled = true; },
  }), { headers: { 'content-type': 'application/json' } }));
  await assert.rejects(large.client.getCve(ID), { code: 'INVALID_RESPONSE' });
  assert.equal(large.calls.length, 1);
  assert.equal(cancelled, true);
});
