import { describe, expect, it, afterEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { SignClient } from '../src/client/signer.js';
import { SignatureVerifier } from '../src/server/verifier.js';
import { MemoryNonceStore } from '../src/server/nonce-store/memory.js';
import { hmacAuthPlugin } from '../src/adapters/fastify.js';

const SECRET = 'k';
const CLIENT_ID = 'svc_a';

interface Running {
  app: FastifyInstance;
  url: string;
  store: MemoryNonceStore;
  close: () => Promise<void>;
}

async function startApp(): Promise<Running> {
  const store = new MemoryNonceStore({ sweepIntervalMs: 0 });
  const verifier = new SignatureVerifier({
    getSecret: async (id) => (id === CLIENT_ID ? SECRET : null),
    nonceStore: store,
  });

  const app = Fastify();
  await app.register(
    hmacAuthPlugin as unknown as Parameters<typeof app.register>[0],
    { verifier },
  );
  app.post('/echo', async (req) => ({
    ok: true,
    clientId: req.hmac?.clientId,
    body: req.body,
  }));
  app.get('/health', async (req) => ({
    ok: true,
    clientId: req.hmac?.clientId,
  }));

  const url = await app.listen({ port: 0, host: '127.0.0.1' });

  return {
    app,
    url,
    store,
    close: async () => {
      await app.close();
      store.close();
    },
  };
}

describe('Fastify adapter', () => {
  const running: Running[] = [];
  afterEach(async () => {
    while (running.length) await running.pop()?.close();
  });

  it('accepts a properly signed POST', async () => {
    const app = await startApp();
    running.push(app);

    const signer = new SignClient({ clientId: CLIENT_ID, secret: SECRET });
    const body = JSON.stringify({ a: 1 });
    const { headerName, headerValue } = signer.sign({
      method: 'POST',
      path: '/echo',
      body,
    });
    const res = await fetch(`${app.url}/echo`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        [headerName]: headerValue,
      },
      body,
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as { clientId: string; body: unknown };
    expect(json.clientId).toBe(CLIENT_ID);
    expect(json.body).toEqual({ a: 1 });
  });

  it('rejects an unsigned request with 401 MISSING_HEADER', async () => {
    const app = await startApp();
    running.push(app);

    const res = await fetch(`${app.url}/health`);
    expect(res.status).toBe(401);
    const json = (await res.json()) as { code: string };
    expect(json.code).toBe('MISSING_HEADER');
  });

  it('rejects a tampered body with 401 INVALID_SIGNATURE', async () => {
    const app = await startApp();
    running.push(app);

    const signer = new SignClient({ clientId: CLIENT_ID, secret: SECRET });
    const body = JSON.stringify({ a: 1 });
    const { headerName, headerValue } = signer.sign({
      method: 'POST',
      path: '/echo',
      body,
    });
    const res = await fetch(`${app.url}/echo`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        [headerName]: headerValue,
      },
      body: JSON.stringify({ a: 2 }),
    });
    expect(res.status).toBe(401);
    const json = (await res.json()) as { code: string };
    expect(json.code).toBe('INVALID_SIGNATURE');
  });
});
