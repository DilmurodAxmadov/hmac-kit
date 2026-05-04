import { describe, expect, it, afterEach } from 'vitest';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { SignClient } from '../src/client/signer.js';
import { SignatureVerifier } from '../src/server/verifier.js';
import { MemoryNonceStore } from '../src/server/nonce-store/memory.js';
import {
  createHmacMiddleware,
  rawBodySaver,
} from '../src/adapters/express.js';

const SECRET = 'k';
const CLIENT_ID = 'svc_a';

interface Running {
  url: string;
  close: () => Promise<void>;
  store: MemoryNonceStore;
}

async function startApp(): Promise<Running> {
  const store = new MemoryNonceStore({ sweepIntervalMs: 0 });
  const verifier = new SignatureVerifier({
    getSecret: async (id) => (id === CLIENT_ID ? SECRET : null),
    nonceStore: store,
  });

  const app = express();
  app.use(express.json({ verify: rawBodySaver }));
  app.use(createHmacMiddleware(verifier));
  app.post('/echo', (req, res) => {
    res.json({ ok: true, clientId: req.hmac?.clientId, body: req.body });
  });
  app.get('/health', (req, res) => {
    res.json({ ok: true, clientId: req.hmac?.clientId });
  });

  const server = app.listen(0);
  await new Promise<void>((r) => server.once('listening', r));
  const port = (server.address() as AddressInfo).port;

  return {
    url: `http://127.0.0.1:${port}`,
    store,
    close: () =>
      new Promise<void>((r) => {
        server.close(() => {
          store.close();
          r();
        });
      }),
  };
}

describe('Express adapter', () => {
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

  it('accepts a signed GET (no body)', async () => {
    const app = await startApp();
    running.push(app);

    const signer = new SignClient({ clientId: CLIENT_ID, secret: SECRET });
    const { headerName, headerValue } = signer.sign({
      method: 'GET',
      path: '/health',
    });
    const res = await fetch(`${app.url}/health`, {
      headers: { [headerName]: headerValue },
    });
    expect(res.status).toBe(200);
  });

  it('rejects an unsigned request with 401', async () => {
    const app = await startApp();
    running.push(app);

    const res = await fetch(`${app.url}/health`);
    expect(res.status).toBe(401);
    const json = (await res.json()) as { code: string };
    expect(json.code).toBe('MISSING_HEADER');
  });

  it('rejects a tampered body with 401', async () => {
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
      body: JSON.stringify({ a: 2 }), // tampered
    });
    expect(res.status).toBe(401);
    const json = (await res.json()) as { code: string };
    expect(json.code).toBe('INVALID_SIGNATURE');
  });

  it('rejects replay with 401 REPLAY_ATTACK', async () => {
    const app = await startApp();
    running.push(app);

    const signer = new SignClient({ clientId: CLIENT_ID, secret: SECRET });
    const { headerName, headerValue } = signer.sign({
      method: 'GET',
      path: '/health',
    });
    const r1 = await fetch(`${app.url}/health`, {
      headers: { [headerName]: headerValue },
    });
    expect(r1.status).toBe(200);
    const r2 = await fetch(`${app.url}/health`, {
      headers: { [headerName]: headerValue },
    });
    expect(r2.status).toBe(401);
    const json = (await r2.json()) as { code: string };
    expect(json.code).toBe('REPLAY_ATTACK');
  });
});
