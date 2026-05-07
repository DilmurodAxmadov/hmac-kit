import { describe, expect, it, vi } from 'vitest';
import { SignedHttpClient } from '../src/client/http-client.js';
import { SignatureVerifier } from '../src/server/verifier.js';
import { MemoryNonceStore } from '../src/server/nonce-store/memory.js';

const BASE_URL = 'https://api.example.com';
const CLIENT_ID = 'svc_test';
const SECRET = 'test-secret-key';

function makeOkFetch(status = 200): typeof globalThis.fetch {
  return vi.fn().mockResolvedValue(new Response('ok', { status }));
}

function makeSequentialFetch(...statuses: number[]): typeof globalThis.fetch {
  let call = 0;
  return vi.fn().mockImplementation(() => {
    const status = statuses[call] ?? statuses[statuses.length - 1];
    call++;
    return Promise.resolve(new Response('body', { status }));
  });
}

describe('SignedHttpClient — basic', () => {
  it('sends a signed GET request', async () => {
    const fetchMock = makeOkFetch();
    const client = new SignedHttpClient({ clientId: CLIENT_ID, secret: SECRET, baseUrl: BASE_URL, fetch: fetchMock });
    const res = await client.get('/health');
    expect(res.status).toBe(200);
    const [url, init] = (fetchMock as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://api.example.com/health');
    expect(init.headers).toHaveProperty('X-Signature');
  });

  it('signs each request independently (different nonce)', async () => {
    const calls: string[] = [];
    const fetchMock = vi.fn().mockImplementation((_url: string, init: RequestInit) => {
      calls.push((init.headers as Record<string, string>)['X-Signature']);
      return Promise.resolve(new Response('ok'));
    });
    const client = new SignedHttpClient({ clientId: CLIENT_ID, secret: SECRET, baseUrl: BASE_URL, fetch: fetchMock });
    await client.get('/a');
    await client.get('/a');
    expect(calls[0]).not.toEqual(calls[1]);
  });
});

describe('SignedHttpClient — retry', () => {
  it('does not retry by default on 500', async () => {
    const fetchMock = makeOkFetch(500);
    const client = new SignedHttpClient({ clientId: CLIENT_ID, secret: SECRET, baseUrl: BASE_URL, fetch: fetchMock });
    const res = await client.get('/');
    expect(res.status).toBe(500);
    expect((fetchMock as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(1);
  });

  it('retries on 500 when attempts > 1 and eventually succeeds', async () => {
    const fetchMock = makeSequentialFetch(500, 200);
    const client = new SignedHttpClient({
      clientId: CLIENT_ID,
      secret: SECRET,
      baseUrl: BASE_URL,
      fetch: fetchMock,
      retry: { attempts: 2, delayMs: 0 },
    });
    const res = await client.get('/');
    expect(res.status).toBe(200);
    expect((fetchMock as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(2);
  });

  it('re-signs on each retry (fresh nonce)', async () => {
    const signatures: string[] = [];
    let call = 0;
    const fetchMock = vi.fn().mockImplementation((_url: string, init: RequestInit) => {
      signatures.push((init.headers as Record<string, string>)['X-Signature']);
      const status = call++ === 0 ? 503 : 200;
      return Promise.resolve(new Response('body', { status }));
    });
    const client = new SignedHttpClient({
      clientId: CLIENT_ID,
      secret: SECRET,
      baseUrl: BASE_URL,
      fetch: fetchMock,
      retry: { attempts: 2, delayMs: 0 },
    });
    await client.get('/');
    expect(signatures[0]).not.toEqual(signatures[1]);
  });

  it('returns last response after exhausting retries', async () => {
    const fetchMock = makeSequentialFetch(502, 503, 500);
    const client = new SignedHttpClient({
      clientId: CLIENT_ID,
      secret: SECRET,
      baseUrl: BASE_URL,
      fetch: fetchMock,
      retry: { attempts: 3, delayMs: 0 },
    });
    const res = await client.get('/');
    expect(res.status).toBe(500);
    expect((fetchMock as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(3);
  });

  it('does not retry on 4xx (except 429)', async () => {
    const fetchMock = makeSequentialFetch(404, 200);
    const client = new SignedHttpClient({
      clientId: CLIENT_ID,
      secret: SECRET,
      baseUrl: BASE_URL,
      fetch: fetchMock,
      retry: { attempts: 2, delayMs: 0 },
    });
    const res = await client.get('/');
    expect(res.status).toBe(404);
    expect((fetchMock as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(1);
  });

  it('retries on 429', async () => {
    const fetchMock = makeSequentialFetch(429, 200);
    const client = new SignedHttpClient({
      clientId: CLIENT_ID,
      secret: SECRET,
      baseUrl: BASE_URL,
      fetch: fetchMock,
      retry: { attempts: 2, delayMs: 0 },
    });
    const res = await client.get('/');
    expect(res.status).toBe(200);
  });
});

describe('SignedHttpClient — end-to-end with verifier', () => {
  it('server accepts request sent by SignedHttpClient', async () => {
    const store = new MemoryNonceStore({ sweepIntervalMs: 0 });
    const verifier = new SignatureVerifier({
      getSecret: async id => (id === CLIENT_ID ? SECRET : null),
      nonceStore: store,
    });

    let capturedHeaders: Record<string, string> = {};
    let capturedBody = '';
    const fetchMock = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      capturedHeaders = init.headers as Record<string, string>;
      capturedBody = init.body as string;
      return new Response('ok');
    });

    const client = new SignedHttpClient({ clientId: CLIENT_ID, secret: SECRET, baseUrl: BASE_URL, fetch: fetchMock });
    await client.post('/api/orders', { item: 'book' });

    const result = await verifier.verify({
      authHeader: capturedHeaders['X-Signature'],
      method: 'POST',
      path: '/api/orders',
      rawBody: capturedBody,
    });
    expect(result.clientId).toBe(CLIENT_ID);
    store.close();
  });
});
