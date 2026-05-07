import { describe, expect, it } from 'vitest';
import { EdgeSignClient } from '../src/client/signer-web.js';
import { EdgeSignatureVerifier } from '../src/server/verifier-web.js';
import { MemoryNonceStore } from '../src/server/nonce-store/memory.js';
import {
  hashBodyWeb,
  computeSignatureWeb,
  safeTimingEqualWeb,
  encodeAuthHeaderWeb,
  decodeAuthHeaderWeb,
  generateNonceWeb,
} from '../src/shared/crypto-web.js';
import {
  InvalidSignatureError,
  MissingHeaderError,
  ReplayAttackError,
} from '../src/shared/errors.js';

const CLIENT_ID = 'edge_svc';
const SECRET = 'edge-secret-key';

describe('crypto-web utilities', () => {
  it('hashBodyWeb returns 64-char hex for sha256', async () => {
    const h = await hashBodyWeb('hello', 'sha256');
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it('hashBodyWeb returns 128-char hex for sha512', async () => {
    const h = await hashBodyWeb('hello', 'sha512');
    expect(h).toMatch(/^[0-9a-f]{128}$/);
  });

  it('hashBodyWeb treats undefined and empty string identically', async () => {
    expect(await hashBodyWeb(undefined)).toEqual(await hashBodyWeb(''));
  });

  it('hashBodyWeb accepts Uint8Array', async () => {
    const fromString = await hashBodyWeb('abc');
    const fromBytes = await hashBodyWeb(new TextEncoder().encode('abc'));
    expect(fromString).toEqual(fromBytes);
  });

  it('computeSignatureWeb is deterministic', async () => {
    const a = await computeSignatureWeb({ algorithm: 'sha256', secret: 's', stringToSign: 'x' });
    const b = await computeSignatureWeb({ algorithm: 'sha256', secret: 's', stringToSign: 'x' });
    expect(a).toEqual(b);
  });

  it('computeSignatureWeb sha512 produces 128-char hex', async () => {
    const sig = await computeSignatureWeb({ algorithm: 'sha512', secret: 's', stringToSign: 'x' });
    expect(sig).toMatch(/^[0-9a-f]{128}$/);
  });

  it('safeTimingEqualWeb returns true for equal strings', async () => {
    expect(await safeTimingEqualWeb('abcdef', 'abcdef')).toBe(true);
  });

  it('safeTimingEqualWeb returns false for different strings', async () => {
    expect(await safeTimingEqualWeb('aaaaaa', 'bbbbbb')).toBe(false);
  });

  it('safeTimingEqualWeb returns false on length mismatch', async () => {
    expect(await safeTimingEqualWeb('abc', 'abcd')).toBe(false);
  });

  it('encodeAuthHeaderWeb / decodeAuthHeaderWeb round-trip', () => {
    const payload = { 'x-api-key': 'k', 'x-nonce': 'n', 'x-timestamp': '1', 'x-signature': 'abc' };
    const encoded = encodeAuthHeaderWeb(payload);
    expect(decodeAuthHeaderWeb(encoded)).toEqual(payload);
  });

  it('generateNonceWeb returns a UUID', () => {
    expect(generateNonceWeb()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });
});

describe('EdgeSignClient', () => {
  it('signs a request and produces a valid payload', async () => {
    const signer = new EdgeSignClient({ clientId: CLIENT_ID, secret: SECRET });
    const { payload } = await signer.sign({ method: 'POST', path: '/api', body: '{}' });
    expect(payload['x-api-key']).toBe(CLIENT_ID);
    expect(payload['x-signature']).toMatch(/^[0-9a-f]{64}$/);
  });

  it('produces 128-char signature with sha512', async () => {
    const signer = new EdgeSignClient({ clientId: CLIENT_ID, secret: SECRET, signatureAlgorithm: 'sha512' });
    const { payload } = await signer.sign({ method: 'GET', path: '/' });
    expect(payload['x-signature']).toMatch(/^[0-9a-f]{128}$/);
  });

  it('toString does not leak the secret', () => {
    const signer = new EdgeSignClient({ clientId: CLIENT_ID, secret: 'TOPSECRET' });
    expect(String(signer)).not.toContain('TOPSECRET');
    expect(JSON.stringify(signer)).not.toContain('TOPSECRET');
  });
});

describe('EdgeSignatureVerifier round-trip', () => {
  it('verifies a request signed by EdgeSignClient', async () => {
    const store = new MemoryNonceStore({ sweepIntervalMs: 0 });
    const verifier = new EdgeSignatureVerifier({
      getSecret: async id => (id === CLIENT_ID ? SECRET : null),
      nonceStore: store,
    });
    const signer = new EdgeSignClient({ clientId: CLIENT_ID, secret: SECRET });
    const body = '{"amount":100}';
    const { headerValue } = await signer.sign({ method: 'POST', path: '/pay', body });
    const result = await verifier.verify({ authHeader: headerValue, method: 'POST', path: '/pay', rawBody: body });
    expect(result.clientId).toBe(CLIENT_ID);
    store.close();
  });

  it('works with sha512', async () => {
    const store = new MemoryNonceStore({ sweepIntervalMs: 0 });
    const verifier = new EdgeSignatureVerifier({
      getSecret: async id => (id === CLIENT_ID ? SECRET : null),
      nonceStore: store,
      signatureAlgorithm: 'sha512',
    });
    const signer = new EdgeSignClient({ clientId: CLIENT_ID, secret: SECRET, signatureAlgorithm: 'sha512' });
    const { headerValue } = await signer.sign({ method: 'GET', path: '/health' });
    const result = await verifier.verify({ authHeader: headerValue, method: 'GET', path: '/health' });
    expect(result.clientId).toBe(CLIENT_ID);
    store.close();
  });

  it('throws MissingHeaderError when header absent', async () => {
    const verifier = new EdgeSignatureVerifier({ getSecret: async () => SECRET });
    await expect(
      verifier.verify({ authHeader: undefined, method: 'GET', path: '/' }),
    ).rejects.toBeInstanceOf(MissingHeaderError);
  });

  it('throws InvalidSignatureError on wrong secret', async () => {
    const store = new MemoryNonceStore({ sweepIntervalMs: 0 });
    const verifier = new EdgeSignatureVerifier({
      getSecret: async id => (id === CLIENT_ID ? SECRET : null),
      nonceStore: store,
    });
    const signer = new EdgeSignClient({ clientId: CLIENT_ID, secret: 'WRONG' });
    const { headerValue } = await signer.sign({ method: 'GET', path: '/' });
    await expect(
      verifier.verify({ authHeader: headerValue, method: 'GET', path: '/' }),
    ).rejects.toBeInstanceOf(InvalidSignatureError);
    store.close();
  });

  it('throws ReplayAttackError on duplicate nonce', async () => {
    const store = new MemoryNonceStore({ sweepIntervalMs: 0 });
    const verifier = new EdgeSignatureVerifier({
      getSecret: async id => (id === CLIENT_ID ? SECRET : null),
      nonceStore: store,
    });
    const signer = new EdgeSignClient({ clientId: CLIENT_ID, secret: SECRET });
    const { headerValue } = await signer.sign({ method: 'GET', path: '/' });
    await verifier.verify({ authHeader: headerValue, method: 'GET', path: '/' });
    await expect(
      verifier.verify({ authHeader: headerValue, method: 'GET', path: '/' }),
    ).rejects.toBeInstanceOf(ReplayAttackError);
    store.close();
  });
});
