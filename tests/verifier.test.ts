import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { SignClient } from '../src/client/signer.js';
import { SignatureVerifier } from '../src/server/verifier.js';
import { MemoryNonceStore } from '../src/server/nonce-store/memory.js';
import {
  ExpiredRequestError,
  HmacAuthError,
  InvalidFormatError,
  InvalidSignatureError,
  MissingHeaderError,
  ReplayAttackError,
  UnknownClientError,
} from '../src/shared/errors.js';

const SECRET = 'super-secret-shared-key';
const CLIENT_ID = 'svc_a';

function makeVerifier(opts?: { window?: number }): {
  verifier: SignatureVerifier;
  store: MemoryNonceStore;
} {
  const store = new MemoryNonceStore({ sweepIntervalMs: 0 });
  const verifier = new SignatureVerifier({
    getSecret: async (id) => (id === CLIENT_ID ? SECRET : null),
    nonceStore: store,
    timestampWindowSeconds: opts?.window ?? 300,
  });
  return { verifier, store };
}

describe('SignatureVerifier round-trip', () => {
  let store: MemoryNonceStore;
  let verifier: SignatureVerifier;
  beforeEach(() => {
    ({ verifier, store } = makeVerifier());
  });
  afterEach(() => store.close());

  it('accepts a freshly signed request', async () => {
    const signer = new SignClient({ clientId: CLIENT_ID, secret: SECRET });
    const body = '{"amount":100}';
    const { headerValue } = signer.sign({
      method: 'POST',
      path: '/api/payments',
      body,
    });
    const result = await verifier.verify({
      authHeader: headerValue,
      method: 'POST',
      path: '/api/payments',
      rawBody: body,
    });
    expect(result.clientId).toBe(CLIENT_ID);
    expect(typeof result.timestamp).toBe('number');
    expect(typeof result.nonce).toBe('string');
  });

  it('accepts requests with no body (GET)', async () => {
    const signer = new SignClient({ clientId: CLIENT_ID, secret: SECRET });
    const { headerValue } = signer.sign({ method: 'GET', path: '/health' });
    const result = await verifier.verify({
      authHeader: headerValue,
      method: 'GET',
      path: '/health',
    });
    expect(result.clientId).toBe(CLIENT_ID);
  });

  it('accepts a Buffer rawBody when client signed the matching string', async () => {
    const signer = new SignClient({ clientId: CLIENT_ID, secret: SECRET });
    const body = '{"a":1}';
    const { headerValue } = signer.sign({
      method: 'POST',
      path: '/x',
      body,
    });
    const result = await verifier.verify({
      authHeader: headerValue,
      method: 'POST',
      path: '/x',
      rawBody: Buffer.from(body, 'utf8'),
    });
    expect(result.clientId).toBe(CLIENT_ID);
  });
});

describe('SignatureVerifier rejection paths', () => {
  let store: MemoryNonceStore;
  let verifier: SignatureVerifier;
  beforeEach(() => {
    ({ verifier, store } = makeVerifier());
  });
  afterEach(() => store.close());

  it('throws MissingHeaderError when authHeader is undefined', async () => {
    await expect(
      verifier.verify({
        authHeader: undefined,
        method: 'GET',
        path: '/',
      }),
    ).rejects.toBeInstanceOf(MissingHeaderError);
  });

  it('throws MissingHeaderError when authHeader is null', async () => {
    await expect(
      verifier.verify({ authHeader: null, method: 'GET', path: '/' }),
    ).rejects.toBeInstanceOf(MissingHeaderError);
  });

  it('throws InvalidFormatError on bad base64/json', async () => {
    await expect(
      verifier.verify({
        authHeader: '!!!not-valid-base64-json!!!',
        method: 'GET',
        path: '/',
      }),
    ).rejects.toBeInstanceOf(InvalidFormatError);
  });

  it('throws InvalidFormatError when payload is missing fields', async () => {
    const incomplete = Buffer.from(
      JSON.stringify({ 'x-api-key': 'a' }),
      'utf8',
    ).toString('base64');
    await expect(
      verifier.verify({
        authHeader: incomplete,
        method: 'GET',
        path: '/',
      }),
    ).rejects.toBeInstanceOf(InvalidFormatError);
  });

  it('throws ExpiredRequestError when timestamp is way in the past', async () => {
    const signer = new SignClient({ clientId: CLIENT_ID, secret: SECRET });
    const { headerValue } = signer.sign({
      method: 'GET',
      path: '/',
      timestamp: 1, // 1970
    });
    await expect(
      verifier.verify({ authHeader: headerValue, method: 'GET', path: '/' }),
    ).rejects.toBeInstanceOf(ExpiredRequestError);
  });

  it('throws ExpiredRequestError when timestamp is far in the future', async () => {
    const signer = new SignClient({ clientId: CLIENT_ID, secret: SECRET });
    const future = Math.floor(Date.now() / 1000) + 10_000;
    const { headerValue } = signer.sign({
      method: 'GET',
      path: '/',
      timestamp: future,
    });
    await expect(
      verifier.verify({ authHeader: headerValue, method: 'GET', path: '/' }),
    ).rejects.toBeInstanceOf(ExpiredRequestError);
  });

  it('throws ReplayAttackError on duplicate nonce', async () => {
    const signer = new SignClient({ clientId: CLIENT_ID, secret: SECRET });
    const { headerValue } = signer.sign({ method: 'GET', path: '/' });
    await verifier.verify({
      authHeader: headerValue,
      method: 'GET',
      path: '/',
    });
    await expect(
      verifier.verify({
        authHeader: headerValue,
        method: 'GET',
        path: '/',
      }),
    ).rejects.toBeInstanceOf(ReplayAttackError);
  });

  it('throws UnknownClientError when secret resolver returns null', async () => {
    const signer = new SignClient({
      clientId: 'unknown_svc',
      secret: SECRET,
    });
    const { headerValue } = signer.sign({ method: 'GET', path: '/' });
    await expect(
      verifier.verify({ authHeader: headerValue, method: 'GET', path: '/' }),
    ).rejects.toBeInstanceOf(UnknownClientError);
  });

  it('throws InvalidSignatureError when signature is wrong', async () => {
    const signer = new SignClient({
      clientId: CLIENT_ID,
      secret: 'WRONG-SECRET',
    });
    const { headerValue } = signer.sign({ method: 'GET', path: '/' });
    await expect(
      verifier.verify({ authHeader: headerValue, method: 'GET', path: '/' }),
    ).rejects.toBeInstanceOf(InvalidSignatureError);
  });

  it('throws InvalidSignatureError when body is tampered', async () => {
    const signer = new SignClient({ clientId: CLIENT_ID, secret: SECRET });
    const { headerValue } = signer.sign({
      method: 'POST',
      path: '/x',
      body: '{"a":1}',
    });
    await expect(
      verifier.verify({
        authHeader: headerValue,
        method: 'POST',
        path: '/x',
        rawBody: '{"a":2}', // changed
      }),
    ).rejects.toBeInstanceOf(InvalidSignatureError);
  });

  it('throws InvalidSignatureError when path is tampered', async () => {
    const signer = new SignClient({ clientId: CLIENT_ID, secret: SECRET });
    const { headerValue } = signer.sign({ method: 'GET', path: '/safe' });
    await expect(
      verifier.verify({
        authHeader: headerValue,
        method: 'GET',
        path: '/admin',
      }),
    ).rejects.toBeInstanceOf(InvalidSignatureError);
  });

  it('throws InvalidSignatureError when method is tampered', async () => {
    const signer = new SignClient({ clientId: CLIENT_ID, secret: SECRET });
    const { headerValue } = signer.sign({ method: 'GET', path: '/x' });
    await expect(
      verifier.verify({
        authHeader: headerValue,
        method: 'DELETE',
        path: '/x',
      }),
    ).rejects.toBeInstanceOf(InvalidSignatureError);
  });

  it('all rejection errors are HmacAuthError instances', async () => {
    const cases = [
      { authHeader: undefined as undefined | string },
      { authHeader: 'bad' },
    ];
    for (const c of cases) {
      try {
        await verifier.verify({
          authHeader: c.authHeader,
          method: 'GET',
          path: '/',
        });
      } catch (err) {
        expect(err).toBeInstanceOf(HmacAuthError);
      }
    }
  });
});

describe('SignatureVerifier — header normalization', () => {
  let store: MemoryNonceStore;
  let verifier: SignatureVerifier;
  beforeEach(() => {
    ({ verifier, store } = makeVerifier());
  });
  afterEach(() => store.close());

  it('handles array header values (Express multi-header)', async () => {
    const signer = new SignClient({ clientId: CLIENT_ID, secret: SECRET });
    const { headerValue } = signer.sign({ method: 'GET', path: '/' });
    const result = await verifier.verify({
      authHeader: [headerValue],
      method: 'GET',
      path: '/',
    });
    expect(result.clientId).toBe(CLIENT_ID);
  });
});
