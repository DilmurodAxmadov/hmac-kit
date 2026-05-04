import { describe, expect, it, afterEach } from 'vitest';
import { SignClient } from '../src/client/signer.js';
import { SignatureVerifier } from '../src/server/verifier.js';
import { MemoryNonceStore } from '../src/server/nonce-store/memory.js';
import {
  HmacAuthGuard,
  createHmacAuthGuard,
  HMAC_VERIFIER,
} from '../src/adapters/nestjs.js';
import {
  HmacAuthError,
  MissingHeaderError,
  ReplayAttackError,
} from '../src/shared/errors.js';

const SECRET = 'k';
const CLIENT_ID = 'svc_a';

function fakeContext(req: unknown): {
  switchToHttp(): { getRequest<T>(): T; getResponse<T>(): T };
} {
  return {
    switchToHttp: () => ({
      getRequest: <T>() => req as T,
      getResponse: <T>() => ({}) as T,
    }),
  };
}

describe('NestJS adapter', () => {
  const stores: MemoryNonceStore[] = [];
  afterEach(() => {
    while (stores.length) stores.pop()?.close();
  });

  function makeGuard(): HmacAuthGuard {
    const store = new MemoryNonceStore({ sweepIntervalMs: 0 });
    stores.push(store);
    const verifier = new SignatureVerifier({
      getSecret: async (id) => (id === CLIENT_ID ? SECRET : null),
      nonceStore: store,
    });
    return new HmacAuthGuard(verifier);
  }

  it('exports HMAC_VERIFIER as a unique symbol', () => {
    expect(typeof HMAC_VERIFIER).toBe('symbol');
  });

  it('throws if constructed without a verifier', () => {
    expect(
      () => new HmacAuthGuard(undefined as unknown as SignatureVerifier),
    ).toThrow(/verifier/i);
  });

  it('factory builds a working guard instance', () => {
    const store = new MemoryNonceStore({ sweepIntervalMs: 0 });
    stores.push(store);
    const verifier = new SignatureVerifier({
      getSecret: async () => SECRET,
      nonceStore: store,
    });
    const guard = createHmacAuthGuard(verifier);
    expect(guard).toBeInstanceOf(HmacAuthGuard);
  });

  it('canActivate returns true for a valid request', async () => {
    const guard = makeGuard();
    const signer = new SignClient({ clientId: CLIENT_ID, secret: SECRET });
    const body = JSON.stringify({ a: 1 });
    const { headerName, headerValue } = signer.sign({
      method: 'POST',
      path: '/api/x',
      body,
    });
    const req: Record<string, unknown> = {
      method: 'POST',
      url: '/api/x',
      headers: { [headerName.toLowerCase()]: headerValue },
      rawBody: Buffer.from(body, 'utf8'),
    };
    const ok = await guard.canActivate(fakeContext(req));
    expect(ok).toBe(true);
    expect((req.hmac as { clientId: string }).clientId).toBe(CLIENT_ID);
  });

  it('throws MissingHeaderError when header is absent', async () => {
    const guard = makeGuard();
    const req = { method: 'GET', url: '/', headers: {} };
    await expect(guard.canActivate(fakeContext(req))).rejects.toBeInstanceOf(
      MissingHeaderError,
    );
  });

  it('throws ReplayAttackError on duplicate nonce', async () => {
    const guard = makeGuard();
    const signer = new SignClient({ clientId: CLIENT_ID, secret: SECRET });
    const { headerName, headerValue } = signer.sign({
      method: 'GET',
      path: '/x',
    });
    const buildReq = (): Record<string, unknown> => ({
      method: 'GET',
      url: '/x',
      headers: { [headerName.toLowerCase()]: headerValue },
    });
    await guard.canActivate(fakeContext(buildReq()));
    await expect(
      guard.canActivate(fakeContext(buildReq())),
    ).rejects.toBeInstanceOf(ReplayAttackError);
  });

  it('all thrown errors are HmacAuthError', async () => {
    const guard = makeGuard();
    try {
      await guard.canActivate(
        fakeContext({ method: 'GET', url: '/', headers: {} }),
      );
    } catch (err) {
      expect(err).toBeInstanceOf(HmacAuthError);
    }
  });
});
