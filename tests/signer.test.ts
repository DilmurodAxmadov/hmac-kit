import { describe, expect, it } from 'vitest';
import { SignClient } from '../src/client/signer.js';
import { decodeAuthHeader } from '../src/shared/crypto-utils.js';

describe('SignClient', () => {
  it('throws if clientId is missing', () => {
    expect(
      () => new SignClient({ clientId: '', secret: 's' }),
    ).toThrow(/clientId/);
  });

  it('throws if secret is missing', () => {
    expect(
      () => new SignClient({ clientId: 'c', secret: '' }),
    ).toThrow(/secret/);
  });

  it('produces a payload with all four fields', () => {
    const s = new SignClient({ clientId: 'svc_a', secret: 'shh' });
    const { payload } = s.sign({
      method: 'POST',
      path: '/x',
      body: '{"a":1}',
    });
    expect(payload['x-api-key']).toBe('svc_a');
    expect(payload['x-timestamp']).toMatch(/^\d+$/);
    expect(payload['x-nonce']).toMatch(/[0-9a-f-]{36}/);
    expect(payload['x-signature']).toMatch(/^[0-9a-f]{64}$/);
  });

  it('headerValue decodes back to the same payload', () => {
    const s = new SignClient({ clientId: 'c', secret: 'k' });
    const { headerValue, payload } = s.sign({ method: 'GET', path: '/' });
    expect(decodeAuthHeader(headerValue)).toEqual(payload);
  });

  it('uses a different signature for different bodies', () => {
    const s = new SignClient({ clientId: 'c', secret: 'k' });
    const a = s.sign({
      method: 'POST',
      path: '/x',
      body: 'a',
      timestamp: 1000,
      nonce: 'n',
    });
    const b = s.sign({
      method: 'POST',
      path: '/x',
      body: 'b',
      timestamp: 1000,
      nonce: 'n',
    });
    expect(a.payload['x-signature']).not.toEqual(b.payload['x-signature']);
  });

  it('honors custom headerName', () => {
    const s = new SignClient({
      clientId: 'c',
      secret: 'k',
      headerName: 'X-Custom',
    });
    expect(s.headerName).toBe('X-Custom');
    expect(s.sign({ method: 'GET', path: '/' }).headerName).toBe('X-Custom');
  });

  it('toString does not leak the secret', () => {
    const s = new SignClient({ clientId: 'c', secret: 'TOPSECRET' });
    expect(String(s)).not.toContain('TOPSECRET');
    expect(JSON.stringify(s)).not.toContain('TOPSECRET');
  });

  it('respects timestamp + nonce overrides for deterministic signing', () => {
    const s = new SignClient({ clientId: 'c', secret: 'k' });
    const a = s.sign({
      method: 'GET',
      path: '/',
      timestamp: 1234,
      nonce: 'fixed',
    });
    const b = s.sign({
      method: 'GET',
      path: '/',
      timestamp: 1234,
      nonce: 'fixed',
    });
    expect(a.payload).toEqual(b.payload);
  });
});
