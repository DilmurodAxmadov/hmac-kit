import { describe, expect, it } from 'vitest';
import {
  buildStringToSign,
  computeSignature,
  decodeAuthHeader,
  encodeAuthHeader,
  generateNonce,
  hashBody,
  isHex,
  nowUnixSeconds,
  safeTimingEqual,
} from '../src/shared/crypto-utils.js';

describe('hashBody', () => {
  it('produces a stable hash for the same input', () => {
    expect(hashBody('hello')).toEqual(hashBody('hello'));
  });

  it('treats undefined and empty string identically', () => {
    expect(hashBody(undefined)).toEqual(hashBody(''));
  });

  it('produces different hashes for different inputs', () => {
    expect(hashBody('a')).not.toEqual(hashBody('b'));
  });

  it('accepts a Buffer', () => {
    const fromString = hashBody('abc');
    const fromBuffer = hashBody(Buffer.from('abc', 'utf8'));
    expect(fromString).toEqual(fromBuffer);
  });

  it('returns 64-char hex (sha256)', () => {
    const h = hashBody('x');
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('buildStringToSign', () => {
  it('joins fields with newlines in canonical order', () => {
    const s = buildStringToSign({
      method: 'post',
      path: '/api/x',
      timestamp: 123,
      nonce: 'n',
      bodyHashHex: 'h',
    });
    expect(s).toBe('POST\n/api/x\n123\nn\nh');
  });

  it('uppercases method', () => {
    const s = buildStringToSign({
      method: 'get',
      path: '/',
      timestamp: 1,
      nonce: 'n',
      bodyHashHex: 'h',
    });
    expect(s.startsWith('GET\n')).toBe(true);
  });
});

describe('computeSignature', () => {
  it('is deterministic for fixed inputs', () => {
    const a = computeSignature({
      algorithm: 'sha256',
      secret: 's',
      stringToSign: 'x',
    });
    const b = computeSignature({
      algorithm: 'sha256',
      secret: 's',
      stringToSign: 'x',
    });
    expect(a).toEqual(b);
  });

  it('changes when secret changes', () => {
    const a = computeSignature({
      algorithm: 'sha256',
      secret: 's1',
      stringToSign: 'x',
    });
    const b = computeSignature({
      algorithm: 'sha256',
      secret: 's2',
      stringToSign: 'x',
    });
    expect(a).not.toEqual(b);
  });

  it('produces different output for sha256 vs sha512', () => {
    const a = computeSignature({
      algorithm: 'sha256',
      secret: 's',
      stringToSign: 'x',
    });
    const b = computeSignature({
      algorithm: 'sha512',
      secret: 's',
      stringToSign: 'x',
    });
    expect(a).not.toEqual(b);
    expect(a.length).toBe(64);
    expect(b.length).toBe(128);
  });
});

describe('safeTimingEqual', () => {
  it('returns true for identical hex', () => {
    expect(safeTimingEqual('abcd', 'abcd')).toBe(true);
  });

  it('returns false for differing hex of equal length', () => {
    expect(safeTimingEqual('abcd', 'abce')).toBe(false);
  });

  it('returns false for different-length inputs', () => {
    expect(safeTimingEqual('abcd', 'abcdef')).toBe(false);
  });

  it('returns false for empty strings', () => {
    expect(safeTimingEqual('', '')).toBe(false);
  });

  it('returns false for non-hex input', () => {
    expect(safeTimingEqual('zzzz', 'abcd')).toBe(false);
  });

  it('returns false for non-string input', () => {
    expect(safeTimingEqual(null as unknown as string, 'abcd')).toBe(false);
  });
});

describe('isHex', () => {
  it('accepts even-length hex', () => {
    expect(isHex('deadbeef')).toBe(true);
  });

  it('rejects odd-length hex', () => {
    expect(isHex('abc')).toBe(false);
  });

  it('rejects non-hex chars', () => {
    expect(isHex('abcg')).toBe(false);
  });
});

describe('encode/decodeAuthHeader', () => {
  it('round-trips a payload', () => {
    const original = { 'x-api-key': 'k', 'x-nonce': 'n' };
    const encoded = encodeAuthHeader(original);
    const decoded = decodeAuthHeader(encoded);
    expect(decoded).toEqual(original);
  });

  it('throws on bad base64/json', () => {
    expect(() => decodeAuthHeader('!!!not-json!!!')).toThrow();
  });
});

describe('generateNonce', () => {
  it('returns a UUID-shaped string', () => {
    const n = generateNonce();
    expect(n).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  it('returns unique values', () => {
    const a = generateNonce();
    const b = generateNonce();
    expect(a).not.toEqual(b);
  });
});

describe('nowUnixSeconds', () => {
  it('returns a finite integer', () => {
    const t = nowUnixSeconds();
    expect(Number.isInteger(t)).toBe(true);
    expect(t).toBeGreaterThan(0);
  });
});
