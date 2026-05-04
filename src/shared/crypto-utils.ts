import {
  createHash,
  createHmac,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import type { SignatureAlgorithm } from './types.js';

/**
 * Cryptographic primitives for the HMAC protocol.
 *
 * SECURITY NOTES (read before changing anything here):
 *
 *   1. We use Node's built-in `crypto` module exclusively — no third-party
 *      crypto code. This means we inherit Node's well-audited OpenSSL
 *      bindings and avoid known foot-guns of pure-JS implementations.
 *
 *   2. `safeTimingEqual` MUST be used instead of `===` or `Buffer.equals`
 *      for any signature comparison. `crypto.timingSafeEqual` runs in
 *      constant time relative to buffer length; naive comparison leaks
 *      the position of the first differing byte via response timing.
 *
 *   3. `timingSafeEqual` ITSELF throws synchronously if the two buffers
 *      have different lengths. That throw is observable from the outside
 *      (different timing than a "false" return) and could be used as a
 *      length oracle. We pre-check length and return `false` early — the
 *      length check is fine to leak because the expected length is a
 *      public constant per algorithm.
 *
 *   4. Body bytes used for hashing MUST be the raw bytes received on the
 *      wire. Re-stringifying parsed JSON will silently change bytes
 *      (key order, whitespace, escaping) and break the protocol. This is
 *      the responsibility of the *caller* but is documented heavily in
 *      types and adapters.
 */

/** Compute SHA-256 hash of body, hex-encoded. Used inside string-to-sign. */
export function hashBody(body: string | Buffer | undefined): string {
  // Empty body must produce a STABLE hash — empty string. Never `undefined`.
  const data = body ?? '';
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Build the canonical string-to-sign. Order, separator (`\n`), and
 * trailing-newline behavior are part of the WIRE protocol — DO NOT change.
 *
 * Format:
 *   <method-uppercase>\n
 *   <path>\n
 *   <unix-seconds>\n
 *   <nonce>\n
 *   <sha256-hex(body)>
 */
export function buildStringToSign(input: {
  method: string;
  path: string;
  timestamp: number | string;
  nonce: string;
  bodyHashHex: string;
}): string {
  return [
    input.method.toUpperCase(),
    input.path,
    String(input.timestamp),
    input.nonce,
    input.bodyHashHex,
  ].join('\n');
}

/** HMAC-SHA256 (or SHA-512) of the string-to-sign, hex-encoded. */
export function computeSignature(args: {
  algorithm: SignatureAlgorithm;
  secret: string;
  stringToSign: string;
}): string {
  return createHmac(args.algorithm, args.secret)
    .update(args.stringToSign)
    .digest('hex');
}

/**
 * Constant-time hex-string compare. Safe against timing oracles.
 *
 * Returns `false` cleanly on length mismatch (cannot leak signature by
 * crashing). Buffers are zeroed implicitly by GC; we don't bother
 * explicitly wiping since hex strings retain the same data anyway.
 */
export function safeTimingEqual(aHex: string, bHex: string): boolean {
  if (typeof aHex !== 'string' || typeof bHex !== 'string') return false;
  if (aHex.length !== bHex.length) return false;
  if (aHex.length === 0) return false;
  // `Buffer.from(hex, 'hex')` silently truncates on invalid hex, which would
  // leak via length difference. Validate first.
  if (!isHex(aHex) || !isHex(bHex)) return false;

  const aBuf = Buffer.from(aHex, 'hex');
  const bBuf = Buffer.from(bHex, 'hex');
  if (aBuf.length !== bBuf.length) return false;

  return timingSafeEqual(aBuf, bBuf);
}

const HEX_RE = /^[0-9a-fA-F]+$/;
export function isHex(s: string): boolean {
  return HEX_RE.test(s) && s.length % 2 === 0;
}

/**
 * Encode the inner auth payload object → JSON → base64. This is the value
 * that goes into the single transport header.
 *
 * Note: base64 here is *masking only*, not encryption. It conveniently
 * packs the whole payload into one HTTP header without escape headaches.
 */
export function encodeAuthHeader(payload: object): string {
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
}

/**
 * Inverse of `encodeAuthHeader`. Throws on bad base64 or bad JSON — caller
 * is expected to translate to `InvalidFormatError`.
 */
export function decodeAuthHeader(raw: string): unknown {
  const json = Buffer.from(raw, 'base64').toString('utf8');
  // Defense: `Buffer.from(x, 'base64')` is permissive — it strips invalid
  // characters silently. So we sanity-check the round-trip.
  // (Strict-mode would compute `Buffer.from(json,'utf8').toString('base64')`
  // and compare — but URL-safe vs standard base64 makes this fragile.
  // Instead we lean on JSON.parse to fail loudly on garbage input.)
  return JSON.parse(json);
}

/** Generate a nonce. Uses Node's crypto-strong UUID v4 by default. */
export function generateNonce(): string {
  return randomUUID();
}

/** Current Unix timestamp in seconds. */
export function nowUnixSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
