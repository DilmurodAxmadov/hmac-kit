/**
 * Web Crypto API equivalents of crypto-utils.ts.
 *
 * Uses only `globalThis.crypto` (Web Crypto) — no `node:crypto`.
 * Works in: Cloudflare Workers, Deno, Vercel Edge, Node.js 18+.
 *
 * All hashing / signing functions are async because Web Crypto is async.
 */

import type { SignatureAlgorithm } from './types.js';

function toHashName(algorithm: SignatureAlgorithm): string {
  return algorithm === 'sha512' ? 'SHA-512' : 'SHA-256';
}

function bufToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), b =>
    b.toString(16).padStart(2, '0'),
  ).join('');
}

export async function hashBodyWeb(
  body: string | Uint8Array | undefined,
  algorithm: SignatureAlgorithm = 'sha256',
): Promise<string> {
  const data = body ?? '';
  const bytes =
    typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hash = await globalThis.crypto.subtle.digest(toHashName(algorithm), bytes);
  return bufToHex(hash);
}

export async function computeSignatureWeb(args: {
  algorithm: SignatureAlgorithm;
  secret: string;
  stringToSign: string;
}): Promise<string> {
  const keyData = new TextEncoder().encode(args.secret);
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: toHashName(args.algorithm) },
    false,
    ['sign'],
  );
  const mac = await globalThis.crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(args.stringToSign),
  );
  return bufToHex(mac);
}

/**
 * Constant-time string comparison using Web Crypto.
 * HMAC-signs both strings with a random key so the comparison
 * operates on fixed-length MAC outputs — no timing oracle.
 */
export async function safeTimingEqualWeb(
  a: string,
  b: string,
): Promise<boolean> {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  if (a.length === 0) return false;

  const enc = new TextEncoder();
  const keyData = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const [aMac, bMac] = await Promise.all([
    globalThis.crypto.subtle.sign('HMAC', key, enc.encode(a)),
    globalThis.crypto.subtle.sign('HMAC', key, enc.encode(b)),
  ]);
  const aBytes = new Uint8Array(aMac);
  const bBytes = new Uint8Array(bMac);
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) {
    diff |= (aBytes[i] ?? 0) ^ (bBytes[i] ?? 0);
  }
  return diff === 0;
}

export function generateNonceWeb(): string {
  return globalThis.crypto.randomUUID();
}

export function nowUnixSecondsWeb(): number {
  return Math.floor(Date.now() / 1000);
}

/** Auth payload auth payload → base64-encoded JSON (auth payload is ASCII-safe). */
export function encodeAuthHeaderWeb(payload: object): string {
  return btoa(JSON.stringify(payload));
}

export function decodeAuthHeaderWeb(raw: string): unknown {
  return JSON.parse(atob(raw));
}

/**
 * Build the canonical string-to-sign. Duplicated from crypto-utils.ts
 * to avoid pulling in the `node:crypto` import chain.
 */
export function buildStringToSignWeb(input: {
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
