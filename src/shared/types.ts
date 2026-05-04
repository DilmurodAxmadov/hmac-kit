/**
 * Public type definitions shared by client and server.
 *
 * Keeping these in a single module means consumers can `import type` without
 * pulling in any runtime code (including the `crypto` module on Edge runtimes
 * where `import` may have side-effects).
 */

export type SignatureAlgorithm = 'sha256' | 'sha512';

/**
 * The decoded inner auth payload. This is what gets JSON.stringify'd and
 * base64-encoded into the single transport header.
 */
export interface AuthPayload {
  'x-api-key': string;
  /** Unix timestamp in seconds. Stored as string for forward compatibility. */
  'x-timestamp': string;
  'x-nonce': string;
  'x-signature': string;
}

/**
 * A minimal logger interface compatible with `console`, `pino`, `winston`,
 * etc. The verifier never logs secrets — only event names + non-sensitive
 * metadata (clientId, error code).
 */
export interface Logger {
  debug?(message: string, meta?: Record<string, unknown>): void;
  info?(message: string, meta?: Record<string, unknown>): void;
  warn?(message: string, meta?: Record<string, unknown>): void;
  error?(message: string, meta?: Record<string, unknown>): void;
}

/**
 * Input to `SignClient.sign()`. The `body` is signed verbatim — callers MUST
 * pass the EXACT bytes (or string) that will be transmitted on the wire.
 * Mismatched JSON re-serialization is the #1 cause of body-hash failures.
 */
export interface SignRequestInput {
  method: string;
  /**
   * Path component of the request URL, including leading slash.
   * Should NOT include the host or query string unless the verifier is also
   * configured to include them. Typical: `/api/payments`.
   */
  path: string;
  /**
   * The request body as a string or Buffer. For empty bodies (e.g. GET) pass
   * `''` or omit it. JSON callers MUST stringify themselves and reuse the
   * same string for the actual HTTP send.
   */
  body?: string | Buffer;
  /**
   * Optional override for timestamp (Unix seconds). Useful in tests; in
   * production leave undefined to let the client use `Date.now()`.
   */
  timestamp?: number;
  /** Optional override for nonce. Default: `crypto.randomUUID()`. */
  nonce?: string;
}

/**
 * Input to `SignatureVerifier.verify()`. The verifier receives the raw,
 * undecoded transport header along with the request data needed to
 * reconstruct the string-to-sign.
 */
export interface VerifyRequestInput {
  /**
   * The value of the `X-Signature` header (base64-encoded JSON).
   * `null`/`undefined` triggers `MissingHeaderError`.
   */
  authHeader: string | string[] | null | undefined;
  method: string;
  path: string;
  /**
   * The RAW request body, exactly as received on the wire — BEFORE any
   * JSON parsing or middleware mutation. This is critical: any
   * re-serialization (e.g. `JSON.stringify(req.body)`) will produce a
   * different byte sequence and the body hash will not match.
   */
  rawBody?: string | Buffer;
}

/**
 * Successful verification result. Returned by `verify()`, never thrown.
 */
export interface VerifyResult {
  clientId: string;
  /** Unix seconds — useful for audit logs. */
  timestamp: number;
  nonce: string;
}

/**
 * The user-supplied secret resolver. Returning `null` triggers
 * `UnknownClientError`. Throwing inside this function is treated as an
 * internal error and propagated.
 *
 * The resolver is async-friendly so it can hit a database / KMS / Vault.
 */
export type SecretResolver = (
  clientId: string,
) => Promise<string | null> | string | null;
