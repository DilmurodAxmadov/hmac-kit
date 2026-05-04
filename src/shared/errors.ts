/**
 * Error hierarchy for `@daxmadov/hmac-kit`.
 *
 * Design goals:
 *   1. Each failure mode has its OWN class, so callers can `instanceof` and
 *      decide what to log / what HTTP status to return.
 *   2. Every error carries a stable `code` string, useful for structured
 *      logging and dashboards. Codes are SCREAMING_SNAKE_CASE and stable
 *      across versions — they're part of the public API.
 *   3. NEVER include the secret, the raw signature, or full body in any
 *      error message. Even via `Error.cause`. This is enforced by always
 *      constructing messages from a hardcoded template — never from
 *      attacker-controlled input.
 *   4. `httpStatus` provides a sensible default mapping so framework
 *      adapters can render appropriate responses without a giant switch.
 */

export type HmacAuthErrorCode =
  | 'MISSING_HEADER'
  | 'INVALID_FORMAT'
  | 'EXPIRED_REQUEST'
  | 'REPLAY_ATTACK'
  | 'UNKNOWN_CLIENT'
  | 'INVALID_SIGNATURE'
  | 'BODY_HASH_MISMATCH'
  | 'INTERNAL_ERROR';

export abstract class HmacAuthError extends Error {
  abstract readonly code: HmacAuthErrorCode;
  /** Recommended HTTP status code for this error. */
  abstract readonly httpStatus: number;

  constructor(message: string) {
    super(message);
    // Preserve the actual subclass name in stack traces.
    this.name = this.constructor.name;
    // V8 prototype chain fix for `instanceof` after transpilation.
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /** Stable JSON shape, safe to send to clients (no secrets). */
  toJSON(): { name: string; code: string; message: string } {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
    };
  }
}

/** No `X-Signature` header was sent. */
export class MissingHeaderError extends HmacAuthError {
  readonly code = 'MISSING_HEADER' as const;
  readonly httpStatus = 401;
  constructor(headerName = 'X-Signature') {
    super(`Required authentication header is missing: ${headerName}`);
  }
}

/**
 * The header existed but could not be decoded — bad base64, bad JSON, or
 * missing required fields inside the inner payload.
 */
export class InvalidFormatError extends HmacAuthError {
  readonly code = 'INVALID_FORMAT' as const;
  readonly httpStatus = 400;
  constructor(reason: string) {
    super(`Authentication header has invalid format: ${reason}`);
  }
}

/**
 * Timestamp is outside the allowed window — too old (replay) or too far in
 * the future (clock skew). The error does NOT distinguish past vs. future
 * publicly; that information is only logged internally.
 */
export class ExpiredRequestError extends HmacAuthError {
  readonly code = 'EXPIRED_REQUEST' as const;
  readonly httpStatus = 401;
  constructor() {
    super('Request timestamp is outside the allowed window');
  }
}

/**
 * The nonce has already been used within the timestamp window. Either a
 * deliberate replay attack or an accidental retry. Either way: deny.
 */
export class ReplayAttackError extends HmacAuthError {
  readonly code = 'REPLAY_ATTACK' as const;
  readonly httpStatus = 401;
  constructor() {
    super('Request nonce has already been used (possible replay attack)');
  }
}

/** Client ID is well-formed but the resolver returned `null`. */
export class UnknownClientError extends HmacAuthError {
  readonly code = 'UNKNOWN_CLIENT' as const;
  readonly httpStatus = 401;
  constructor() {
    super('Unknown client');
  }
}

/**
 * The signature is well-formed and the same length as expected, but does
 * not match the locally computed value. Always returned via constant-time
 * compare to prevent timing attacks.
 */
export class InvalidSignatureError extends HmacAuthError {
  readonly code = 'INVALID_SIGNATURE' as const;
  readonly httpStatus = 401;
  constructor() {
    super('Request signature is invalid');
  }
}

/**
 * Body was tampered with: the SHA-256 hash embedded in the string-to-sign
 * does not match the hash of the received body. Distinct from
 * `InvalidSignatureError` for debugging — note that with a correctly-built
 * client this should never fire; it usually means a middleware mutated the
 * body before it reached the verifier.
 */
export class BodyHashMismatchError extends HmacAuthError {
  readonly code = 'BODY_HASH_MISMATCH' as const;
  readonly httpStatus = 400;
  constructor() {
    super('Request body does not match the signed body hash');
  }
}

/**
 * Wraps a non-auth failure inside the verifier (e.g. nonce store outage).
 * Intentionally an auth error subclass so adapters can short-circuit, but
 * carries `httpStatus = 500` so callers know to alert.
 */
export class InternalAuthError extends HmacAuthError {
  readonly code = 'INTERNAL_ERROR' as const;
  readonly httpStatus = 500;
  constructor(reason: string) {
    super(`Internal authentication error: ${reason}`);
  }
}
