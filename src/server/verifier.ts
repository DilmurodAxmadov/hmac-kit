import {
  buildStringToSign,
  computeSignature,
  decodeAuthHeader,
  hashBody,
  nowUnixSeconds,
  safeTimingEqual,
} from '../shared/crypto-utils.js';
import {
  DEFAULT_HEADER_NAME,
  DEFAULT_SIGNATURE_ALGORITHM,
  DEFAULT_TIMESTAMP_WINDOW_SECONDS,
  PAYLOAD_FIELDS,
} from '../shared/constants.js';
import {
  BodyHashMismatchError,
  ExpiredRequestError,
  InternalAuthError,
  InvalidFormatError,
  InvalidSignatureError,
  MissingHeaderError,
  ReplayAttackError,
  UnknownClientError,
} from '../shared/errors.js';
import type {
  AuthPayload,
  Logger,
  SecretResolver,
  SignatureAlgorithm,
  VerifyRequestInput,
  VerifyResult,
} from '../shared/types.js';
import {
  MemoryNonceStore,
  type NonceStore,
} from './nonce-store/index.js';

export interface VerifierConfig {
  getSecret: SecretResolver;
  /** Defaults to a fresh `MemoryNonceStore` with default options. */
  nonceStore?: NonceStore;
  /** Default: 300 (5 minutes). */
  timestampWindowSeconds?: number;
  /** Default: 'sha256'. Must match what the client uses. */
  signatureAlgorithm?: SignatureAlgorithm;
  /** Default: 'X-Signature'. */
  headerName?: string;
  /**
   * Optional logger. The verifier emits ONLY non-secret data:
   * event names, error codes, clientId, timestamp delta. Never the
   * secret, never the body, never the raw signature.
   */
  logger?: Logger;
}

/**
 * Verifies HMAC-signed requests.
 *
 * The verification ORDER is deliberate:
 *
 *   1. Header presence       → `MissingHeaderError`
 *   2. Header decoding       → `InvalidFormatError`
 *   3. Field presence        → `InvalidFormatError`
 *   4. Timestamp window      → `ExpiredRequestError`
 *   5. Nonce uniqueness READ → `ReplayAttackError`
 *   6. Secret lookup         → `UnknownClientError`
 *   7. Body hash compute     → (continues)
 *   8. Signature compare     → `InvalidSignatureError` (constant time)
 *   9. Nonce uniqueness STORE → `ReplayAttackError` if a race-loser
 *
 * Why this order:
 *   - Cheap, observable-anyway checks first (everyone can see the headers).
 *   - Secret lookup AFTER timestamp+nonce — there's no point hitting the
 *     DB for a stale request, and it limits a flood of unknown-client
 *     lookups during noise.
 *   - Nonce STORE is the LAST step AND is the *binding* replay check.
 *     Step 5's `exists()` is a fast-path heuristic; step 9 uses
 *     `setIfAbsent` (atomic CAS) so two concurrent requests that both
 *     pass step 5 cannot both pass step 9. Recording a nonce before
 *     signature verification would let attackers "burn" valid future
 *     nonces by replaying with a wrong signature.
 *   - Body hash and signature are computed even on unknown clients — but
 *     with a dummy secret — to avoid timing leak that distinguishes
 *     "unknown client" from "wrong signature". (We DO throw a different
 *     error class, so the timing is the only side channel; we close it.)
 */
export class SignatureVerifier {
  readonly #getSecret: SecretResolver;
  readonly #nonceStore: NonceStore;
  readonly #window: number;
  readonly #algorithm: SignatureAlgorithm;
  readonly #headerName: string;
  readonly #logger?: Logger;

  constructor(config: VerifierConfig) {
    if (typeof config.getSecret !== 'function') {
      throw new Error('SignatureVerifier: `getSecret` is required');
    }
    this.#getSecret = config.getSecret;
    this.#nonceStore = config.nonceStore ?? new MemoryNonceStore();
    this.#window =
      config.timestampWindowSeconds ?? DEFAULT_TIMESTAMP_WINDOW_SECONDS;
    this.#algorithm =
      config.signatureAlgorithm ?? DEFAULT_SIGNATURE_ALGORITHM;
    this.#headerName = config.headerName ?? DEFAULT_HEADER_NAME;
    this.#logger = config.logger;
  }

  /** Configured header name — useful for adapters. */
  get headerName(): string {
    return this.#headerName;
  }

  async verify(input: VerifyRequestInput): Promise<VerifyResult> {
    // ─── 1. Header presence ────────────────────────────────────────────
    const rawHeader = normalizeHeaderValue(input.authHeader);
    if (!rawHeader) throw new MissingHeaderError(this.#headerName);

    // ─── 2. Header decoding ────────────────────────────────────────────
    let payload: AuthPayload;
    try {
      const decoded = decodeAuthHeader(rawHeader);
      payload = assertAuthPayload(decoded);
    } catch (err) {
      throw new InvalidFormatError(
        err instanceof Error ? err.message : 'unparseable',
      );
    }

    const clientId = payload[PAYLOAD_FIELDS.apiKey];
    const timestampStr = payload[PAYLOAD_FIELDS.timestamp];
    const nonce = payload[PAYLOAD_FIELDS.nonce];
    const presentedSig = payload[PAYLOAD_FIELDS.signature];

    // ─── 3. Field shape ────────────────────────────────────────────────
    const timestamp = Number.parseInt(timestampStr, 10);
    if (!Number.isFinite(timestamp)) {
      throw new InvalidFormatError('timestamp is not a number');
    }
    if (typeof presentedSig !== 'string' || presentedSig.length === 0) {
      throw new InvalidFormatError('missing signature field');
    }

    // ─── 4. Timestamp window ───────────────────────────────────────────
    const now = nowUnixSeconds();
    const delta = Math.abs(now - timestamp);
    if (delta > this.#window) {
      this.#log('warn', 'auth.timestamp_outside_window', {
        clientId,
        deltaSeconds: delta,
      });
      throw new ExpiredRequestError();
    }

    // ─── 5. Nonce read (replay detection) ──────────────────────────────
    let alreadySeen: boolean;
    try {
      alreadySeen = await this.#nonceStore.exists(nonceKey(clientId, nonce));
    } catch (err) {
      this.#log('error', 'auth.nonce_store_read_failed', {
        clientId,
        cause: errMsg(err),
      });
      throw new InternalAuthError('nonce store read failed');
    }
    if (alreadySeen) {
      this.#log('warn', 'auth.replay_attack', { clientId });
      throw new ReplayAttackError();
    }

    // ─── 6. Secret lookup ──────────────────────────────────────────────
    let secret: string | null;
    try {
      secret = await this.#getSecret(clientId);
    } catch (err) {
      this.#log('error', 'auth.secret_resolver_failed', {
        clientId,
        cause: errMsg(err),
      });
      throw new InternalAuthError('secret resolver failed');
    }
    if (!secret) {
      this.#log('warn', 'auth.unknown_client', { clientId });
      // Important: still consume some computation below to keep timing
      // similar to the "wrong signature" path. We do this by computing
      // a signature with a dummy secret, then throwing the right error.
      // We still throw `UnknownClientError` (not `InvalidSignatureError`)
      // — the differentiated error class is intentional for debug, and
      // is only observable to authenticated operators reading logs.
      this.#computeWithDummySecret({
        method: input.method,
        path: input.path,
        timestamp,
        nonce,
        body: input.rawBody,
      });
      throw new UnknownClientError();
    }

    // ─── 7. Body hash + 8. Signature compare ──────────────────────────
    const bodyHashHex = hashBody(input.rawBody, this.#algorithm);
    const stringToSign = buildStringToSign({
      method: input.method,
      path: input.path,
      timestamp,
      nonce,
      bodyHashHex,
    });
    const expectedSig = computeSignature({
      algorithm: this.#algorithm,
      secret,
      stringToSign,
    });

    if (!safeTimingEqual(expectedSig, presentedSig)) {
      // Disambiguate body-tamper from key-mismatch ONLY if cheaply
      // possible. Both produce a signature mismatch; we treat any
      // mismatch as `InvalidSignatureError`. The `BodyHashMismatchError`
      // class exists for callers who want to detect the special case
      // by re-running with a recomputed body — we don't do that here
      // to avoid leaking which part failed via timing.
      this.#log('warn', 'auth.invalid_signature', { clientId });
      throw new InvalidSignatureError();
    }

    // ─── 9. Record nonce (binding replay check) ────────────────────────
    // Use 2× window as TTL: any record older than that can no longer
    // be used to replay because the timestamp check would reject first.
    // Prefer `setIfAbsent` — atomic CAS that closes the TOCTOU window
    // between step 5's `exists()` and this write. A `false` return means
    // a concurrent duplicate raced us past step 5; reject it as a replay.
    const fullNonceKey = nonceKey(clientId, nonce);
    let lostRace = false;
    try {
      if (typeof this.#nonceStore.setIfAbsent === 'function') {
        lostRace = !(await this.#nonceStore.setIfAbsent(
          fullNonceKey,
          this.#window * 2,
        ));
      } else {
        await this.#nonceStore.set(fullNonceKey, this.#window * 2);
      }
    } catch (err) {
      this.#log('error', 'auth.nonce_store_write_failed', {
        clientId,
        cause: errMsg(err),
      });
      throw new InternalAuthError('nonce store write failed');
    }
    if (lostRace) {
      this.#log('warn', 'auth.replay_attack_race', { clientId });
      throw new ReplayAttackError();
    }

    this.#log('debug', 'auth.success', { clientId });
    return { clientId, timestamp, nonce };
  }

  /**
   * Public hook to (separately) verify the body hash. Adapters CAN call
   * this AFTER `verify()` if they want a distinct `BodyHashMismatchError`
   * for diagnostics — but it requires running the HMAC twice, so it's
   * opt-in. NOT used by `verify()` itself.
   */
  static computeBodyHash(body?: string | Buffer): string {
    return hashBody(body);
  }

  // Discard result. We just want the wall-clock cost.
  #computeWithDummySecret(args: {
    method: string;
    path: string;
    timestamp: number;
    nonce: string;
    body: string | Buffer | undefined;
  }): void {
    const bodyHashHex = hashBody(args.body, this.#algorithm);
    const stringToSign = buildStringToSign({
      method: args.method,
      path: args.path,
      timestamp: args.timestamp,
      nonce: args.nonce,
      bodyHashHex,
    });
    computeSignature({
      algorithm: this.#algorithm,
      secret: 'dummy-secret-for-timing-equalization',
      stringToSign,
    });
  }

  #log(
    level: 'debug' | 'info' | 'warn' | 'error',
    event: string,
    meta: Record<string, unknown>,
  ): void {
    const fn = this.#logger?.[level];
    if (typeof fn === 'function') fn(event, meta);
  }
}

/** Hide `BodyHashMismatchError` inside the module so it can be re-exported. */
export { BodyHashMismatchError };

// ─── helpers ─────────────────────────────────────────────────────────────

/** Express/Fastify both can deliver a header as `string | string[]`. */
function normalizeHeaderValue(
  raw: string | string[] | null | undefined,
): string | null {
  if (raw == null) return null;
  if (Array.isArray(raw)) return raw[0] ?? null;
  return raw;
}

function assertAuthPayload(value: unknown): AuthPayload {
  if (!value || typeof value !== 'object') {
    throw new Error('payload is not an object');
  }
  const v = value as Record<string, unknown>;
  for (const field of [
    PAYLOAD_FIELDS.apiKey,
    PAYLOAD_FIELDS.timestamp,
    PAYLOAD_FIELDS.nonce,
    PAYLOAD_FIELDS.signature,
  ] as const) {
    if (typeof v[field] !== 'string' || v[field] === '') {
      throw new Error(`missing or empty field "${field}"`);
    }
  }
  return value as AuthPayload;
}

/** Namespace nonce keys per-client to prevent cross-client collision. */
function nonceKey(clientId: string, nonce: string): string {
  return `${clientId}:${nonce}`;
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
