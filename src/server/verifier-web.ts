import {
  buildStringToSignWeb,
  computeSignatureWeb,
  decodeAuthHeaderWeb,
  hashBodyWeb,
  nowUnixSecondsWeb,
  safeTimingEqualWeb,
} from '../shared/crypto-web.js';
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
import { MemoryNonceStore, type NonceStore } from './nonce-store/index.js';

export interface EdgeVerifierConfig {
  getSecret: SecretResolver;
  nonceStore?: NonceStore;
  timestampWindowSeconds?: number;
  signatureAlgorithm?: SignatureAlgorithm;
  headerName?: string;
  logger?: Logger;
}

/**
 * Edge-compatible verifier. Uses Web Crypto API — works in
 * Cloudflare Workers, Deno, Vercel Edge Runtime, and Node.js 18+.
 *
 * API is identical to `SignatureVerifier`; same verification order and
 * security properties.
 */
export class EdgeSignatureVerifier {
  readonly #getSecret: SecretResolver;
  readonly #nonceStore: NonceStore;
  readonly #window: number;
  readonly #algorithm: SignatureAlgorithm;
  readonly #headerName: string;
  readonly #logger?: Logger;

  constructor(config: EdgeVerifierConfig) {
    if (typeof config.getSecret !== 'function') {
      throw new Error('EdgeSignatureVerifier: `getSecret` is required');
    }
    this.#getSecret = config.getSecret;
    this.#nonceStore = config.nonceStore ?? new MemoryNonceStore();
    this.#window = config.timestampWindowSeconds ?? DEFAULT_TIMESTAMP_WINDOW_SECONDS;
    this.#algorithm = config.signatureAlgorithm ?? DEFAULT_SIGNATURE_ALGORITHM;
    this.#headerName = config.headerName ?? DEFAULT_HEADER_NAME;
    this.#logger = config.logger;
  }

  get headerName(): string {
    return this.#headerName;
  }

  async verify(input: VerifyRequestInput): Promise<VerifyResult> {
    const rawHeader = normalizeHeaderValue(input.authHeader);
    if (!rawHeader) throw new MissingHeaderError(this.#headerName);

    let payload: AuthPayload;
    try {
      const decoded = decodeAuthHeaderWeb(rawHeader);
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

    const timestamp = Number.parseInt(timestampStr, 10);
    if (!Number.isFinite(timestamp)) {
      throw new InvalidFormatError('timestamp is not a number');
    }
    if (typeof presentedSig !== 'string' || presentedSig.length === 0) {
      throw new InvalidFormatError('missing signature field');
    }

    const now = nowUnixSecondsWeb();
    const delta = Math.abs(now - timestamp);
    if (delta > this.#window) {
      this.#log('warn', 'auth.timestamp_outside_window', { clientId, deltaSeconds: delta });
      throw new ExpiredRequestError();
    }

    let alreadySeen: boolean;
    try {
      alreadySeen = await this.#nonceStore.exists(nonceKey(clientId, nonce));
    } catch (err) {
      this.#log('error', 'auth.nonce_store_read_failed', { clientId, cause: errMsg(err) });
      throw new InternalAuthError('nonce store read failed');
    }
    if (alreadySeen) {
      this.#log('warn', 'auth.replay_attack', { clientId });
      throw new ReplayAttackError();
    }

    let secret: string | null;
    try {
      secret = await this.#getSecret(clientId);
    } catch (err) {
      this.#log('error', 'auth.secret_resolver_failed', { clientId, cause: errMsg(err) });
      throw new InternalAuthError('secret resolver failed');
    }
    if (!secret) {
      this.#log('warn', 'auth.unknown_client', { clientId });
      await this.#computeWithDummySecret({ method: input.method, path: input.path, timestamp, nonce, body: input.rawBody });
      throw new UnknownClientError();
    }

    const bodyHashHex = await hashBodyWeb(input.rawBody as string | Uint8Array | undefined, this.#algorithm);
    const stringToSign = buildStringToSignWeb({
      method: input.method,
      path: input.path,
      timestamp,
      nonce,
      bodyHashHex,
    });
    const expectedSig = await computeSignatureWeb({
      algorithm: this.#algorithm,
      secret,
      stringToSign,
    });

    if (!(await safeTimingEqualWeb(expectedSig, presentedSig))) {
      this.#log('warn', 'auth.invalid_signature', { clientId });
      throw new InvalidSignatureError();
    }

    // Atomic CAS via `setIfAbsent` when available; closes the TOCTOU
    // window between the earlier `exists()` heuristic and this write.
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
      this.#log('error', 'auth.nonce_store_write_failed', { clientId, cause: errMsg(err) });
      throw new InternalAuthError('nonce store write failed');
    }
    if (lostRace) {
      this.#log('warn', 'auth.replay_attack_race', { clientId });
      throw new ReplayAttackError();
    }

    this.#log('debug', 'auth.success', { clientId });
    return { clientId, timestamp, nonce };
  }

  static async computeBodyHash(
    body?: string | Uint8Array,
    algorithm: SignatureAlgorithm = 'sha256',
  ): Promise<string> {
    return hashBodyWeb(body, algorithm);
  }

  async #computeWithDummySecret(args: {
    method: string;
    path: string;
    timestamp: number;
    nonce: string;
    body: string | Buffer | undefined;
  }): Promise<void> {
    const bodyHashHex = await hashBodyWeb(args.body as string | Uint8Array | undefined, this.#algorithm);
    const stringToSign = buildStringToSignWeb({
      method: args.method,
      path: args.path,
      timestamp: args.timestamp,
      nonce: args.nonce,
      bodyHashHex,
    });
    await computeSignatureWeb({
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

export { BodyHashMismatchError };

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

function nonceKey(clientId: string, nonce: string): string {
  return `${clientId}:${nonce}`;
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
