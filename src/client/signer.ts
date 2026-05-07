import {
  buildStringToSign,
  computeSignature,
  encodeAuthHeader,
  generateNonce,
  hashBody,
  nowUnixSeconds,
} from '../shared/crypto-utils.js';
import {
  DEFAULT_HEADER_NAME,
  DEFAULT_SIGNATURE_ALGORITHM,
  PAYLOAD_FIELDS,
} from '../shared/constants.js';
import type {
  AuthPayload,
  SignRequestInput,
  SignatureAlgorithm,
} from '../shared/types.js';

export interface SignClientConfig {
  clientId: string;
  /**
   * Shared secret. Treat like a password: load from a secret manager or
   * env var, never check into source control.
   */
  secret: string;
  signatureAlgorithm?: SignatureAlgorithm;
  /**
   * Header name to advertise via `headerName` getter. Pure metadata —
   * `sign()` itself returns just the value, you choose the header name
   * when sending. Defaults to `X-Signature` to match the server default.
   */
  headerName?: string;
}

/**
 * Result of `SignClient.sign()`. Most callers want `headerValue`, but we
 * also expose the inner fields for debugging and for callers who want to
 * send them as separate headers (e.g. in environments that strip long
 * Authorization-style headers).
 */
export interface SignResult {
  /** Final value to put on the wire (base64-encoded JSON of the inner payload). */
  headerValue: string;
  /** Header name to use, e.g. `X-Signature`. */
  headerName: string;
  /** Decoded payload, useful for logging in non-production. NEVER LOG `signature`. */
  payload: AuthPayload;
}

/**
 * Stateless signer for the HMAC protocol.
 *
 * Usage:
 *
 *   const signer = new SignClient({ clientId: 'svc_a', secret: '...' });
 *   const { headerName, headerValue } = signer.sign({
 *     method: 'POST',
 *     path: '/api/payments',
 *     body: JSON.stringify({ amount: 100 }), // exact bytes you'll send
 *   });
 *   await fetch(url, { method: 'POST', headers: { [headerName]: headerValue, 'Content-Type': 'application/json' }, body: ... });
 *
 * IMPORTANT: the `body` you pass to `sign()` must be byte-identical to the
 * `body` you pass to your HTTP client. If you re-stringify after signing
 * (e.g. axios will re-serialize unless `transformRequest` is overridden),
 * the server's body-hash check will fail.
 */
export class SignClient {
  readonly clientId: string;
  readonly headerName: string;
  readonly algorithm: SignatureAlgorithm;
  // Held in a closure-private property; never exposed.
  readonly #secret: string;

  constructor(config: SignClientConfig) {
    if (!config.clientId) {
      throw new Error('SignClient: clientId is required');
    }
    if (!config.secret) {
      throw new Error('SignClient: secret is required');
    }
    this.clientId = config.clientId;
    this.#secret = config.secret;
    this.headerName = config.headerName ?? DEFAULT_HEADER_NAME;
    this.algorithm = config.signatureAlgorithm ?? DEFAULT_SIGNATURE_ALGORITHM;
  }

  sign(input: SignRequestInput): SignResult {
    const timestamp = input.timestamp ?? nowUnixSeconds();
    const nonce = input.nonce ?? generateNonce();
    const bodyHashHex = hashBody(input.body, this.algorithm);
    const stringToSign = buildStringToSign({
      method: input.method,
      path: input.path,
      timestamp,
      nonce,
      bodyHashHex,
    });

    const signature = computeSignature({
      algorithm: this.algorithm,
      secret: this.#secret,
      stringToSign,
    });

    const payload: AuthPayload = {
      [PAYLOAD_FIELDS.apiKey]: this.clientId,
      [PAYLOAD_FIELDS.timestamp]: String(timestamp),
      [PAYLOAD_FIELDS.nonce]: nonce,
      [PAYLOAD_FIELDS.signature]: signature,
    };

    return {
      headerName: this.headerName,
      headerValue: encodeAuthHeader(payload),
      payload,
    };
  }

  /**
   * Override `toString` / `toJSON` so accidental `console.log(signer)` does
   * not leak the secret. (Default behavior would print the whole object.)
   */
  toString(): string {
    return `SignClient(clientId=${this.clientId}, algorithm=${this.algorithm})`;
  }
  toJSON(): { clientId: string; algorithm: string } {
    return { clientId: this.clientId, algorithm: this.algorithm };
  }
}
