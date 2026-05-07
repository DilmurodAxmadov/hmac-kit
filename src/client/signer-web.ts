import {
  buildStringToSignWeb,
  computeSignatureWeb,
  encodeAuthHeaderWeb,
  generateNonceWeb,
  hashBodyWeb,
  nowUnixSecondsWeb,
} from '../shared/crypto-web.js';
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

export interface EdgeSignClientConfig {
  clientId: string;
  secret: string;
  signatureAlgorithm?: SignatureAlgorithm;
  headerName?: string;
}

export interface EdgeSignResult {
  headerValue: string;
  headerName: string;
  payload: AuthPayload;
}

/**
 * Edge-compatible async signer. Uses Web Crypto API — works in
 * Cloudflare Workers, Deno, Vercel Edge Runtime, and Node.js 18+.
 *
 * `sign()` is async; otherwise the API mirrors `SignClient`.
 */
export class EdgeSignClient {
  readonly clientId: string;
  readonly headerName: string;
  readonly algorithm: SignatureAlgorithm;
  readonly #secret: string;

  constructor(config: EdgeSignClientConfig) {
    if (!config.clientId) throw new Error('EdgeSignClient: clientId is required');
    if (!config.secret) throw new Error('EdgeSignClient: secret is required');
    this.clientId = config.clientId;
    this.#secret = config.secret;
    this.headerName = config.headerName ?? DEFAULT_HEADER_NAME;
    this.algorithm = config.signatureAlgorithm ?? DEFAULT_SIGNATURE_ALGORITHM;
  }

  async sign(input: SignRequestInput): Promise<EdgeSignResult> {
    const timestamp = input.timestamp ?? nowUnixSecondsWeb();
    const nonce = input.nonce ?? generateNonceWeb();
    const bodyHashHex = await hashBodyWeb(input.body as string | Uint8Array | undefined, this.algorithm);
    const stringToSign = buildStringToSignWeb({
      method: input.method,
      path: input.path,
      timestamp,
      nonce,
      bodyHashHex,
    });

    const signature = await computeSignatureWeb({
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
      headerValue: encodeAuthHeaderWeb(payload),
      payload,
    };
  }

  toString(): string {
    return `EdgeSignClient(clientId=${this.clientId}, algorithm=${this.algorithm})`;
  }
  toJSON(): { clientId: string; algorithm: string } {
    return { clientId: this.clientId, algorithm: this.algorithm };
  }
}
