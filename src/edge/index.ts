/**
 * Edge Runtime entry point for `@daxmadov/hmac-kit/edge`.
 *
 * Uses Web Crypto API exclusively — no `node:crypto`.
 * Compatible with: Cloudflare Workers, Deno, Vercel Edge, Node.js 18+.
 *
 * Usage:
 *   import { EdgeSignClient, EdgeSignatureVerifier } from '@daxmadov/hmac-kit/edge'
 */

export { EdgeSignClient } from '../client/signer-web.js';
export type { EdgeSignClientConfig, EdgeSignResult } from '../client/signer-web.js';

export { EdgeSignedHttpClient } from '../client/http-client-web.js';
export type {
  EdgeSignedHttpClientConfig,
  EdgeSignedRequestOptions,
  EdgeRetryConfig,
} from '../client/http-client-web.js';

export { EdgeSignatureVerifier } from '../server/verifier-web.js';
export type { EdgeVerifierConfig } from '../server/verifier-web.js';
export { BodyHashMismatchError as EdgeBodyHashMismatchError } from '../server/verifier-web.js';

export { MemoryNonceStore, RedisNonceStore } from '../server/nonce-store/index.js';
export type {
  NonceStore,
  MemoryNonceStoreOptions,
  RedisNonceStoreOptions,
  RedisLikeClient,
} from '../server/nonce-store/index.js';

export * from '../shared/errors.js';
export type {
  AuthPayload,
  Logger,
  SecretResolver,
  SignatureAlgorithm,
  SignRequestInput,
  VerifyRequestInput,
  VerifyResult,
} from '../shared/types.js';
