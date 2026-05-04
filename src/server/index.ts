export { SignatureVerifier } from './verifier.js';
export type { VerifierConfig } from './verifier.js';

// Nonce stores
export {
  MemoryNonceStore,
  RedisNonceStore,
} from './nonce-store/index.js';
export type {
  NonceStore,
  MemoryNonceStoreOptions,
  RedisNonceStoreOptions,
  RedisLikeClient,
} from './nonce-store/index.js';

// Errors live in `shared` but are re-exported here because server users
// almost always need them for `instanceof` discrimination.
export {
  HmacAuthError,
  MissingHeaderError,
  InvalidFormatError,
  ExpiredRequestError,
  ReplayAttackError,
  UnknownClientError,
  InvalidSignatureError,
  BodyHashMismatchError,
  InternalAuthError,
} from '../shared/errors.js';
export type { HmacAuthErrorCode } from '../shared/errors.js';

// Common types
export type {
  Logger,
  SecretResolver,
  SignatureAlgorithm,
  VerifyRequestInput,
  VerifyResult,
} from '../shared/types.js';
