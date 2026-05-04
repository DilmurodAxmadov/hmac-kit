export { SignClient } from './signer.js';
export type { SignClientConfig, SignResult } from './signer.js';
export { SignedHttpClient } from './http-client.js';
export type {
  SignedHttpClientConfig,
  SignedRequestOptions,
} from './http-client.js';

// Re-export types that consumers commonly need alongside the client.
export type {
  AuthPayload,
  SignRequestInput,
  SignatureAlgorithm,
} from '../shared/types.js';
