/**
 * `@daxmadov/hmac-kit` — root barrel.
 *
 * Most apps should import from a SUBPATH for smaller bundles:
 *   - `@daxmadov/hmac-kit/client` → just the signer + signed-fetch
 *   - `@daxmadov/hmac-kit/server` → just the verifier + nonce stores
 *   - `@daxmadov/hmac-kit/adapters/express`  (etc.)
 *
 * The root barrel re-exports everything for convenience but pulls in
 * both client + server code. That's fine for monolith apps, less so for
 * a tiny client-only consumer.
 */
export * from './client/index.js';
export * from './server/index.js';

// Re-export the protocol version so callers can pin/check it explicitly.
export { PROTOCOL_VERSION } from './shared/constants.js';
