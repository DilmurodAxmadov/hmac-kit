# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] — 2026-05-18

### Fixed

- **Replay protection race condition (security)** — `SignatureVerifier` and
  `EdgeSignatureVerifier` now bind their replay decision through an atomic
  compare-and-set on the nonce store, closing a TOCTOU window between the
  early `exists()` heuristic and the final `set()`. Previously, two
  concurrent identical signed requests could both observe `exists() === false`
  and both pass verification — a classic double-spend risk for payment-like
  APIs. The loser of the CAS race now receives `ReplayAttackError`.

### Added

- **`NonceStore.setIfAbsent(key, ttlSeconds): Promise<boolean>`** — new
  optional method on the store interface. Returns `true` if the entry was
  newly inserted, `false` if a live entry already existed. Both
  `MemoryNonceStore` and `RedisNonceStore` implement it; the verifier
  prefers it when available and gracefully falls back to `exists`+`set`
  for third-party stores that do not implement it (with the documented
  weaker semantics).

### Notes

- Fully backward compatible. No API changes for users of `SignClient`,
  `SignedHttpClient`, `SignatureVerifier`, or the framework adapters.
- Third-party `NonceStore` implementations continue to work unchanged;
  they should add `setIfAbsent` for race-safe replay protection.

## [0.2.0] — 2026-05-07

### Added

- **SHA-512 support** — `signatureAlgorithm: 'sha512'` now works end-to-end.
  Both body hashing and HMAC computation use the configured algorithm.
  Pass the same `signatureAlgorithm` to `SignClient` / `SignedHttpClient` and
  `SignatureVerifier` to activate. Default remains SHA-256.

- **Auto-retry in `SignedHttpClient`** — new `retry` config option.
  - `attempts` — total attempts including the first (default: `1`, i.e. no retry).
  - `delayMs` — base delay between retries in ms (default: `500`).
  - `backoff` — `'exponential'` (default) or `'fixed'`.
  - `statusCodes` — HTTP status codes that trigger a retry (default:
    `[429, 500, 502, 503, 504]`).
  - Each retry re-signs with a **fresh nonce and timestamp** — replay protection
    is never weakened by retries.

- **Edge Runtime support** — new `@daxmadov/hmac-kit/edge` subpath export.
  Uses `globalThis.crypto` (Web Crypto API) exclusively — no `node:crypto`.
  Compatible with Cloudflare Workers, Deno, Vercel Edge Functions, Bun, and
  Node.js 18+.
  - `EdgeSignClient` — same API as `SignClient`; `sign()` is `async`.
  - `EdgeSignatureVerifier` — same API as `SignatureVerifier`.
  - `EdgeSignedHttpClient` — same API as `SignedHttpClient`, includes retry.
  - Timing-safe comparison implemented via HMAC with a per-call random key
    (Web Crypto has no `timingSafeEqual` equivalent).

### Changed

- `hashBody` now accepts an optional `algorithm` parameter (default: `'sha256'`).
  When `signatureAlgorithm: 'sha512'` is configured, the body hash embedded in
  the string-to-sign also uses SHA-512 for consistency.

  > **Migration**: if you were explicitly passing `signatureAlgorithm: 'sha512'`
  > in v0.1.0 (undocumented), the wire format has changed — both client and
  > server must upgrade together.

---

## [0.1.0] — 2026-05-04

Initial public release.

### Added

- **Project skeleton**: `package.json` with subpath `exports`, dual
  ESM/CJS build via `tsup`, strict `tsconfig.json`, Vitest config,
  ESLint + Prettier.
- **Shared layer** (`src/shared/`):
  - `types.ts` — public `AuthPayload`, `SignRequestInput`,
    `VerifyRequestInput`, `VerifyResult`, `SecretResolver`, `Logger`,
    `SignatureAlgorithm`.
  - `errors.ts` — `HmacAuthError` hierarchy with stable `code` strings
    and `httpStatus` mapping. Subclasses: `MissingHeaderError`,
    `InvalidFormatError`, `ExpiredRequestError`, `ReplayAttackError`,
    `UnknownClientError`, `InvalidSignatureError`,
    `BodyHashMismatchError`, `InternalAuthError`.
  - `crypto-utils.ts` — `hashBody`, `buildStringToSign`,
    `computeSignature`, `safeTimingEqual` (constant-time, length-validated),
    `encodeAuthHeader`, `decodeAuthHeader`, `generateNonce`,
    `nowUnixSeconds`.
  - `constants.ts` — `DEFAULT_HEADER_NAME`,
    `DEFAULT_TIMESTAMP_WINDOW_SECONDS`, `DEFAULT_SIGNATURE_ALGORITHM`,
    `PAYLOAD_FIELDS`, `PROTOCOL_VERSION`.
- **Client** (`src/client/`):
  - `SignClient` — stateless signer. Holds secret in a private
    `#secret` field, overrides `toString` / `toJSON` to prevent
    log-leaking.
  - `SignedHttpClient` — fetch wrapper that signs every request.
    Serializes the body exactly once, supports timeouts via
    `AbortController`, merges multiple `AbortSignal`s.
- **Server** (`src/server/`):
  - `SignatureVerifier` — full verification pipeline with deliberate
    ordering (header → format → timestamp → nonce read → secret →
    signature → nonce write). Constant-time signature compare.
    Optional logger.
  - `MemoryNonceStore` — in-memory TTL store with periodic sweep
    (`unref()`'d timer) and max-entries safety valve.
  - `RedisNonceStore` — `ioredis`-compatible store with optional
    `SET NX EX` atomic mode. No hard runtime dependency on `ioredis` —
    caller passes in the client.
- **Adapters** (`src/adapters/`):
  - `express.ts` — `createHmacMiddleware(verifier)` plus a
    `rawBodySaver` callback for `express.json({ verify })`. Maps
    `HmacAuthError` to the matching HTTP status.
  - `fastify.ts` — `hmacAuthPlugin` with a content-type parser that
    populates `request.rawBody`, plus a `preValidation` hook that
    verifies and attaches `request.hmac`.
  - `nestjs.ts` — `HmacAuthGuard`, `createHmacAuthGuard(verifier)`
    factory, and an `HMAC_VERIFIER` injection token. Compatible with
    Express- or Fastify-based Nest apps that opt into
    `{ rawBody: true }`.
- **Tests**: comprehensive Vitest suite covering crypto utils, signer,
  verifier (success + every rejection path), nonce stores (memory + a
  mock Redis client), and integration tests for the Express, Fastify,
  and NestJS adapters.

### Security

- Constant-time signature comparison via `crypto.timingSafeEqual` with
  strict length and hex-format pre-validation.
- Verification order designed to delay secret lookup until after cheap
  checks pass; nonce is recorded only after a successful signature
  verification.
- Nonces are namespaced per client (`clientId:nonce`).
- Secrets never appear in error messages, `toString`, or `toJSON`.
- Verifier never parses or re-serializes the request body — raw bytes
  only.
