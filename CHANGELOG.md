# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
