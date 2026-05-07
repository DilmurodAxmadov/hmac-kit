# @daxmadov/hmac-kit

[![npm version](https://img.shields.io/npm/v/@daxmadov/hmac-kit.svg)](https://www.npmjs.com/package/@daxmadov/hmac-kit)
[![npm downloads](https://img.shields.io/npm/dm/@daxmadov/hmac-kit.svg)](https://www.npmjs.com/package/@daxmadov/hmac-kit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/node/v/@daxmadov/hmac-kit.svg)](https://nodejs.org)

Framework-agnostic HMAC-SHA256/SHA-512 request signing for server-to-server
authentication. Includes a stateless client signer, a server-side verifier
with replay protection, pluggable nonce storage (memory / Redis), and
adapters for Express, Fastify, and NestJS.

- Constant-time signature comparison
- Replay protection via per-client nonces
- 5-minute timestamp window (configurable)
- SHA-256 (default) or SHA-512 — opt-in per client/server pair
- Built-in retry with exponential backoff (`SignedHttpClient`)
- Edge Runtime support — Cloudflare Workers, Deno, Vercel Edge (`/edge`)
- Zero hard runtime dependencies — peer deps are all optional
- Dual ESM + CJS, full `.d.ts` types per subpath

## Install

```bash
npm install @daxmadov/hmac-kit
```

Optional, only if you use the matching feature:

```bash
npm install ioredis           # for RedisNonceStore
npm install express           # for the Express adapter
npm install fastify           # for the Fastify adapter
npm install @nestjs/common    # for the NestJS adapter
```

Requires Node.js 18+.

## Quick start

### Client

```ts
import { SignClient } from '@daxmadov/hmac-kit/client';

const signer = new SignClient({
  clientId: 'svc_a',
  secret: process.env.API_SECRET!,
});

const body = JSON.stringify({ amount: 100 });
const { headerName, headerValue } = signer.sign({
  method: 'POST',
  path: '/api/payments',
  body, // EXACT bytes you'll send on the wire
});

await fetch('https://api.example.com/api/payments', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    [headerName]: headerValue,
  },
  body, // <-- same string you signed
});
```

Or, with the built-in fetch wrapper:

```ts
import { SignedHttpClient } from '@daxmadov/hmac-kit/client';

const client = new SignedHttpClient({
  baseUrl: 'https://api.example.com',
  clientId: 'svc_a',
  secret: process.env.API_SECRET!,
});

const res = await client.post('/api/payments', { amount: 100 });
```

#### Retry on transient errors

`SignedHttpClient` can retry automatically. Each retry re-signs with a
fresh nonce and timestamp, so replay protection is never compromised.

```ts
const client = new SignedHttpClient({
  baseUrl: 'https://api.example.com',
  clientId: 'svc_a',
  secret: process.env.API_SECRET!,
  retry: {
    attempts: 3,           // total attempts including the first (default: 1)
    delayMs: 500,          // base delay in ms (default: 500)
    backoff: 'exponential',// 'exponential' or 'fixed' (default: 'exponential')
    statusCodes: [429, 500, 502, 503, 504], // which codes to retry
  },
});
```

#### SHA-512

Pass `signatureAlgorithm: 'sha512'` to both client and server to use
HMAC-SHA-512. Both sides must use the same algorithm.

```ts
const signer = new SignClient({
  clientId: 'svc_a',
  secret: process.env.API_SECRET!,
  signatureAlgorithm: 'sha512',
});

const verifier = new SignatureVerifier({
  getSecret: async (id) => db.getSecret(id),
  signatureAlgorithm: 'sha512',
});
```

### Server (raw)

```ts
import {
  SignatureVerifier,
  MemoryNonceStore,
  HmacAuthError,
} from '@daxmadov/hmac-kit/server';

const verifier = new SignatureVerifier({
  getSecret: async (clientId) => {
    const row = await db.clients.findOne({ id: clientId });
    return row?.secret ?? null;
  },
  nonceStore: new MemoryNonceStore(), // or RedisNonceStore for prod
  timestampWindowSeconds: 300,
});

try {
  const { clientId } = await verifier.verify({
    authHeader: req.headers['x-signature'],
    method: req.method,
    path: req.path,
    rawBody: req.rawBody, // raw bytes — see "Raw body" below
  });
  // request is authentic; clientId is verified
} catch (err) {
  if (err instanceof HmacAuthError) {
    res.status(err.httpStatus).json(err.toJSON());
    return;
  }
  throw err;
}
```

### Express adapter

```ts
import express from 'express';
import { SignatureVerifier, MemoryNonceStore } from '@daxmadov/hmac-kit/server';
import {
  createHmacMiddleware,
  rawBodySaver,
} from '@daxmadov/hmac-kit/adapters/express';

const verifier = new SignatureVerifier({
  getSecret: async (id) => process.env.SHARED_SECRET ?? null,
  nonceStore: new MemoryNonceStore(),
});

const app = express();
app.use(express.json({ verify: rawBodySaver })); // captures req.rawBody
app.use(createHmacMiddleware(verifier));

app.post('/api/payments', (req, res) => {
  res.json({ ok: true, clientId: req.hmac!.clientId });
});
```

### Fastify adapter

```ts
import Fastify from 'fastify';
import { SignatureVerifier, MemoryNonceStore } from '@daxmadov/hmac-kit/server';
import { hmacAuthPlugin } from '@daxmadov/hmac-kit/adapters/fastify';

const verifier = new SignatureVerifier({ /* ... */ });
const app = Fastify();
await app.register(hmacAuthPlugin, { verifier });

app.post('/api/payments', async (req) => ({ clientId: req.hmac?.clientId }));
```

### NestJS adapter

Enable raw body capture at app boot:

```ts
const app = await NestFactory.create(AppModule, { rawBody: true });
```

Wire the guard:

```ts
import { Module, UseGuards, Post, Req } from '@nestjs/common';
import { SignatureVerifier, MemoryNonceStore } from '@daxmadov/hmac-kit/server';
import { HmacAuthGuard, HMAC_VERIFIER } from '@daxmadov/hmac-kit/adapters/nestjs';

@Module({
  providers: [
    {
      provide: HMAC_VERIFIER,
      useFactory: () =>
        new SignatureVerifier({
          getSecret: async () => process.env.SHARED_SECRET ?? null,
          nonceStore: new MemoryNonceStore(),
        }),
    },
    {
      provide: HmacAuthGuard,
      useFactory: (v: SignatureVerifier) => new HmacAuthGuard(v),
      inject: [HMAC_VERIFIER],
    },
  ],
  exports: [HmacAuthGuard],
})
export class HmacModule {}

@Controller('api')
export class PaymentsController {
  @UseGuards(HmacAuthGuard)
  @Post('payments')
  handle(@Req() req: any) {
    return { clientId: req.hmac.clientId };
  }
}
```

## Edge Runtime

Use the `/edge` subpath for environments that do not support `node:crypto`
(Cloudflare Workers, Deno, Vercel Edge Functions, Bun).

The Edge API is identical to the Node.js API except that `EdgeSignClient.sign()`
is `async`.

```ts
import {
  EdgeSignClient,
  EdgeSignatureVerifier,
  EdgeSignedHttpClient,
  MemoryNonceStore,
} from '@daxmadov/hmac-kit/edge';

// Client
const signer = new EdgeSignClient({
  clientId: 'svc_a',
  secret: process.env.API_SECRET!,
});

const { headerName, headerValue } = await signer.sign({
  method: 'POST',
  path: '/api/payments',
  body: JSON.stringify({ amount: 100 }),
});

// Server (e.g. Cloudflare Worker)
const verifier = new EdgeSignatureVerifier({
  getSecret: async (id) => env.SECRETS[id] ?? null,
  nonceStore: new MemoryNonceStore(),
});

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const rawBody = await request.text();

    try {
      const { clientId } = await verifier.verify({
        authHeader: request.headers.get('x-signature'),
        method: request.method,
        path: url.pathname + url.search,
        rawBody,
      });
      return Response.json({ ok: true, clientId });
    } catch (err: any) {
      return Response.json(err.toJSON(), { status: err.httpStatus ?? 500 });
    }
  },
};
```

The `EdgeSignedHttpClient` has the same retry support as `SignedHttpClient`.

> **Node.js**: You can also use the `/edge` export in Node.js 18+ — both
> `node:crypto` and `globalThis.crypto` are available there.

## Raw body

The verifier hashes the **exact bytes** the client signed. If your HTTP
framework parses the body before the verifier sees it (Express, NestJS,
Fastify), you must capture the raw bytes:

- **Express**: use the included `rawBodySaver` as `express.json({ verify })`.
- **Fastify**: the included plugin registers a content-type parser that
  populates `req.rawBody` automatically.
- **NestJS**: pass `{ rawBody: true }` to `NestFactory.create`.

Re-stringifying parsed JSON will silently change bytes (key order,
whitespace, escaping) and the body-hash check will fail.

## Protocol

The string-to-sign is the following five fields joined by `\n`:

```
<METHOD>\n
<path>\n
<unix-seconds>\n
<nonce-uuid-v4>\n
<sha256-hex(body)>   ← sha512-hex when signatureAlgorithm is 'sha512'
```

Signature = `HMAC-<algorithm>(secret, stringToSign)`, hex-encoded.
Default algorithm is SHA-256; opt into SHA-512 via `signatureAlgorithm: 'sha512'`
on both client and server.

The auth fields are JSON-encoded, base64-encoded, and transmitted as a
single `X-Signature` header. The server decodes, validates timestamp and
nonce, recomputes the signature, and constant-time compares.

Verification order is deliberate: cheap checks first (header presence,
format, timestamp, nonce read), secret lookup AFTER timestamp and nonce,
nonce stored ONLY after the signature verifies.

## Errors

All verification errors extend `HmacAuthError`. Each has a stable `code`
string and a recommended `httpStatus`:

| Class                   | code                | status |
| ----------------------- | ------------------- | ------ |
| `MissingHeaderError`    | `MISSING_HEADER`    | 401    |
| `InvalidFormatError`    | `INVALID_FORMAT`    | 400    |
| `ExpiredRequestError`   | `EXPIRED_REQUEST`   | 401    |
| `ReplayAttackError`     | `REPLAY_ATTACK`     | 401    |
| `UnknownClientError`    | `UNKNOWN_CLIENT`    | 401    |
| `InvalidSignatureError` | `INVALID_SIGNATURE` | 401    |
| `BodyHashMismatchError` | `BODY_HASH_MISMATCH`| 400    |
| `InternalAuthError`     | `INTERNAL_ERROR`    | 500    |

Use `err.toJSON()` to get a safe-to-send error body — secrets and raw
signatures never appear in messages.

## Security checklist

- Constant-time signature comparison (`crypto.timingSafeEqual` with strict
  pre-validation).
- Hex/base64 length and format check before `timingSafeEqual` to avoid
  exception-based length oracles.
- Verification order: cheap checks first, secret lookup AFTER timestamp +
  nonce, nonce stored ONLY after signature verifies.
- Nonces keyed per client (`clientId:nonce`) to prevent cross-client
  collisions.
- Secrets never appear in error messages, never in `toString` / `toJSON`.
- Cryptographically-strong nonces (`crypto.randomUUID`).
- Verifier never parses or re-serializes the request body — raw bytes only.

## Build & develop

```bash
npm install
npm run typecheck
npm run lint
npm test
npm run build      # produces dist/ (ESM + CJS + .d.ts per entry)
```

## License

MIT — see `LICENSE`.
