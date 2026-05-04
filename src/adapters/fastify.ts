/**
 * Fastify plugin for `@daxmadov/hmac-kit`.
 *
 * Registers an `onRequest`/`preValidation` hook that:
 *   1. Captures the raw body bytes (Fastify parses JSON eagerly, so we
 *      must intercept before parsing — done via `addContentTypeParser`).
 *   2. Verifies the HMAC signature.
 *   3. On success, attaches the verified result to `request.hmac`.
 *   4. On failure, sends an error response (or rethrows for the app's
 *      error handler — controlled via `respondOnError`).
 *
 * Usage:
 *
 *   import Fastify from 'fastify';
 *   import { SignatureVerifier, MemoryNonceStore } from '@daxmadov/hmac-kit/server';
 *   import { hmacAuthPlugin } from '@daxmadov/hmac-kit/adapters/fastify';
 *
 *   const verifier = new SignatureVerifier({ ... });
 *   const app = Fastify();
 *   await app.register(hmacAuthPlugin, { verifier });
 *
 *   app.post('/api/payments', async (req) => {
 *     return { clientId: req.hmac?.clientId };
 *   });
 */

import { HmacAuthError } from '../shared/errors.js';
import type { SignatureVerifier } from '../server/verifier.js';
import type { VerifyResult } from '../shared/types.js';

/**
 * Minimal subset of Fastify types we use. Defined locally so the package
 * has no hard runtime dependency on `fastify` — consumers bring their own.
 */
interface FastifyRequestLike {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  rawBody?: Buffer;
  hmac?: VerifyResult;
}

interface FastifyReplyLike {
  code(status: number): FastifyReplyLike;
  send(payload: unknown): FastifyReplyLike;
}

interface FastifyInstanceLike {
  addContentTypeParser(
    contentType: string | string[] | RegExp,
    options: { parseAs: 'buffer' | 'string' },
    parser: (
      req: FastifyRequestLike,
      body: Buffer | string,
      done: (err: Error | null, body?: unknown) => void,
    ) => void,
  ): void;
  addHook(
    name: 'preValidation',
    handler: (
      req: FastifyRequestLike,
      reply: FastifyReplyLike,
    ) => Promise<void>,
  ): void;
}

type FastifyDoneFn = (err?: Error) => void;

export interface HmacAuthPluginOptions {
  verifier: SignatureVerifier;
  /**
   * If `true` (default), the plugin sends a JSON error response on
   * verification failure. If `false`, the error is rethrown so Fastify's
   * `setErrorHandler` can handle it.
   */
  respondOnError?: boolean;
}

/**
 * Fastify plugin. Use with `app.register(hmacAuthPlugin, { verifier })`.
 *
 * NOTE: Fastify will parse bodies BEFORE hooks run unless we register a
 * content type parser. We register one for `application/json` and
 * `application/octet-stream` that buffers the raw bytes, then re-parses
 * for the route handler. This way `req.rawBody` is the EXACT wire bytes.
 */
export function hmacAuthPlugin(
  app: FastifyInstanceLike,
  options: HmacAuthPluginOptions,
  done: FastifyDoneFn,
): void {
  if (!options || !options.verifier) {
    done(new Error('hmacAuthPlugin: `verifier` option is required'));
    return;
  }
  const verifier = options.verifier;
  const respondOnError = options.respondOnError ?? true;

  // Replace the default JSON parser with one that stashes raw bytes first.
  app.addContentTypeParser(
    'application/json',
    { parseAs: 'buffer' },
    (req, body, parserDone) => {
      const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
      req.rawBody = buf;
      if (buf.length === 0) {
        parserDone(null, undefined);
        return;
      }
      try {
        parserDone(null, JSON.parse(buf.toString('utf8')));
      } catch (err) {
        parserDone(err as Error);
      }
    },
  );

  // Pass-through buffer parser for non-JSON; verifier still needs raw bytes.
  app.addContentTypeParser(
    'application/octet-stream',
    { parseAs: 'buffer' },
    (req, body, parserDone) => {
      req.rawBody = Buffer.isBuffer(body) ? body : Buffer.from(body);
      parserDone(null, req.rawBody);
    },
  );

  app.addHook('preValidation', async (req, reply) => {
    try {
      const result = await verifier.verify({
        authHeader: req.headers[verifier.headerName.toLowerCase()],
        method: req.method,
        path: req.url,
        rawBody: req.rawBody,
      });
      req.hmac = result;
    } catch (err) {
      if (respondOnError && err instanceof HmacAuthError) {
        await reply.code(err.httpStatus).send(err.toJSON());
        return;
      }
      throw err;
    }
  });

  done();
}

// Mark the plugin as Fastify-encapsulation-aware. Fastify checks this
// symbol to decide whether to skip its plugin sandbox. We export a
// version that DOES skip sandboxing because we modify request decorators.
// The symbol name is part of Fastify's public contract; we duplicate it
// here so we don't pull `fastify` in at import time.
(hmacAuthPlugin as unknown as { [k: string]: unknown })[
  Symbol.for('skip-override') as unknown as string
] = true;

// Consumers who want autocomplete on `request.hmac` and `request.rawBody`
// can add the following to a .d.ts in their project:
//
//   import 'fastify';
//   declare module 'fastify' {
//     interface FastifyRequest {
//       rawBody?: Buffer;
//       hmac?: import('@daxmadov/hmac-kit/server').VerifyResult;
//     }
//   }
