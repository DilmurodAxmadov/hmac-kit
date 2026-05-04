/**
 * Express adapter for `@daxmadov/hmac-kit`.
 *
 * Provides:
 *   - `createHmacMiddleware(verifier, options?)` — Express middleware that
 *     verifies the signature on every incoming request and attaches the
 *     verified `clientId` (+ timestamp / nonce) to the request object.
 *   - `rawBodySaver` — `express.json()` `verify` callback that stashes the
 *     raw body bytes on `req.rawBody` so the verifier can hash them. JSON
 *     re-serialization would silently change bytes and break the body hash;
 *     this is the canonical fix.
 *
 * Usage:
 *
 *   import express from 'express';
 *   import { SignatureVerifier, MemoryNonceStore } from '@daxmadov/hmac-kit/server';
 *   import {
 *     createHmacMiddleware,
 *     rawBodySaver,
 *   } from '@daxmadov/hmac-kit/adapters/express';
 *
 *   const verifier = new SignatureVerifier({
 *     getSecret: async (id) => process.env.SHARED_SECRET ?? null,
 *     nonceStore: new MemoryNonceStore(),
 *   });
 *
 *   const app = express();
 *   app.use(express.json({ verify: rawBodySaver }));
 *   app.use(createHmacMiddleware(verifier));
 *
 *   app.post('/api/payments', (req, res) => {
 *     // req.hmac.clientId is set by the middleware
 *     res.json({ ok: true, clientId: req.hmac.clientId });
 *   });
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { HmacAuthError } from '../shared/errors.js';
import type { SignatureVerifier } from '../server/verifier.js';
import type { VerifyResult } from '../shared/types.js';

/**
 * Subset of the Express `Request` object the middleware actually touches.
 * Defining it locally means we don't need a hard dependency on `@types/express`
 * at runtime, while consumers still get the augmentation via module
 * declaration merging (see bottom of this file).
 */
interface ExpressRequestLike extends IncomingMessage {
  method: string;
  /** Set by Express. */
  originalUrl?: string;
  /** Set by Express. */
  url?: string;
  /** Set by `rawBodySaver`. */
  rawBody?: Buffer;
  /** Set by the middleware on success. */
  hmac?: VerifyResult;
}

interface ExpressResponseLike extends ServerResponse {
  status(code: number): ExpressResponseLike;
  json(body: unknown): ExpressResponseLike;
}

type NextFunction = (err?: unknown) => void;

export interface CreateHmacMiddlewareOptions {
  /**
   * If `true` (default), the middleware sends a JSON error response on
   * verification failure. If `false`, the middleware calls `next(err)` so
   * the app's error-handling middleware can take over.
   */
  respondOnError?: boolean;
  /**
   * Property name on the request object where the verified result is
   * attached. Default: `'hmac'`. Set to a custom name to avoid colliding
   * with other middlewares.
   */
  attachAs?: string;
}

/**
 * `express.json({ verify })` callback that saves the raw body bytes on
 * `req.rawBody`. Required so the verifier can hash exactly the bytes the
 * client signed. Without this, `req.body` is the parsed object and
 * re-stringifying it produces different bytes.
 */
export function rawBodySaver(
  req: IncomingMessage & { rawBody?: Buffer },
  _res: ServerResponse,
  buf: Buffer,
): void {
  if (buf && buf.length > 0) {
    req.rawBody = Buffer.from(buf);
  }
}

/**
 * Build an Express middleware from a `SignatureVerifier`.
 */
export function createHmacMiddleware(
  verifier: SignatureVerifier,
  options: CreateHmacMiddlewareOptions = {},
): (
  req: ExpressRequestLike,
  res: ExpressResponseLike,
  next: NextFunction,
) => void {
  const respondOnError = options.respondOnError ?? true;
  const attachAs = options.attachAs ?? 'hmac';

  return function hmacMiddleware(
    req: ExpressRequestLike,
    res: ExpressResponseLike,
    next: NextFunction,
  ): void {
    const headerName = verifier.headerName;
    const headerKey = headerName.toLowerCase();
    const authHeader = req.headers[headerKey] as
      | string
      | string[]
      | undefined;

    // Express normalizes the path on `req.path`, but that's a getter we
    // can't rely on without `@types/express`. `originalUrl` (preferred) or
    // `url` is the verbatim request target — same as the client signed.
    const path = req.originalUrl ?? req.url ?? '/';

    verifier
      .verify({
        authHeader,
        method: req.method,
        path,
        rawBody: req.rawBody,
      })
      .then((result) => {
        (req as unknown as Record<string, unknown>)[attachAs] = result;
        next();
      })
      .catch((err: unknown) => {
        if (respondOnError && err instanceof HmacAuthError) {
          res.status(err.httpStatus).json(err.toJSON());
          return;
        }
        next(err);
      });
  };
}

/**
 * Augment Express `Request` so consumers using `@types/express` get
 * autocomplete for `req.hmac` and `req.rawBody`.
 *
 * This is purely a type-level addition — no runtime impact.
 */
declare module 'express-serve-static-core' {
  interface Request {
    rawBody?: Buffer;
    hmac?: VerifyResult;
  }
}
