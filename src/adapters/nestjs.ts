/**
 * NestJS adapter for `@daxmadov/hmac-kit`.
 *
 * Provides:
 *   - `HmacAuthGuard` — a Nest `CanActivate` guard that verifies the
 *     signature on every incoming request. On success, it attaches the
 *     verified result as `request.hmac`. On failure, it throws an
 *     `HmacAuthError` subclass which the global filter (or framework
 *     default) maps to the appropriate HTTP status.
 *   - `createHmacAuthGuard(verifier)` — convenience factory that returns
 *     a guard class bound to a specific verifier instance, useful when
 *     you don't want to wire a Nest provider for the verifier.
 *
 * IMPORTANT — raw body:
 *   NestJS uses Express by default. You MUST enable raw-body capture so
 *   the verifier can hash the EXACT wire bytes:
 *
 *     const app = await NestFactory.create(AppModule, { rawBody: true });
 *
 *   With Fastify (`NestFactory.create<NestFastifyApplication>(...)`), pass
 *   `{ rawBody: true }` and the platform-fastify adapter will populate
 *   `request.rawBody` automatically.
 *
 * Usage:
 *
 *   // hmac.module.ts
 *   import { Module } from '@nestjs/common';
 *   import { SignatureVerifier, MemoryNonceStore } from '@daxmadov/hmac-kit/server';
 *   import { HMAC_VERIFIER, HmacAuthGuard } from '@daxmadov/hmac-kit/adapters/nestjs';
 *
 *   @Module({
 *     providers: [
 *       {
 *         provide: HMAC_VERIFIER,
 *         useFactory: () => new SignatureVerifier({ ... }),
 *       },
 *       HmacAuthGuard,
 *     ],
 *     exports: [HmacAuthGuard, HMAC_VERIFIER],
 *   })
 *   export class HmacModule {}
 *
 *   // controller.ts
 *   @UseGuards(HmacAuthGuard)
 *   @Post('/payments')
 *   handle(@Req() req) { return { clientId: req.hmac.clientId }; }
 */

import { HmacAuthError } from '../shared/errors.js';
import type { SignatureVerifier } from '../server/verifier.js';
import type { VerifyResult } from '../shared/types.js';

/**
 * Injection token for the verifier. Bind a `SignatureVerifier` instance
 * to this token in your module's providers. The guard reads it via Nest's
 * `@Inject(HMAC_VERIFIER)`.
 */
export const HMAC_VERIFIER = Symbol.for('@daxmadov/hmac-kit/verifier');

/**
 * Minimal shape of `ExecutionContext` we touch — kept local so we don't
 * pull `@nestjs/common` types in at runtime.
 */
interface NestExecutionContextLike {
  switchToHttp(): {
    getRequest<T = unknown>(): T;
    getResponse<T = unknown>(): T;
  };
}

interface NestRequestLike {
  method: string;
  url?: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  /** Express (`{ rawBody: true }`) or Fastify (`{ rawBody: true }`) sets this. */
  rawBody?: Buffer;
  /** Some Express middlewares put it here; we accept either. */
  body?: unknown;
  hmac?: VerifyResult;
}

/**
 * Reusable guard. Construct directly with a verifier, OR rely on Nest DI
 * by registering the verifier under the `HMAC_VERIFIER` token (see file
 * header for the module pattern).
 */
export class HmacAuthGuard {
  readonly #verifier: SignatureVerifier;

  constructor(verifier: SignatureVerifier) {
    if (!verifier) {
      throw new Error(
        'HmacAuthGuard: a SignatureVerifier instance is required. ' +
          'Bind one to the HMAC_VERIFIER token in your Nest module.',
      );
    }
    this.#verifier = verifier;
  }

  async canActivate(context: NestExecutionContextLike): Promise<boolean> {
    const req = context.switchToHttp().getRequest<NestRequestLike>();

    const headerKey = this.#verifier.headerName.toLowerCase();
    const authHeader = req.headers[headerKey];

    const path = req.originalUrl ?? req.url ?? '/';

    // The verifier throws `HmacAuthError` subclasses on failure; we let
    // them propagate so a global Nest `ExceptionFilter` can map them
    // to the right HTTP status. We don't throw `HttpException` here to
    // avoid pulling in `@nestjs/common` at runtime.
    const result = await this.#verifier.verify({
      authHeader,
      method: req.method,
      path,
      rawBody: req.rawBody,
    });
    req.hmac = result;
    return true;
  }
}

/**
 * Factory: returns a guard class pre-bound to a verifier instance,
 * suitable for `@UseGuards(createHmacAuthGuard(verifier))` without
 * needing a DI provider.
 *
 * Note: the returned value is the SAME guard for every call to the
 * factory with the same verifier — the class wraps a closure.
 */
export function createHmacAuthGuard(
  verifier: SignatureVerifier,
): HmacAuthGuard {
  return new HmacAuthGuard(verifier);
}

/**
 * Re-export for convenience: callers commonly want to catch this in a
 * Nest `ExceptionFilter`.
 */
export { HmacAuthError };
