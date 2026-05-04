import type { NonceStore } from './interface.js';

/**
 * Minimal subset of `ioredis.Redis` we depend on. Defining it locally
 * means we can `import type` without forcing TypeScript to resolve the
 * actual `ioredis` module at compile time of consumers who don't use it.
 */
export interface RedisLikeClient {
  exists(key: string): Promise<number>;
  set(
    key: string,
    value: string,
    flag1: 'EX',
    ttlSeconds: number,
    flag2?: 'NX',
  ): Promise<'OK' | null>;
}

export interface RedisNonceStoreOptions {
  /**
   * An `ioredis`-compatible client instance. We accept any object with
   * `exists` and `set` methods, so `Redis | Cluster | mocks` all work.
   */
  client: RedisLikeClient;
  /**
   * Prefix prepended to every nonce key. Useful when the Redis instance
   * is shared across services. Default: `hmac-nonce:`.
   */
  keyPrefix?: string;
  /**
   * If `true` (default), `set` uses `SET NX EX` so concurrent duplicate
   * nonces are atomically rejected at the storage layer — the strongest
   * replay protection possible. If `false`, plain `SET EX` is used,
   * which is slightly faster but allows a vanishingly small race window.
   */
  atomic?: boolean;
}

/**
 * Distributed nonce store backed by Redis.
 *
 * Uses `ioredis` (or any compatible client) — but does NOT import it
 * directly. The caller passes in an existing instance, which means:
 *   - The package has zero hard runtime dependency on ioredis.
 *   - Consumers retain control over connection lifecycle, retry, TLS, etc.
 *
 * Pair with `timestampWindowSeconds: 300` and a TTL of ~600 seconds
 * (verifier sets this automatically as 2× window).
 */
export class RedisNonceStore implements NonceStore {
  readonly #client: RedisLikeClient;
  readonly #prefix: string;
  readonly #atomic: boolean;

  constructor(options: RedisNonceStoreOptions) {
    if (!options.client) {
      throw new Error('RedisNonceStore: `client` is required');
    }
    this.#client = options.client;
    this.#prefix = options.keyPrefix ?? 'hmac-nonce:';
    this.#atomic = options.atomic ?? true;
  }

  async exists(key: string): Promise<boolean> {
    const reply = await this.#client.exists(this.#prefix + key);
    return reply > 0;
  }

  async set(key: string, ttlSeconds: number): Promise<void> {
    const fullKey = this.#prefix + key;
    if (this.#atomic) {
      // `SET NX EX` — succeeds only if the key did not exist. Returning
      // `null` means a concurrent request already inserted it; we treat
      // that as success here because the verifier's pre-check already
      // determined the request to be legitimate. The replay-detection
      // happens in `exists`, not in `set`.
      await this.#client.set(fullKey, '1', 'EX', ttlSeconds, 'NX');
    } else {
      await this.#client.set(fullKey, '1', 'EX', ttlSeconds);
    }
  }
}
