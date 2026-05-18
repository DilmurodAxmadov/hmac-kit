import type { NonceStore } from './interface.js';

/**
 * In-memory nonce store with TTL eviction.
 *
 * SCOPE: This is suitable for:
 *   - Single-process services
 *   - Tests
 *   - Development
 *
 * NOT suitable for:
 *   - Horizontally scaled apps (each replica has its own memory) —
 *     a request signed for replica A could be replayed against replica B.
 *   - Workloads with high nonce volume + long windows — `Map` grows
 *     unbounded between sweeps. The default sweep interval is 60s.
 *
 * For production multi-replica deployments, use `RedisNonceStore`.
 */
export interface MemoryNonceStoreOptions {
  /**
   * How often to scan the map and drop expired entries, in milliseconds.
   * Default: 60_000 (1 minute). Lower → more CPU, less memory.
   */
  sweepIntervalMs?: number;
  /**
   * Cap on stored entries. When exceeded, the oldest entries are evicted
   * even if not yet expired. This is a safety valve against unbounded
   * growth from buggy clients. Default: 100_000.
   */
  maxEntries?: number;
}

export class MemoryNonceStore implements NonceStore {
  readonly #map = new Map<string, number /* expiresAtMs */>();
  readonly #maxEntries: number;
  #timer: NodeJS.Timeout | null = null;

  constructor(options: MemoryNonceStoreOptions = {}) {
    this.#maxEntries = options.maxEntries ?? 100_000;
    const interval = options.sweepIntervalMs ?? 60_000;
    if (interval > 0) {
      this.#timer = setInterval(() => this.#sweep(), interval);
      // `unref()` so this timer never blocks process exit. Without it, a
      // CLI app that creates a verifier would hang waiting for the
      // interval. The map itself is cleared on process exit anyway.
      this.#timer.unref?.();
    }
  }

  async exists(key: string): Promise<boolean> {
    const expiresAt = this.#map.get(key);
    if (expiresAt === undefined) return false;
    if (expiresAt <= Date.now()) {
      // Expired — clean up lazily so we don't accidentally treat it as a hit.
      this.#map.delete(key);
      return false;
    }
    return true;
  }

  async set(key: string, ttlSeconds: number): Promise<void> {
    this.#insert(key, ttlSeconds);
  }

  /**
   * Atomic check-and-insert. No `await` between the read and the write —
   * so on a single event loop, no other caller can interleave between
   * `Map.get` and `Map.set` here. This is what gives us race-safe replay
   * protection. Returns `true` if the key was newly inserted, `false` if
   * a non-expired entry already existed.
   */
  async setIfAbsent(key: string, ttlSeconds: number): Promise<boolean> {
    const existing = this.#map.get(key);
    if (existing !== undefined && existing > Date.now()) {
      return false;
    }
    this.#insert(key, ttlSeconds);
    return true;
  }

  #insert(key: string, ttlSeconds: number): void {
    if (this.#map.size >= this.#maxEntries) {
      // Drop the oldest single entry (Map preserves insertion order).
      const oldest = this.#map.keys().next().value;
      if (oldest !== undefined) this.#map.delete(oldest);
    }
    this.#map.set(key, Date.now() + ttlSeconds * 1000);
  }

  /** Manual eviction sweep. Exposed for tests. */
  #sweep(): void {
    const now = Date.now();
    for (const [key, expiresAt] of this.#map.entries()) {
      if (expiresAt <= now) this.#map.delete(key);
    }
  }

  /**
   * Stop the background sweep timer. Call this when your app is shutting
   * down or in tests, to avoid leaking timers across test runs.
   */
  close(): void {
    if (this.#timer) {
      clearInterval(this.#timer);
      this.#timer = null;
    }
    this.#map.clear();
  }

  /** For tests only. */
  size(): number {
    return this.#map.size;
  }
}
