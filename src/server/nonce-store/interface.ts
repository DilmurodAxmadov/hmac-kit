/**
 * Pluggable storage for "have I seen this nonce already?" lookups.
 *
 * Implementation rules:
 *   - `set` MUST honor the TTL — entries below TTL must remain visible to
 *     `exists`. Otherwise the protocol's replay protection breaks.
 *   - `exists` MUST be safe to call concurrently from many requests.
 *   - Storage failures (network, etc.) should throw — the verifier will
 *     translate to `InternalAuthError` and refuse the request, which is
 *     the safe default. Better to fail closed than to admit a replay.
 *
 * Recommended TTL: at least 2× `timestampWindowSeconds`. The window
 * defines how far in the past a request may be; nonce records older
 * than that can be safely forgotten because timestamps will reject
 * the request first.
 */
export interface NonceStore {
  /**
   * Returns `true` if the key is present (i.e. nonce already used).
   * Implementations MAY return false for expired keys.
   */
  exists(key: string): Promise<boolean>;

  /**
   * Record the key with the given TTL (seconds). Subsequent `exists` calls
   * within the TTL must return `true`.
   *
   * NOTE: This primitive is NOT race-safe on its own. Two concurrent
   * requests with the same nonce that both observe `exists() === false`
   * will both reach `set()` and both succeed. Prefer `setIfAbsent` for
   * binding replay decisions — the verifier uses it when available.
   */
  set(key: string, ttlSeconds: number): Promise<void>;

  /**
   * Atomically record the key only if it is not already present.
   * Returns `true` if the entry was newly inserted, `false` if a live
   * entry already existed (i.e. a concurrent duplicate / replay).
   *
   * This is the SAFE primitive used by the verifier to bind its replay
   * decision: even if two identical requests race past the early
   * `exists()` heuristic, only one of them can win the `setIfAbsent`
   * race; the loser is treated as a replay.
   *
   * Optional for backward compatibility. Implementations SHOULD provide
   * it. Both `MemoryNonceStore` and `RedisNonceStore` do. Third-party
   * stores without this method fall back to the weaker `exists`+`set`
   * path, which admits a small race window under concurrency.
   */
  setIfAbsent?(key: string, ttlSeconds: number): Promise<boolean>;
}
