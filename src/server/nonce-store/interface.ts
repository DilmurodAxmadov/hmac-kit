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
   * NOTE: Callers must perform a check-then-set. Atomic CAS would be safer
   * against truly concurrent identical requests, but the cost (Redis
   * `SET NX EX` round-trip per request) is high. The verifier reads then
   * writes; the worst case race admits two duplicate requests in the same
   * millisecond — both with the SAME signature — which is functionally
   * equivalent to the single legitimate request being processed.
   * Implementations CAN provide stronger guarantees (see `RedisNonceStore`
   * for an `SETNX`-based variant if desired).
   */
  set(key: string, ttlSeconds: number): Promise<void>;
}
