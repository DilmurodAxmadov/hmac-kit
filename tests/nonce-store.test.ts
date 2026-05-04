import { describe, expect, it, afterEach } from 'vitest';
import { MemoryNonceStore } from '../src/server/nonce-store/memory.js';
import {
  RedisNonceStore,
  type RedisLikeClient,
} from '../src/server/nonce-store/redis.js';

describe('MemoryNonceStore', () => {
  const stores: MemoryNonceStore[] = [];
  afterEach(() => {
    while (stores.length) stores.pop()?.close();
  });

  it('exists returns false for unseen keys', async () => {
    const s = new MemoryNonceStore({ sweepIntervalMs: 0 });
    stores.push(s);
    expect(await s.exists('nope')).toBe(false);
  });

  it('records a key and reports it as existing', async () => {
    const s = new MemoryNonceStore({ sweepIntervalMs: 0 });
    stores.push(s);
    await s.set('k', 60);
    expect(await s.exists('k')).toBe(true);
  });

  it('expires keys past their TTL', async () => {
    const s = new MemoryNonceStore({ sweepIntervalMs: 0 });
    stores.push(s);
    await s.set('k', -1); // already expired
    expect(await s.exists('k')).toBe(false);
  });

  it('drops oldest entry when maxEntries exceeded', async () => {
    const s = new MemoryNonceStore({
      sweepIntervalMs: 0,
      maxEntries: 2,
    });
    stores.push(s);
    await s.set('a', 60);
    await s.set('b', 60);
    await s.set('c', 60); // evicts 'a'
    expect(await s.exists('a')).toBe(false);
    expect(await s.exists('b')).toBe(true);
    expect(await s.exists('c')).toBe(true);
    expect(s.size()).toBe(2);
  });

  it('close clears the timer and the map', async () => {
    const s = new MemoryNonceStore({ sweepIntervalMs: 0 });
    await s.set('k', 60);
    s.close();
    expect(s.size()).toBe(0);
  });
});

describe('RedisNonceStore', () => {
  function makeClient(): RedisLikeClient & {
    calls: { name: string; args: unknown[] }[];
    storage: Map<string, number>;
  } {
    const storage = new Map<string, number>();
    const calls: { name: string; args: unknown[] }[] = [];
    return {
      storage,
      calls,
      async exists(key: string): Promise<number> {
        calls.push({ name: 'exists', args: [key] });
        const expiresAt = storage.get(key);
        if (expiresAt === undefined) return 0;
        if (expiresAt <= Date.now()) {
          storage.delete(key);
          return 0;
        }
        return 1;
      },
      async set(
        key: string,
        _value: string,
        _ex: 'EX',
        ttl: number,
        nx?: 'NX',
      ): Promise<'OK' | null> {
        calls.push({ name: 'set', args: [key, _value, _ex, ttl, nx] });
        if (nx === 'NX' && storage.has(key)) return null;
        storage.set(key, Date.now() + ttl * 1000);
        return 'OK';
      },
    };
  }

  it('throws if no client is provided', () => {
    expect(
      () =>
        new RedisNonceStore({
          client: undefined as unknown as RedisLikeClient,
        }),
    ).toThrow(/client/);
  });

  it('exists is false for missing keys', async () => {
    const client = makeClient();
    const s = new RedisNonceStore({ client });
    expect(await s.exists('nope')).toBe(false);
  });

  it('round-trips set + exists with the configured prefix', async () => {
    const client = makeClient();
    const s = new RedisNonceStore({ client, keyPrefix: 'p:' });
    await s.set('k', 60);
    expect(await s.exists('k')).toBe(true);
    expect(client.storage.has('p:k')).toBe(true);
  });

  it('uses NX when atomic=true (default)', async () => {
    const client = makeClient();
    const s = new RedisNonceStore({ client });
    await s.set('k', 60);
    const setCall = client.calls.find((c) => c.name === 'set');
    expect(setCall?.args[4]).toBe('NX');
  });

  it('omits NX when atomic=false', async () => {
    const client = makeClient();
    const s = new RedisNonceStore({ client, atomic: false });
    await s.set('k', 60);
    const setCall = client.calls.find((c) => c.name === 'set');
    expect(setCall?.args[4]).toBeUndefined();
  });
});
