// Path: zn-vault-sdk-node/test/http-client.test.ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Buffer } from 'node:buffer';
import https from 'node:https';
import { EventEmitter } from 'node:events';

// We test the chunk-accumulation logic in isolation by extracting it.
// The bug: `let data=''; data += chunk` decodes each Buffer chunk as UTF-8,
// corrupting non-ASCII bytes. The fix accumulates Buffer[] then concats.
import { accumulate } from '../src/http/body.js';
import { HttpClient, ZnVaultError, RateLimitError } from '../src/http/client.js';

describe('binary-safe body accumulation', () => {
  it('preserves arbitrary bytes (no UTF-8 corruption)', () => {
    // 0xFF 0xFE 0x00 are invalid/edge UTF-8 — would become U+FFFD if string-coerced.
    const chunks = [Buffer.from([0xff, 0xfe]), Buffer.from([0x00, 0x80])];
    const out = accumulate(chunks);
    expect(out.equals(Buffer.from([0xff, 0xfe, 0x00, 0x80]))).toBe(true);
  });

  it('reassembles a multi-byte UTF-8 char split across chunks', () => {
    // '€' = E2 82 AC; split the 3 bytes across two chunks.
    const chunks = [Buffer.from([0xe2, 0x82]), Buffer.from([0xac])];
    expect(accumulate(chunks).toString('utf8')).toBe('€');
  });
});

// ---------------------------------------------------------------------------
// RETRY-01: Idempotent-only retry on 5xx / network errors
// RETRY-02: Retry-After clamp to 60s
// ---------------------------------------------------------------------------

describe('idempotent-only retry (RETRY-01)', () => {
  let client: HttpClient;

  beforeEach(() => {
    client = new HttpClient({ baseUrl: 'https://localhost:9999', retries: 3, rejectUnauthorized: false });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('POST (non-idempotent): does NOT retry on 500 — attempted exactly once', async () => {
    const spy = vi
      .spyOn(client as unknown as { executeRequest: () => Promise<unknown> }, 'executeRequest')
      .mockRejectedValue(new ZnVaultError('boom', 500));

    await expect(client.post('/x', {})).rejects.toThrow(ZnVaultError);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('PATCH (non-idempotent): does NOT retry on 500 — attempted exactly once', async () => {
    const spy = vi
      .spyOn(client as unknown as { executeRequest: () => Promise<unknown> }, 'executeRequest')
      .mockRejectedValue(new ZnVaultError('boom', 500));

    await expect(client.patch('/x', {})).rejects.toThrow(ZnVaultError);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('GET (idempotent): retries on 500 — attempted retryAttempts+1 times', async () => {
    const spy = vi
      .spyOn(client as unknown as { executeRequest: () => Promise<unknown> }, 'executeRequest')
      .mockRejectedValue(new ZnVaultError('boom', 500));
    // Also mock sleep so the test is instant
    vi.spyOn(client as unknown as { sleep: (ms: number) => Promise<void> }, 'sleep').mockResolvedValue(undefined);

    await expect(client.get('/x')).rejects.toThrow(ZnVaultError);
    // retries=3 means 1 initial attempt + 3 retries = 4 total
    expect(spy).toHaveBeenCalledTimes(4);
  });

  it('PUT (idempotent): retries on 500', async () => {
    const spy = vi
      .spyOn(client as unknown as { executeRequest: () => Promise<unknown> }, 'executeRequest')
      .mockRejectedValue(new ZnVaultError('boom', 500));
    vi.spyOn(client as unknown as { sleep: (ms: number) => Promise<void> }, 'sleep').mockResolvedValue(undefined);

    await expect(client.put('/x', {})).rejects.toThrow(ZnVaultError);
    expect(spy).toHaveBeenCalledTimes(4);
  });

  it('DELETE (idempotent): retries on 500', async () => {
    const spy = vi
      .spyOn(client as unknown as { executeRequest: () => Promise<unknown> }, 'executeRequest')
      .mockRejectedValue(new ZnVaultError('boom', 500));
    vi.spyOn(client as unknown as { sleep: (ms: number) => Promise<void> }, 'sleep').mockResolvedValue(undefined);

    await expect(client.delete('/x')).rejects.toThrow(ZnVaultError);
    expect(spy).toHaveBeenCalledTimes(4);
  });

  it('POST (non-idempotent): does NOT retry on network error (statusCode 0)', async () => {
    const spy = vi
      .spyOn(client as unknown as { executeRequest: () => Promise<unknown> }, 'executeRequest')
      .mockRejectedValue(new ZnVaultError('Connection error: ECONNREFUSED', 0, 'CONNECTION_ERROR'));

    await expect(client.post('/x', {})).rejects.toThrow(ZnVaultError);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('GET (idempotent): retries on network error (statusCode 0)', async () => {
    const spy = vi
      .spyOn(client as unknown as { executeRequest: () => Promise<unknown> }, 'executeRequest')
      .mockRejectedValue(new ZnVaultError('Connection error: ECONNREFUSED', 0, 'CONNECTION_ERROR'));
    vi.spyOn(client as unknown as { sleep: (ms: number) => Promise<void> }, 'sleep').mockResolvedValue(undefined);

    await expect(client.get('/x')).rejects.toThrow(ZnVaultError);
    expect(spy).toHaveBeenCalledTimes(4);
  });
});

describe('Retry-After clamp (RETRY-02)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('clamps a huge Retry-After value to <= 60000ms', async () => {
    const client = new HttpClient({ baseUrl: 'https://localhost:9999', retries: 3, rejectUnauthorized: false });

    // First call throws RateLimitError with a huge retryAfter, second call succeeds
    const execSpy = vi
      .spyOn(client as unknown as { executeRequest: () => Promise<unknown> }, 'executeRequest')
      .mockRejectedValueOnce(new RateLimitError('rate limited', 999999))
      .mockResolvedValueOnce({ ok: true });

    const sleepSpy = vi
      .spyOn(client as unknown as { sleep: (ms: number) => Promise<void> }, 'sleep')
      .mockResolvedValue(undefined);

    await client.get('/x');

    expect(execSpy).toHaveBeenCalledTimes(2);
    expect(sleepSpy).toHaveBeenCalledTimes(1);
    const delayUsed = sleepSpy.mock.calls[0][0] as number;
    expect(delayUsed).toBeLessThanOrEqual(60000);
  });

  it('uses actual Retry-After * 1000 when it is <= 60000ms', async () => {
    const client = new HttpClient({ baseUrl: 'https://localhost:9999', retries: 3, rejectUnauthorized: false });

    const execSpy = vi
      .spyOn(client as unknown as { executeRequest: () => Promise<unknown> }, 'executeRequest')
      .mockRejectedValueOnce(new RateLimitError('rate limited', 30)) // 30s = 30000ms, within cap
      .mockResolvedValueOnce({ ok: true });

    const sleepSpy = vi
      .spyOn(client as unknown as { sleep: (ms: number) => Promise<void> }, 'sleep')
      .mockResolvedValue(undefined);

    await client.get('/x');

    expect(execSpy).toHaveBeenCalledTimes(2);
    expect(sleepSpy).toHaveBeenCalledTimes(1);
    const delayUsed = sleepSpy.mock.calls[0][0] as number;
    expect(delayUsed).toBe(30000);
  });

  it('POST still honors 429 (retries on RateLimitError) regardless of idempotency', async () => {
    const client = new HttpClient({ baseUrl: 'https://localhost:9999', retries: 3, rejectUnauthorized: false });

    const execSpy = vi
      .spyOn(client as unknown as { executeRequest: () => Promise<unknown> }, 'executeRequest')
      .mockRejectedValueOnce(new RateLimitError('rate limited', 1))
      .mockResolvedValueOnce({ ok: true });

    vi
      .spyOn(client as unknown as { sleep: (ms: number) => Promise<void> }, 'sleep')
      .mockResolvedValue(undefined);

    const result = await client.post('/x', {});
    expect(result).toEqual({ ok: true });
    expect(execSpy).toHaveBeenCalledTimes(2);
  });
});

// ---------------------------------------------------------------------------
// ROTATION-01: bind failure must still reschedule (no dead-stop)
// MANAGEDKEY-02: setTimeout delay must be clamped to <= 2^31-1 ms
// MANAGEDKEY-01: concurrent refreshManagedKey() calls share one in-flight bind
// ---------------------------------------------------------------------------

type ClientPrivate = {
  managedKeyState: {
    name: string;
    currentKey: string;
    nextRotationAt?: Date;
    graceExpiresAt?: Date;
    refreshBeforeExpiryMs: number;
    refreshTimer?: ReturnType<typeof setTimeout>;
    isRefreshing: boolean;
    onKeyRotated?: (newKey: string, oldKey: string) => void;
    onRotationError?: (error: Error) => void;
    refreshInFlight?: Promise<unknown>;
  };
  bindManagedKeyInternal: (name: string) => Promise<unknown>;
  scheduleManagedKeyRefresh: () => void;
  doManagedKeyRefresh: () => Promise<unknown>;
};

function makeManagedClient() {
  const client = new HttpClient({ baseUrl: 'https://localhost:9999', rejectUnauthorized: false });
  // Inject managed key state directly (avoids calling bindManagedKeyInternal in initManagedKey)
  (client as unknown as ClientPrivate).managedKeyState = {
    name: 'test-key',
    currentKey: 'znv_initial',
    refreshBeforeExpiryMs: 30_000,
    isRefreshing: false,
  };
  return client;
}

describe('ROTATION-01: bind failure reschedules (no dead-stop)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('scheduleManagedKeyRefresh is called even when bindManagedKeyInternal rejects', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));

    const client = makeManagedClient();
    const priv = client as unknown as ClientPrivate;

    // Stub bind to reject
    vi.spyOn(priv, 'bindManagedKeyInternal').mockRejectedValue(new Error('bind failed'));

    // Spy on scheduleManagedKeyRefresh
    const scheduleSpy = vi.spyOn(priv, 'scheduleManagedKeyRefresh');

    // doManagedKeyRefresh should reject (bind error propagates)
    await expect(priv.doManagedKeyRefresh()).rejects.toThrow('bind failed');

    // But scheduleManagedKeyRefresh must still have been called (failure-path reschedule)
    expect(scheduleSpy).toHaveBeenCalledTimes(1);
  });
});

describe('MANAGEDKEY-02: setTimeout delay clamped to <= 2^31-1 ms', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('schedules with delay <= 2_147_483_647 when nextRotationAt is 60 days out', () => {
    vi.useFakeTimers();
    const now = new Date('2026-01-01T00:00:00Z');
    vi.setSystemTime(now);

    const client = makeManagedClient();
    const priv = client as unknown as ClientPrivate;

    // 60 days in the future — well over 2^31-1 ms (~24.8 days)
    const sixtyDaysMs = 60 * 24 * 60 * 60 * 1000;
    priv.managedKeyState.nextRotationAt = new Date(now.getTime() + sixtyDaysMs);
    priv.managedKeyState.refreshBeforeExpiryMs = 0;

    const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout');

    priv.scheduleManagedKeyRefresh();

    // At least one setTimeout call should have a delay <= MAX
    const MAX_DELAY = 2_147_483_647;
    const delays = setTimeoutSpy.mock.calls.map((args) => args[1] as number);
    expect(delays.length).toBeGreaterThan(0);
    for (const d of delays) {
      expect(d).toBeLessThanOrEqual(MAX_DELAY);
    }
  });
});

describe('MANAGEDKEY-02b: chain-reschedule guard prevents premature refresh', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('clamped timer fires and reschedules (not refreshes) when Date.now() < targetAt', async () => {
    vi.useFakeTimers();
    const now = new Date('2026-01-01T00:00:00Z');
    vi.setSystemTime(now);

    const client = makeManagedClient();
    const priv = client as unknown as ClientPrivate;

    // 60 days in the future — true delay well over MAX_TIMER_DELAY (~24.8 days)
    const sixtyDaysMs = 60 * 24 * 60 * 60 * 1000;
    priv.managedKeyState.nextRotationAt = new Date(now.getTime() + sixtyDaysMs);
    priv.managedKeyState.refreshBeforeExpiryMs = 0;

    // Spy on bindManagedKeyInternal — must NOT be called during a clamped-timer fire
    const bindSpy = vi.spyOn(priv, 'bindManagedKeyInternal');

    const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout');

    // Start scheduling
    priv.scheduleManagedKeyRefresh();

    // After the first scheduleManagedKeyRefresh call, setTimeout was called once (clamped)
    const callsAfterFirst = setTimeoutSpy.mock.calls.length;
    expect(callsAfterFirst).toBeGreaterThanOrEqual(1);

    // Do NOT advance system time — wall clock stays at `now`, far before targetAt.
    // Advance fake timers by MAX_TIMER_DELAY so the clamped timer fires.
    await vi.advanceTimersByTimeAsync(2_147_483_647);

    // The guard `if (Date.now() < targetAt)` should have caused a re-call to
    // scheduleManagedKeyRefresh(), which in turn calls setTimeout again.
    const callsAfterFire = setTimeoutSpy.mock.calls.length;
    expect(callsAfterFire).toBeGreaterThan(callsAfterFirst);

    // bindManagedKeyInternal must NOT have been called — no premature refresh
    expect(bindSpy).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// TIMEOUT-01: Overall request deadline — wall-clock cap, not just idle-socket
// ---------------------------------------------------------------------------

describe('TIMEOUT-01: overall request deadline rejects with TIMEOUT', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('rejects with errorCode TIMEOUT when server never responds within timeout', async () => {
    vi.useFakeTimers();

    // Build a fake https.ClientRequest that never calls the response callback
    // and does NOT emit 'error' on destroy — so only the overall deadline
    // can settle the promise (not the error handler with CONNECTION_ERROR).
    class FakeRequest extends EventEmitter {
      destroyed = false;
      destroy() { this.destroyed = true; /* intentionally silent — deadline owns the rejection */ }
      write() { return true; }
      end() { return this; }
    }
    const fakeReq = new FakeRequest();

    vi.spyOn(https, 'request').mockImplementation(
      (_opts: unknown, _cb?: unknown) => fakeReq as unknown as ReturnType<typeof https.request>
    );

    // retries: 0 so there is no retry loop to advance through; the deadline
    // fires once and the promise rejects immediately.
    const client = new HttpClient({
      baseUrl: 'https://vault.example.com',
      timeout: 200,
      retries: 0,
      rejectUnauthorized: false,
    });

    // Attach a rejection handler immediately so no "unhandled rejection" fires
    // while we advance fake timers past the deadline.
    const promise = client.get<unknown>('/slow').catch((e: unknown) => e);

    // Advance fake time past the deadline — the overall deadline timer should fire.
    await vi.advanceTimersByTimeAsync(300);

    const result = await promise;
    expect(result).toMatchObject({ errorCode: 'TIMEOUT' });
    expect(result).toBeInstanceOf(ZnVaultError);
  });

  it('does NOT reject prematurely when response arrives before deadline', async () => {
    vi.useFakeTimers();

    // A fake request where the response arrives quickly (before the timeout).
    class FakeRequest extends EventEmitter {
      destroyed = false;
      destroy() { this.destroyed = true; }
      write() { return true; }
      end() {
        // Simulate an immediate 200 response with a JSON body.
        const res = new EventEmitter() as NodeJS.ReadableStream & EventEmitter & { statusCode: number; headers: Record<string, string> };
        res.statusCode = 200;
        res.headers = {};
        // Schedule response delivery in the next microtask so the caller
        // has time to register its handlers.
        Promise.resolve().then(() => {
          res.emit('data', Buffer.from(JSON.stringify({ ok: true })));
          res.emit('end');
        });
        // The callback passed to https.request receives the res object.
        // We stored it in the mock so we can invoke it here.
        this.emit('_response', res);
        return this;
      }
    }

    let capturedCallback: ((res: unknown) => void) | undefined;
    vi.spyOn(https, 'request').mockImplementation(
      (_opts: unknown, cb?: unknown) => {
        capturedCallback = cb as (res: unknown) => void;
        const req = new FakeRequest();
        req.on('_response', (res) => { capturedCallback?.(res); });
        return req as unknown as ReturnType<typeof https.request>;
      }
    );

    const client = new HttpClient({
      baseUrl: 'https://vault.example.com',
      timeout: 5000,
      rejectUnauthorized: false,
    });

    const promise = client.get<{ ok: boolean }>('/fast');

    // Advance just a little — response arrives, deadline must be cleared.
    await vi.advanceTimersByTimeAsync(10);

    const result = await promise;
    expect(result).toEqual({ ok: true });
  });
});

describe('MANAGEDKEY-01: concurrent refreshManagedKey() shares one in-flight bind', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('bindManagedKeyInternal called once; both callers get the same real response', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));

    const client = makeManagedClient();
    const priv = client as unknown as ClientPrivate;

    const realResponse = {
      id: 'key-123',
      key: 'znv_real_rotated',
      prefix: 'znv_real',
      name: 'test-key',
      expiresAt: '2026-02-01T00:00:00Z',
      gracePeriod: '7d',
      rotationMode: 'scheduled' as const,
      permissions: ['read:secrets'],
      nextRotationAt: '2026-02-01T00:00:00Z',
      graceExpiresAt: '2026-02-08T00:00:00Z',
    };

    // Stub bind: resolves after a tick
    const bindSpy = vi
      .spyOn(priv, 'bindManagedKeyInternal')
      .mockImplementation(() => Promise.resolve(realResponse));

    // Also stub scheduleManagedKeyRefresh to avoid timer side-effects
    vi.spyOn(priv, 'scheduleManagedKeyRefresh').mockReturnValue(undefined);

    // Two concurrent calls
    const [r1, r2] = await Promise.all([client.refreshManagedKey(), client.refreshManagedKey()]);

    // bindManagedKeyInternal must have been called exactly once
    expect(bindSpy).toHaveBeenCalledTimes(1);

    // Both results must be the same real object (not fabricated empty)
    expect(r1.id).toBe('key-123');
    expect(r2.id).toBe('key-123');
    expect(r1).toBe(r2); // same reference — shared in-flight promise
  });
});
