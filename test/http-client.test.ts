// Path: zn-vault-sdk-node/test/http-client.test.ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Buffer } from 'node:buffer';

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
