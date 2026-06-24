// Path: zn-vault-sdk-node/test/audit.test.ts

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { AuditClient } from '../src/audit/client.js';
import type { HttpClient } from '../src/http/client.js';

function makeClient() {
  const http = { post: vi.fn(), get: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() };
  return { client: new AuditClient(http as unknown as HttpClient), http };
}

describe('AuditClient (mocked HTTP)', () => {
  let client: AuditClient;
  let http: ReturnType<typeof makeClient>['http'];
  beforeEach(() => ({ client, http } = makeClient()));

  // AUDIT-01: list() builds snake_case query params
  it('list sends snake_case query params (client_cn, start_date, end_date)', async () => {
    const mockResponse = {
      items: [],
      pagination: { total: 0, limit: 50, offset: 0, hasMore: false },
    };
    http.get.mockResolvedValue(mockResponse);

    await client.list({
      clientCn: 'acme/admin',
      action: 'SECRET_READ',
      resource: '/v1/secrets/abc',
      startDate: '2026-01-01T00:00:00Z',
      endDate: '2026-01-31T23:59:59Z',
      limit: 100,
      offset: 0,
    });

    // Must use snake_case param names on the wire
    const callArg: string = http.get.mock.calls[0][0] as string;
    expect(callArg).toContain('client_cn=acme%2Fadmin');
    expect(callArg).toContain('start_date=');
    expect(callArg).toContain('end_date=');
    expect(callArg).toContain('action=SECRET_READ');
    expect(callArg).toContain('resource=');
    expect(callArg).toContain('limit=100');
    // Must NOT use camelCase param names
    expect(callArg).not.toContain('userId=');
    expect(callArg).not.toContain('resourceType=');
    expect(callArg).not.toContain('startDate=');
    expect(callArg).not.toContain('endDate=');
  });

  // AUDIT-02: list() returns items + pagination (no stats — stats are via getStats())
  it('list returns items and pagination from server response (no stats field)', async () => {
    const mockEntry = {
      id: 'a1b2c3',
      timestamp: '2026-01-15T10:00:00Z',
      action: 'SECRET_READ',
      resource: '/v1/secrets/foo',
      actor: 'acme/admin',
      clientCert: 'acme/admin',
      result: 'success' as const,
      ip: '192.168.1.1',
      metadata: null,
    };
    const mockResponse = {
      items: [mockEntry],
      pagination: { total: 1, limit: 50, offset: 0, hasMore: false },
    };
    http.get.mockResolvedValue(mockResponse);

    const result = await client.list();
    expect(result.items).toHaveLength(1);
    expect(result.items[0].id).toBe('a1b2c3');
    expect(result.items[0].actor).toBe('acme/admin');
    expect(result.items[0].result).toBe('success');
    expect(result.pagination.total).toBe(1);
    expect(result.pagination.hasMore).toBe(false);
    // stats is NOT part of the list response — use getStats() for stats
    expect((result as Record<string, unknown>).stats).toBeUndefined();
  });

  // EXPORT-01: exportLogs() returns bare raw-shape array and sends format=json in query
  it('exportLogs returns the bare raw array and sends format=json query param', async () => {
    const mockArray = [
      {
        id: 1,
        ts: '2026-01-15T10:00:00Z',
        client_cn: 'acme/admin',
        action: 'SECRET_CREATE',
        resource: '/v1/secrets/bar',
        result: 'success',
        ip: '10.0.0.1',
      },
    ];
    // Server returns a bare array of raw (snake_case) rows
    http.get.mockResolvedValue(mockArray);

    const result = await client.exportLogs({ format: 'json' });

    // format=json must reach the query string
    const callArg: string = http.get.mock.calls[0][0] as string;
    expect(callArg).toContain('format=json');

    // Result is a bare array with the raw snake_case shape
    expect(Array.isArray(result)).toBe(true);
    expect(result).toHaveLength(1);
    expect(result[0].ts).toBe('2026-01-15T10:00:00Z');
    expect(result[0].client_cn).toBe('acme/admin');
    expect(result[0].result).toBe('success');
  });

  // AUDIT-03: getStats() hits /v1/audit/stats and returns correct shape
  it('getStats sends GET /v1/audit/stats and returns stats shape', async () => {
    const mockStats = {
      total: 500,
      successCount: 450,
      failureCount: 50,
      uniqueUsers: 10,
      successRate: 90,
      topActors: [{ actor: 'acme/admin', count: 200 }],
      topActions: [{ action: 'SECRET_READ', count: 300 }],
      recentFailures: [],
    };
    http.get.mockResolvedValue(mockStats);

    const result = await client.getStats();
    expect(http.get).toHaveBeenCalledWith('/v1/audit/stats');
    expect(result.total).toBe(500);
    expect(result.successCount).toBe(450);
    expect(result.failureCount).toBe(50);
    expect(result.uniqueUsers).toBe(10);
    expect(result.successRate).toBe(90);
    expect(result.topActors).toHaveLength(1);
  });

  // AUDIT-04: verify() returns correct shape (valid, errors, checkedEntries, lastVerified)
  it('verify returns the server shape (valid, errors, checkedEntries, lastVerified)', async () => {
    const mockVerify = {
      valid: true,
      errors: [],
      checkedEntries: 1000,
      lastVerified: '2026-01-15T10:00:00Z',
    };
    http.get.mockResolvedValue(mockVerify);

    const result = await client.verify();
    expect(http.get).toHaveBeenCalledWith('/v1/audit/verify');
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.checkedEntries).toBe(1000);
    expect(result.lastVerified).toBe('2026-01-15T10:00:00Z');
  });

  // CONTRACT-01: get(id) method does not exist
  it('AuditClient has no get(id) method', () => {
    expect(typeof (client as unknown as Record<string, unknown>)['get']).not.toBe('function');
  });
});
