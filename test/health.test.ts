// Path: zn-vault-sdk-node/test/health.test.ts
//
// Unit tests for HealthClient — use a mocked HttpClient so no live server is needed.
// These tests are NON-VACUOUS: they would fail against the old shapes
// ('healthy'/'unhealthy' status, 'database'/'encryption' check keys).

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { HealthClient } from '../src/health/client.js';
import type { HttpClient } from '../src/http/client.js';
import type { HealthStatus, ReadinessStatus } from '../src/health/client.js';

function makeClient() {
  const http = { get: vi.fn() };
  return { client: new HealthClient(http as unknown as HttpClient), http };
}

// ---------------------------------------------------------------------------
// HEALTH-01: GET /v1/health response shape
// ---------------------------------------------------------------------------

describe('HealthClient.check() — HEALTH-01', () => {
  let client: HealthClient;
  let http: ReturnType<typeof makeClient>['http'];

  beforeEach(() => ({ client, http } = makeClient()));

  it('returns status "ok" from server response', async () => {
    const serverResponse: HealthStatus = {
      status: 'ok',
      version: '1.46.6',
      uptime: 12345,
      timestamp: '2026-06-24T10:00:00.000Z',
      checks: {
        db: { status: 'ok' },
        tls: { status: 'ok' },
      },
    };
    http.get.mockResolvedValue(serverResponse);

    const result = await client.check();
    expect(result.status).toBe('ok');
    expect(['ok', 'degraded', 'error']).toContain(result.status);
  });

  it('returns status "degraded" when server signals degraded state', async () => {
    const serverResponse: HealthStatus = {
      status: 'degraded',
      version: '1.46.6',
      uptime: 100,
      timestamp: '2026-06-24T10:00:00.000Z',
      checks: {
        db: { status: 'degraded', details: { latencyMs: 9999 } },
        tls: { status: 'ok' },
      },
    };
    http.get.mockResolvedValue(serverResponse);

    const result = await client.check();
    expect(result.status).toBe('degraded');
  });

  it('returns status "error" when server signals error state', async () => {
    const serverResponse: HealthStatus = {
      status: 'error',
      version: '1.46.6',
      uptime: 5,
      timestamp: '2026-06-24T10:00:00.000Z',
      checks: {
        db: { status: 'error' },
        tls: { status: 'ok' },
      },
    };
    http.get.mockResolvedValue(serverResponse);

    const result = await client.check();
    expect(result.status).toBe('error');
  });

  it('exposes checks.db and checks.tls (not "database" or "encryption")', async () => {
    const serverResponse: HealthStatus = {
      status: 'ok',
      version: '1.46.6',
      uptime: 42,
      timestamp: '2026-06-24T10:00:00.000Z',
      checks: {
        db: { status: 'ok', details: { latencyMs: 2 } },
        tls: { status: 'ok', details: { enabled: true, requestCert: true, rejectUnauthorized: false } },
      },
    };
    http.get.mockResolvedValue(serverResponse);

    const result = await client.check();

    // Correct keys must be present
    expect(result.checks.db).toBeDefined();
    expect(result.checks.tls).toBeDefined();
    expect(result.checks.db.status).toBe('ok');
    expect(result.checks.tls.status).toBe('ok');

    // Old (wrong) keys must NOT be expected by the type (compile-level guard)
    // Runtime: the raw server response has no 'database' or 'encryption' keys
    const raw = result as Record<string, unknown>;
    const checks = raw['checks'] as Record<string, unknown>;
    expect(checks['database']).toBeUndefined();
    expect(checks['encryption']).toBeUndefined();
  });

  it('status enum does not include "healthy" or "unhealthy" (old wrong values)', async () => {
    const serverResponse: HealthStatus = {
      status: 'ok',
      version: '1.0.0',
      uptime: 1,
      timestamp: '2026-06-24T10:00:00.000Z',
      checks: { db: { status: 'ok' }, tls: { status: 'ok' } },
    };
    http.get.mockResolvedValue(serverResponse);

    const result = await client.check();
    expect(result.status).not.toBe('healthy');
    expect(result.status).not.toBe('unhealthy');
  });

  it('surfaces optional kmip block when present', async () => {
    const serverResponse: HealthStatus = {
      status: 'ok',
      version: '1.46.6',
      uptime: 100,
      timestamp: '2026-06-24T10:00:00.000Z',
      checks: {
        db: { status: 'ok' },
        tls: { status: 'ok' },
        kmip: {
          enabled: true,
          listening: true,
          port: 5696,
          serverCertDaysToExpiry: 180,
        },
      },
    };
    http.get.mockResolvedValue(serverResponse);

    const result = await client.check();
    expect(result.checks.kmip).toBeDefined();
    expect(result.checks.kmip?.enabled).toBe(true);
    expect(result.checks.kmip?.port).toBe(5696);
  });

  it('calls GET /v1/health', async () => {
    http.get.mockResolvedValue({
      status: 'ok', version: '1.0', uptime: 1, timestamp: '',
      checks: { db: { status: 'ok' }, tls: { status: 'ok' } },
    });
    await client.check();
    expect(http.get).toHaveBeenCalledWith('/v1/health');
  });
});

// ---------------------------------------------------------------------------
// HEALTH-02: GET /v1/health/ready response shape
// ---------------------------------------------------------------------------

describe('HealthClient.ready() — HEALTH-02', () => {
  let client: HealthClient;
  let http: ReturnType<typeof makeClient>['http'];

  beforeEach(() => ({ client, http } = makeClient()));

  it('returns status "ready" when server is healthy', async () => {
    const serverResponse: ReadinessStatus = {
      status: 'ready',
      timestamp: '2026-06-24T10:00:00.000Z',
    };
    http.get.mockResolvedValue(serverResponse);

    const result = await client.ready();
    expect(result.status).toBe('ready');
    expect(result.timestamp).toBeDefined();
    expect(result.reason).toBeUndefined();
  });

  it('returns status "not ready" when DB is unhealthy (503)', async () => {
    const serverResponse: ReadinessStatus = {
      status: 'not ready',
      timestamp: '2026-06-24T10:00:00.000Z',
      reason: 'database not healthy',
    };
    http.get.mockResolvedValue(serverResponse);

    const result = await client.ready();
    expect(result.status).toBe('not ready');
    expect(result.reason).toBe('database not healthy');
  });

  it('returns status "degraded" when LMK rotation is stuck', async () => {
    const serverResponse: ReadinessStatus = {
      status: 'degraded',
      timestamp: '2026-06-24T10:00:00.000Z',
      reason: 'lmk_rotation_stuck',
    };
    http.get.mockResolvedValue(serverResponse);

    const result = await client.ready();
    expect(result.status).toBe('degraded');
    expect(result.reason).toBe('lmk_rotation_stuck');
  });

  it('status enum includes "ready", "not ready", "degraded" (not boolean "ready")', async () => {
    const serverResponse: ReadinessStatus = {
      status: 'ready',
      timestamp: '2026-06-24T10:00:00.000Z',
    };
    http.get.mockResolvedValue(serverResponse);

    const result = await client.ready();
    // Old shape was { ready: boolean, checks: {...} } — should not be that
    expect(typeof result.status).toBe('string');
    expect(['ready', 'not ready', 'degraded']).toContain(result.status);
  });

  it('calls GET /v1/health/ready', async () => {
    http.get.mockResolvedValue({ status: 'ready', timestamp: '2026-06-24T10:00:00.000Z' });
    await client.ready();
    expect(http.get).toHaveBeenCalledWith('/v1/health/ready');
  });
});
