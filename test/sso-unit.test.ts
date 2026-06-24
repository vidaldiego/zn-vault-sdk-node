// Path: zn-vault-sdk-node/test/sso-unit.test.ts
// Unit tests for SSO fixes: CACHE-01 (exp re-check on cache hit) and PKG-04 (export parity)

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ============================================================================
// PKG-04: Export parity — root '.' vs './sso'
// ============================================================================
describe('PKG-04: root export parity', () => {
  it('exports createFastifySSOScopes from root index', async () => {
    const rootExports = await import('../src/index.js');
    expect(typeof rootExports.createFastifySSOScopes).toBe('function');
  });

  it('exports createFastifySSORoles from root index', async () => {
    const rootExports = await import('../src/index.js');
    expect(typeof rootExports.createFastifySSORoles).toBe('function');
  });

  it('exports createExpressSSOScopes from root index', async () => {
    const rootExports = await import('../src/index.js');
    expect(typeof rootExports.createExpressSSOScopes).toBe('function');
  });

  it('exports createExpressSSORoles from root index', async () => {
    const rootExports = await import('../src/index.js');
    expect(typeof rootExports.createExpressSSORoles).toBe('function');
  });

  it('exports requireScopes from root index', async () => {
    const rootExports = await import('../src/index.js');
    expect(typeof rootExports.requireScopes).toBe('function');
  });

  it('exports requireRole from root index', async () => {
    const rootExports = await import('../src/index.js');
    expect(typeof rootExports.requireRole).toBe('function');
  });

  it('root index and ./sso export the same guard-function names', async () => {
    const rootExports = await import('../src/index.js');
    const ssoExports = await import('../src/sso/index.js');

    const guardNames = [
      'createFastifySSOAuth',
      'createFastifySSOScopes',
      'createFastifySSORoles',
      'createExpressSSOAuth',
      'createExpressSSOScopes',
      'createExpressSSORoles',
      'requireScopes',
      'requireRole',
    ];

    for (const name of guardNames) {
      expect(
        typeof (rootExports as Record<string, unknown>)[name],
        `root index missing guard: ${name}`
      ).toBe('function');
      expect(
        typeof (ssoExports as Record<string, unknown>)[name],
        `sso/index.ts missing guard: ${name}`
      ).toBe('function');
    }
  });

  it('dead export createExpressSSOScopes_Roles is NOT exported from sso/index', async () => {
    const ssoExports = await import('../src/sso/index.js') as Record<string, unknown>;
    expect(ssoExports['createExpressSSOScopes_Roles']).toBeUndefined();
  });
});

// ============================================================================
// CACHE-01: Expired token must not validate even when cached
// ============================================================================
describe('CACHE-01: introspection cache exp re-check', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('rejects a cached token after its exp has passed (fail-closed security)', async () => {
    // We'll use a fixed "now" for determinism
    const startMs = 1_700_000_000_000; // arbitrary fixed epoch ms
    vi.setSystemTime(startMs);

    // Token expires 30 seconds from "now"
    const tokenExpSec = Math.floor(startMs / 1000) + 30;

    // Import here so module-level state is fresh under fake timers
    const { SSOClient } = await import('../src/sso/client.js');

    // Patch the private `introspect` method via a subclass so we can intercept
    // the HTTP call without a real network connection
    let introspectCallCount = 0;
    class TestSSOClient extends SSOClient {
      override async introspect(_token: string) {
        introspectCallCount++;
        return {
          active: true,
          sub: 'user-1',
          username: 'alice',
          email: 'alice@example.com',
          tenantId: 'acme',
          clientId: 'sso_abc',
          aud: 'sso_abc',
          role: 'member',
          scope: 'openid profile',
          exp: tokenExpSec,
          iat: Math.floor(startMs / 1000) - 60,
          iss: 'https://vault.example.com',
        };
      }
    }

    const client = new TestSSOClient({
      vaultUrl: 'https://vault.example.com',
      clientId: 'sso_abc',
      clientSecret: 'secret',
      introspectionCacheTtlMs: 120_000, // 2-minute cache TTL — longer than token lifetime
    });

    // First call: populates the cache via introspect()
    const result1 = await client.validateToken('token-abc');
    expect(result1).not.toBeNull();
    expect(result1?.username).toBe('alice');
    expect(introspectCallCount).toBe(1);

    // Advance time to JUST BEFORE expiry (29 s) — should still be valid from cache
    vi.setSystemTime(startMs + 29_000);
    const result2 = await client.validateToken('token-abc');
    expect(result2).not.toBeNull();
    // May or may not have called introspect again (implementation choice);
    // what matters is that it's valid at t+29s

    // Advance time PAST the token exp (31 s after start)
    vi.setSystemTime(startMs + 31_000);

    // CACHE-01: with the bug, this returns the cached active result
    // With the fix, it must return null (or re-introspect with a fresh call)
    const result3 = await client.validateToken('token-abc');
    expect(result3).toBeNull();
  });

  it('allows a token that has NOT yet expired to be served from cache', async () => {
    const startMs = 1_700_000_000_000;
    vi.setSystemTime(startMs);

    const tokenExpSec = Math.floor(startMs / 1000) + 300; // 5 minutes

    const { SSOClient } = await import('../src/sso/client.js');

    class TestSSOClient extends SSOClient {
      override async introspect(_token: string) {
        return {
          active: true,
          sub: 'user-2',
          username: 'bob',
          tenantId: 'acme',
          clientId: 'sso_abc',
          aud: 'sso_abc',
          role: 'admin',
          scope: 'openid',
          exp: tokenExpSec,
          iat: Math.floor(startMs / 1000),
          iss: 'https://vault.example.com',
        };
      }
    }

    const client = new TestSSOClient({
      vaultUrl: 'https://vault.example.com',
      clientId: 'sso_abc',
      clientSecret: 'secret',
      introspectionCacheTtlMs: 120_000,
    });

    await client.validateToken('token-bob');

    // 60 seconds later — token not expired (exp is 300s from start)
    vi.setSystemTime(startMs + 60_000);
    const result = await client.validateToken('token-bob');
    expect(result).not.toBeNull();
    expect(result?.username).toBe('bob');
  });

  it('handles missing exp gracefully (no crash, follows cache TTL only)', async () => {
    const startMs = 1_700_000_000_000;
    vi.setSystemTime(startMs);

    const { SSOClient } = await import('../src/sso/client.js');

    class TestSSOClient extends SSOClient {
      override async introspect(_token: string) {
        return {
          active: true,
          sub: 'user-3',
          username: 'charlie',
          tenantId: 'acme',
          clientId: 'sso_abc',
          aud: 'sso_abc',
          role: 'viewer',
          scope: 'openid',
          // No exp field
          iat: Math.floor(startMs / 1000),
          iss: 'https://vault.example.com',
        };
      }
    }

    const client = new TestSSOClient({
      vaultUrl: 'https://vault.example.com',
      clientId: 'sso_abc',
      clientSecret: 'secret',
      introspectionCacheTtlMs: 120_000,
    });

    await client.validateToken('token-charlie');

    // Advance time — no exp, so falls back to cache TTL (which is 120s)
    vi.setSystemTime(startMs + 60_000);
    const result = await client.validateToken('token-charlie');
    // Should still be valid since cache TTL hasn't expired
    expect(result).not.toBeNull();
    expect(result?.username).toBe('charlie');
  });
});
