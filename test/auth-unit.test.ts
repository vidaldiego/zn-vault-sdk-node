// Path: zn-vault-sdk-node/test/auth-unit.test.ts
// Unit tests for AuthClient field-name contracts (AUTH-01..09).
// Uses a mocked HttpClient — no live server required.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { AuthClient } from '../src/auth/client.js';
import type { HttpClient } from '../src/http/client.js';

function makeClient() {
  const http = {
    post: vi.fn(),
    get: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    setTokens: vi.fn(),
    getRefreshToken: vi.fn(),
    clearTokens: vi.fn(),
  };
  return { client: new AuthClient(http as unknown as HttpClient), http };
}

describe('AuthClient field-name contracts (mocked HTTP)', () => {
  let client: AuthClient;
  let http: ReturnType<typeof makeClient>['http'];

  beforeEach(() => ({ client, http } = makeClient()));

  // AUTH-01: login sends totpCode (camelCase), not totp_code
  it('AUTH-01: login sends totpCode (camelCase)', async () => {
    http.post.mockResolvedValue({ accessToken: 'a', refreshToken: 'r', expiresIn: 3600, tokenType: 'Bearer' });
    await client.login({ username: 'u', password: 'p', totpCode: '123456' });
    expect(http.post).toHaveBeenCalledWith('/auth/login', {
      username: 'u',
      password: 'p',
      totpCode: '123456',
    });
  });

  // AUTH-01: login without totpCode still sends the field as undefined (not totp_code)
  it('AUTH-01: login without 2FA omits totpCode (no snake_case fallback)', async () => {
    http.post.mockResolvedValue({ accessToken: 'a', refreshToken: 'r', expiresIn: 3600, tokenType: 'Bearer' });
    await client.login({ username: 'acme/admin', password: 'pass' });
    const body = http.post.mock.calls[0][1] as Record<string, unknown>;
    expect(body).not.toHaveProperty('totp_code');
    expect(body.username).toBe('acme/admin');
  });

  // AUTH-02: login with tenant prefix formats as "tenant/username"
  it('AUTH-02: login with separate tenant formats username as tenant/username', async () => {
    http.post.mockResolvedValue({ accessToken: 'a', refreshToken: 'r', expiresIn: 3600, tokenType: 'Bearer' });
    await client.login({ tenant: 'acme', username: 'admin', password: 'p' });
    const body = http.post.mock.calls[0][1] as Record<string, unknown>;
    expect(body.username).toBe('acme/admin');
  });

  // AUTH-03: changePassword sends currentPassword/newPassword (camelCase)
  it('AUTH-03: changePassword sends currentPassword/newPassword', async () => {
    http.post.mockResolvedValue({ message: 'ok' });
    await client.changePassword('old', 'newPassword12!');
    expect(http.post).toHaveBeenCalledWith('/auth/change-password', {
      currentPassword: 'old',
      newPassword: 'newPassword12!',
    });
  });

  // AUTH-03: changePassword does NOT send snake_case fields
  it('AUTH-03: changePassword does not send current_password or new_password', async () => {
    http.post.mockResolvedValue({ message: 'ok' });
    await client.changePassword('old', 'new');
    const body = http.post.mock.calls[0][1] as Record<string, unknown>;
    expect(body).not.toHaveProperty('current_password');
    expect(body).not.toHaveProperty('new_password');
  });

  // AUTH-04: forceChangePassword sends userId (not username) + camelCase passwords
  it('AUTH-04: forceChangePassword sends userId/currentPassword/newPassword', async () => {
    http.post.mockResolvedValue({ message: 'Password changed successfully.' });
    const result = await client.forceChangePassword(
      '550e8400-e29b-41d4-a716-446655440000',
      'oldPass',
      'newPass12!'
    );
    expect(http.post).toHaveBeenCalledWith('/auth/force-change-password', {
      userId: '550e8400-e29b-41d4-a716-446655440000',
      currentPassword: 'oldPass',
      newPassword: 'newPass12!',
    });
    expect(result).toEqual({ message: 'Password changed successfully.' });
  });

  // AUTH-04: forceChangePassword does NOT send username or snake_case
  it('AUTH-04: forceChangePassword does not send username or snake_case fields', async () => {
    http.post.mockResolvedValue({ message: 'ok' });
    await client.forceChangePassword('uuid-123', 'old', 'new');
    const body = http.post.mock.calls[0][1] as Record<string, unknown>;
    expect(body).not.toHaveProperty('username');
    expect(body).not.toHaveProperty('current_password');
    expect(body).not.toHaveProperty('new_password');
  });

  // AUTH-05a: verify2fa sends totpCode (not code)
  it('AUTH-05a: verify2fa sends totpCode (not code)', async () => {
    http.post.mockResolvedValue({ message: '2FA enabled successfully', enabled: true });
    await client.verify2fa('654321');
    expect(http.post).toHaveBeenCalledWith('/auth/2fa/verify', { totpCode: '654321' });
  });

  // AUTH-05a: verify2fa does NOT send field named 'code'
  it('AUTH-05a: verify2fa does not send field named code', async () => {
    http.post.mockResolvedValue({ message: 'ok', enabled: true });
    await client.verify2fa('123456');
    const body = http.post.mock.calls[0][1] as Record<string, unknown>;
    expect(body).not.toHaveProperty('code');
    expect(body).not.toHaveProperty('totp_code');
  });

  // AUTH-05b: disable2fa sends totpCode (not totp_code)
  it('AUTH-05b: disable2fa sends password and totpCode (camelCase)', async () => {
    http.post.mockResolvedValue({ message: '2FA disabled successfully', enabled: false });
    await client.disable2fa('mypassword', '111222');
    expect(http.post).toHaveBeenCalledWith('/auth/2fa/disable', {
      password: 'mypassword',
      totpCode: '111222',
    });
  });

  // AUTH-05b: disable2fa does NOT send totp_code
  it('AUTH-05b: disable2fa does not send totp_code (snake_case)', async () => {
    http.post.mockResolvedValue({ message: 'ok', enabled: false });
    await client.disable2fa('pass', '999888');
    const body = http.post.mock.calls[0][1] as Record<string, unknown>;
    expect(body).not.toHaveProperty('totp_code');
  });

  // AUTH-05b: disable2fa without totpCode passes undefined (not missing key named totp_code)
  it('AUTH-05b: disable2fa without totpCode sends only password', async () => {
    http.post.mockResolvedValue({ message: 'ok', enabled: false });
    await client.disable2fa('pass');
    const body = http.post.mock.calls[0][1] as Record<string, unknown>;
    expect(body).toHaveProperty('password', 'pass');
    expect(body).not.toHaveProperty('totp_code');
  });

  // AUTH-06: getApiKey returns the bare object (server returns apiKey directly, not wrapped in { apiKey })
  it('AUTH-06: getApiKey returns the bare response object directly', async () => {
    const fakeKey = {
      id: 'key_123',
      name: 'test-key',
      tenant_id: 'acme',
      created_by: 'user_1',
      created_at: '2026-01-01T00:00:00.000Z',
      expires_at: '2026-04-01T00:00:00.000Z',
      prefix: 'znv_abcd',
      permissions: ['secret:read:metadata'],
      ip_allowlist: [],
      enabled: true,
      rotation_count: 0,
      last_rotation: null,
      is_managed: false,
      rotation_mode: null,
      rotation_interval_seconds: null,
      grace_period_seconds: 300,
      next_rotation_at: null,
      late_pickup_enabled: false,
      late_pickup_window_seconds: 0,
    };
    http.get.mockResolvedValue(fakeKey);
    const result = await client.getApiKey('key_123');
    // Must return the bare object, not result.apiKey
    expect(result).toBe(fakeKey);
    expect(result.id).toBe('key_123');
    expect(result.tenant_id).toBe('acme');
  });

  // AUTH-06: getApiKey does NOT unwrap an apiKey property
  it('AUTH-06: getApiKey does not return response.apiKey wrapper', async () => {
    const fakeKey = { id: 'key_abc', name: 'my-key', tenant_id: 'acme', permissions: [] };
    http.get.mockResolvedValue(fakeKey);
    const result = await client.getApiKey('key_abc');
    // If old code were used, result would be undefined (fakeKey has no .apiKey property)
    expect(result).not.toBeUndefined();
    expect(result.id).toBe('key_abc');
  });

  // AUTH-07: createManagedApiKey POSTs to /auth/api-keys (NOT /auth/api-keys/managed)
  it('AUTH-07: createManagedApiKey POSTs to /auth/api-keys', async () => {
    http.post.mockResolvedValue({
      apiKey: { id: 'key_managed', name: 'my-managed', is_managed: true, permissions: [] },
      message: 'Managed API key created.',
    });
    await client.createManagedApiKey({
      name: 'my-managed',
      permissions: ['secret:read:metadata'],
      rotationMode: 'scheduled',
      rotationInterval: '24h',
      gracePeriod: '5m',
    });
    const [path] = http.post.mock.calls[0];
    expect(path).toBe('/auth/api-keys');
  });

  // AUTH-07: createManagedApiKey sends managed config as nested managed object
  it('AUTH-07: createManagedApiKey sends nested managed object', async () => {
    http.post.mockResolvedValue({
      apiKey: { id: 'key_managed', name: 'my-managed', is_managed: true, permissions: [] },
      message: 'Managed API key created.',
    });
    await client.createManagedApiKey({
      name: 'my-managed',
      permissions: ['secret:read:metadata'],
      rotationMode: 'on-use',
      gracePeriod: '10m',
      description: 'A managed key',
    });
    const body = http.post.mock.calls[0][1] as Record<string, unknown>;
    // Top-level fields
    expect(body.name).toBe('my-managed');
    expect(body.permissions).toEqual(['secret:read:metadata']);
    expect(body.description).toBe('A managed key');
    // Rotation config must be in nested managed object
    expect(body).toHaveProperty('managed');
    const managed = body.managed as Record<string, unknown>;
    expect(managed.rotationMode).toBe('on-use');
    expect(managed.gracePeriod).toBe('10m');
    // Must NOT have rotationMode at the top level
    expect(body).not.toHaveProperty('rotationMode');
    expect(body).not.toHaveProperty('gracePeriod');
  });

  // AUTH-07b: createManagedApiKey response uses snake_case ApiKey shape (FIX 3)
  it('AUTH-07b: createManagedApiKey response.apiKey uses snake_case fields', async () => {
    const mockResponse = {
      key: 'znv_managed123',
      apiKey: {
        id: 'key_managed_456',
        name: 'my-managed-key',
        tenant_id: 'acme',
        is_managed: true,
        rotation_mode: 'scheduled' as const,
        rotation_interval_seconds: 86400,
        grace_period_seconds: 300,
        first_used_at: null,
        grace_expires_at: null,
        rotation_webhook_url: 'https://example.com/webhook',
        created_by_username: 'alice',
        permissions: ['secret:read:metadata'],
        enabled: true,
      },
      message: 'Managed API key created. Use POST /auth/api-keys/managed/my-managed-key/bind to retrieve the key value.',
    };
    http.post.mockResolvedValue(mockResponse);
    const result = await client.createManagedApiKey({
      name: 'my-managed-key',
      permissions: ['secret:read:metadata'],
      rotationMode: 'scheduled',
      rotationInterval: '24h',
    });
    // The apiKey shape must be snake_case (ApiKey), not camelCase (ManagedApiKey)
    expect(result.apiKey.rotation_mode).toBe('scheduled');
    expect(result.apiKey.is_managed).toBe(true);
    expect(result.apiKey.rotation_webhook_url).toBe('https://example.com/webhook');
    expect(result.apiKey.created_by_username).toBe('alice');
    expect(result.apiKey.grace_expires_at).toBeNull();
    expect(result.apiKey.first_used_at).toBeNull();
    // Must NOT be reading camelCase ManagedApiKey fields
    expect((result.apiKey as Record<string, unknown>)['rotationMode']).toBeUndefined();
    expect((result.apiKey as Record<string, unknown>)['tenantId']).toBeUndefined();
  });

  // AUTH-08: rotateApiKey sends { name } only — no expiresInDays
  it('AUTH-08: rotateApiKey sends name-only body (no expiresInDays)', async () => {
    http.post.mockResolvedValue({
      key: 'znv_newkey123',
      apiKey: { id: 'key_123', name: 'renamed-key', permissions: [] },
      message: 'Save this key',
    });
    await client.rotateApiKey('key_123', 'renamed-key');
    const body = http.post.mock.calls[0][1] as Record<string, unknown>;
    expect(body).toHaveProperty('name', 'renamed-key');
    expect(body).not.toHaveProperty('expiresInDays');
  });

  // AUTH-08: rotateApiKey without name sends empty/undefined name
  it('AUTH-08: rotateApiKey without name sends no expiresInDays', async () => {
    http.post.mockResolvedValue({
      key: 'znv_newkey456',
      apiKey: { id: 'key_123', name: 'my-key', permissions: [] },
      message: 'Save this key',
    });
    await client.rotateApiKey('key_123');
    const [path, body] = http.post.mock.calls[0] as [string, Record<string, unknown>];
    expect(path).toBe('/auth/api-keys/key_123/rotate');
    expect(body).not.toHaveProperty('expiresInDays');
  });

  // AUTH-09: rotateCurrentApiKey sends { name } only — no expiresInDays
  it('AUTH-09: rotateCurrentApiKey sends name-only body (no expiresInDays)', async () => {
    http.post.mockResolvedValue({
      key: 'znv_selfnew123',
      apiKey: { id: 'key_self', name: 'self-key', permissions: [] },
      expiresInDays: 90,
      message: 'Save this key',
    });
    await client.rotateCurrentApiKey('new-name');
    const body = http.post.mock.calls[0][1] as Record<string, unknown>;
    expect(body).toHaveProperty('name', 'new-name');
    expect(body).not.toHaveProperty('expiresInDays');
  });

  // AUTH-09: rotateCurrentApiKey without name sends no expiresInDays
  it('AUTH-09: rotateCurrentApiKey without name does not send expiresInDays', async () => {
    http.post.mockResolvedValue({
      key: 'znv_selfnew456',
      apiKey: { id: 'key_self', name: 'self-key', permissions: [] },
      expiresInDays: 90,
      message: 'Save this key',
    });
    await client.rotateCurrentApiKey();
    const [path, body] = http.post.mock.calls[0] as [string, Record<string, unknown>];
    expect(path).toBe('/auth/api-keys/self/rotate');
    expect(body).not.toHaveProperty('expiresInDays');
  });
});
