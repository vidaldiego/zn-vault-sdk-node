// Path: zn-vault-sdk-node/test/auth-unit.test.ts
// Unit tests for AuthClient field-name contracts (AUTH-01..05).
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
});
