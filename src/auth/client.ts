// Path: zn-vault-sdk-node/src/auth/client.ts

import type { HttpClient } from '../http/client.js';
import type {
  LoginRequest,
  LoginResponse,
  RefreshResponse,
  MeResponse,
  User,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  ApiKey,
  TwoFactorSetupResponse,
  TwoFactorStatus,
  ManagedApiKey,
  CreateManagedApiKeyRequest,
  CreateManagedApiKeyResponse,
  ManagedKeyBindResponse,
  ManagedKeyRotateResponse,
  UpdateManagedApiKeyConfigRequest,
} from '../types/index.js';

export class AuthClient {
  constructor(private http: HttpClient) {}

  /**
   * Login with username and password.
   *
   * The username must include the tenant prefix in the format `tenant/username`
   * (e.g., "acme/admin"). This allows multiple tenants to have users with the
   * same username. Email addresses can also be used as username.
   *
   * Alternatively, you can provide `tenant` and `username` separately in the
   * request object, and the SDK will format them automatically.
   *
   * @param request - Login credentials
   * @returns Login response with tokens
   */
  async login(request: LoginRequest): Promise<LoginResponse> {
    // If tenant is provided separately, format as "tenant/username"
    const username = request.tenant
      ? `${request.tenant}/${request.username}`
      : request.username;

    const response = await this.http.post<LoginResponse>('/auth/login', {
      username,
      password: request.password,
      totp_code: request.totpCode,
    });

    if (response.accessToken) {
      this.http.setTokens(response.accessToken, response.refreshToken);
    }

    return response;
  }

  /**
   * Login with tenant and username as separate parameters.
   *
   * Convenience method that formats the username as "tenant/username".
   *
   * @param tenant - Tenant identifier (e.g., "acme")
   * @param username - Username within the tenant (e.g., "admin")
   * @param password - User password
   * @param totpCode - Optional TOTP code if 2FA is enabled
   * @returns Login response with tokens
   */
  async loginWithTenant(
    tenant: string,
    username: string,
    password: string,
    totpCode?: string
  ): Promise<LoginResponse> {
    return this.login({
      tenant,
      username,
      password,
      totpCode,
    });
  }

  async refresh(refreshToken?: string): Promise<RefreshResponse> {
    const token = refreshToken ?? this.http.getRefreshToken();
    if (!token) {
      throw new Error('No refresh token available');
    }

    const response = await this.http.post<RefreshResponse>('/auth/refresh', {
      refreshToken: token,
    });

    if (response.accessToken) {
      this.http.setTokens(response.accessToken, response.refreshToken);
    }

    return response;
  }

  async me(): Promise<User> {
    const response = await this.http.get<MeResponse>('/auth/me');
    return response.user;
  }

  async updateProfile(email?: string): Promise<User> {
    const response = await this.http.put<MeResponse>('/auth/me', { email });
    return response.user;
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.http.post('/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    });
  }

  async forceChangePassword(
    username: string,
    currentPassword: string,
    newPassword: string
  ): Promise<LoginResponse> {
    return this.http.post<LoginResponse>('/auth/force-change-password', {
      username,
      current_password: currentPassword,
      new_password: newPassword,
    });
  }

  logout(): void {
    this.http.clearTokens();
  }

  // API Keys

  /**
   * Create an API key for programmatic access.
   *
   * API keys are independent (not bound to any user) and managed at the tenant level.
   * The key value is only shown once - save it immediately!
   *
   * @param request - API key creation parameters
   * @returns The created API key with the full key value
   */
  async createApiKey(request: CreateApiKeyRequest): Promise<CreateApiKeyResponse> {
    const path = request.tenantId
      ? `/auth/api-keys?tenantId=${encodeURIComponent(request.tenantId)}`
      : '/auth/api-keys';

    return this.http.post<CreateApiKeyResponse>(path, {
      name: request.name,
      permissions: request.permissions,
      description: request.description,
      expiresInDays: request.expiresInDays,
      ipAllowlist: request.ipAllowlist,
      conditions: request.conditions,
    });
  }

  /**
   * List all API keys for the current tenant.
   *
   * @returns Object containing all keys and keys expiring soon
   */
  async listApiKeys(): Promise<{ keys: ApiKey[]; expiringSoon: ApiKey[] }> {
    return this.http.get('/auth/api-keys');
  }

  /**
   * Get a specific API key by ID.
   *
   * @param id - The API key ID
   * @returns The API key metadata
   */
  async getApiKey(id: string): Promise<ApiKey> {
    const response = await this.http.get<{ apiKey: ApiKey }>(`/auth/api-keys/${id}`);
    return response.apiKey;
  }

  /**
   * Delete an API key.
   *
   * @param id - The API key ID to delete
   */
  async deleteApiKey(id: string): Promise<void> {
    await this.http.delete(`/auth/api-keys/${id}`);
  }

  /**
   * Rotate an API key, generating a new key value.
   *
   * @param id - The API key ID to rotate
   * @param expiresInDays - Optional new expiration period
   * @returns The rotated API key with new key value
   */
  async rotateApiKey(id: string, expiresInDays?: number): Promise<CreateApiKeyResponse> {
    return this.http.post<CreateApiKeyResponse>(`/auth/api-keys/${id}/rotate`, {
      expiresInDays,
    });
  }

  /**
   * Get information about the currently authenticated API key.
   * Only works when authenticated via API key.
   *
   * @returns The current API key metadata with expiration info
   */
  async getCurrentApiKey(): Promise<ApiKey & { expiresInDays: number; isExpiringSoon: boolean }> {
    const response = await this.http.get<{ apiKey: ApiKey; expiresInDays: number; isExpiringSoon: boolean }>('/auth/api-keys/self');
    return { ...response.apiKey, expiresInDays: response.expiresInDays, isExpiringSoon: response.isExpiringSoon };
  }

  /**
   * Rotate the currently authenticated API key.
   * Only works when authenticated via API key.
   *
   * @param expiresInDays - Optional new expiration period
   * @returns The rotated API key with new key value
   */
  async rotateCurrentApiKey(expiresInDays?: number): Promise<CreateApiKeyResponse> {
    return this.http.post<CreateApiKeyResponse>('/auth/api-keys/self/rotate', {
      expiresInDays,
    });
  }

  // 2FA
  async enable2fa(): Promise<TwoFactorSetupResponse> {
    return this.http.post<TwoFactorSetupResponse>('/auth/2fa/enable');
  }

  async verify2fa(code: string): Promise<void> {
    await this.http.post('/auth/2fa/verify', { code });
  }

  async disable2fa(password: string, totpCode?: string): Promise<void> {
    await this.http.post('/auth/2fa/disable', {
      password,
      totp_code: totpCode,
    });
  }

  async get2faStatus(): Promise<TwoFactorStatus> {
    return this.http.get<TwoFactorStatus>('/auth/2fa/status');
  }

  // =========================================================================
  // Managed API Keys
  // =========================================================================

  /**
   * Create a managed API key with auto-rotation configuration.
   *
   * Managed keys automatically rotate based on the configured mode:
   * - `scheduled`: Rotates at fixed intervals (e.g., every 24 hours)
   * - `on-use`: Rotates after being used (TTL resets on each use)
   * - `on-bind`: Rotates each time bind is called
   *
   * @param request - Managed key creation parameters
   * @returns The created managed key metadata (no key value - use bind to get it)
   */
  async createManagedApiKey(request: CreateManagedApiKeyRequest): Promise<CreateManagedApiKeyResponse> {
    const params = new URLSearchParams();
    if (request.tenantId) params.append('tenantId', request.tenantId);
    const query = params.toString();

    return this.http.post<CreateManagedApiKeyResponse>(
      `/auth/api-keys/managed${query ? `?${query}` : ''}`,
      {
        name: request.name,
        permissions: request.permissions,
        rotationMode: request.rotationMode,
        rotationInterval: request.rotationInterval,
        gracePeriod: request.gracePeriod,
        description: request.description,
        expiresInDays: request.expiresInDays,
      }
    );
  }

  /**
   * List managed API keys.
   *
   * @param tenantId - Optional tenant ID filter (for superadmin)
   * @returns List of managed keys
   */
  async listManagedApiKeys(tenantId?: string): Promise<{ keys: ManagedApiKey[]; total: number }> {
    const params = new URLSearchParams();
    if (tenantId) params.append('tenantId', tenantId);
    const query = params.toString();

    return this.http.get<{ keys: ManagedApiKey[]; total: number }>(
      `/auth/api-keys/managed${query ? `?${query}` : ''}`
    );
  }

  /**
   * Get a managed API key by name.
   *
   * @param name - The managed key name
   * @param tenantId - Optional tenant ID (for cross-tenant access)
   * @returns The managed key metadata
   */
  async getManagedApiKey(name: string, tenantId?: string): Promise<ManagedApiKey> {
    const params = new URLSearchParams();
    if (tenantId) params.append('tenantId', tenantId);
    const query = params.toString();

    return this.http.get<ManagedApiKey>(
      `/auth/api-keys/managed/${encodeURIComponent(name)}${query ? `?${query}` : ''}`
    );
  }

  /**
   * Bind to a managed API key to get the current key value.
   *
   * This is the primary method for agents to obtain their API key.
   * The response includes rotation metadata to help the SDK know when
   * to re-bind for a new key.
   *
   * Security: This endpoint requires the caller to already have a valid
   * API key (the current one, even during grace period). This prevents
   * unauthorized access to managed keys.
   *
   * @param name - The managed key name
   * @param tenantId - Optional tenant ID (for cross-tenant access)
   * @returns The current key value and rotation metadata
   */
  async bindManagedApiKey(name: string, tenantId?: string): Promise<ManagedKeyBindResponse> {
    const params = new URLSearchParams();
    if (tenantId) params.append('tenantId', tenantId);
    const query = params.toString();

    return this.http.post<ManagedKeyBindResponse>(
      `/auth/api-keys/managed/${encodeURIComponent(name)}/bind${query ? `?${query}` : ''}`,
      {}
    );
  }

  /**
   * Force rotate a managed API key.
   *
   * Creates a new key immediately, regardless of the rotation schedule.
   * The old key remains valid during the grace period.
   *
   * @param name - The managed key name
   * @param tenantId - Optional tenant ID (for cross-tenant access)
   * @returns The new key value and rotation info
   */
  async rotateManagedApiKey(name: string, tenantId?: string): Promise<ManagedKeyRotateResponse> {
    const params = new URLSearchParams();
    if (tenantId) params.append('tenantId', tenantId);
    const query = params.toString();

    return this.http.post<ManagedKeyRotateResponse>(
      `/auth/api-keys/managed/${encodeURIComponent(name)}/rotate${query ? `?${query}` : ''}`,
      {}
    );
  }

  /**
   * Update managed API key configuration.
   *
   * @param name - The managed key name
   * @param config - Configuration updates
   * @param tenantId - Optional tenant ID (for cross-tenant access)
   * @returns Updated managed key metadata
   */
  async updateManagedApiKeyConfig(
    name: string,
    config: UpdateManagedApiKeyConfigRequest,
    tenantId?: string
  ): Promise<ManagedApiKey> {
    const params = new URLSearchParams();
    if (tenantId) params.append('tenantId', tenantId);
    const query = params.toString();

    return this.http.patch<ManagedApiKey>(
      `/auth/api-keys/managed/${encodeURIComponent(name)}/config${query ? `?${query}` : ''}`,
      config
    );
  }

  /**
   * Delete a managed API key.
   *
   * @param name - The managed key name
   * @param tenantId - Optional tenant ID (for cross-tenant access)
   */
  async deleteManagedApiKey(name: string, tenantId?: string): Promise<void> {
    const params = new URLSearchParams();
    if (tenantId) params.append('tenantId', tenantId);
    const query = params.toString();

    await this.http.delete(
      `/auth/api-keys/managed/${encodeURIComponent(name)}${query ? `?${query}` : ''}`
    );
  }
}
