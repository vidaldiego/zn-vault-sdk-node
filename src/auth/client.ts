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
  RegistrationToken,
  CreateRegistrationTokenRequest,
  CreateRegistrationTokenResponse,
  ListRegistrationTokensResponse,
  BootstrapResponse,
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
      totpCode: request.totpCode,
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
      currentPassword,
      newPassword,
    });
  }

  async forceChangePassword(
    userId: string,
    currentPassword: string,
    newPassword: string
  ): Promise<{ message: string }> {
    return this.http.post<{ message: string }>('/auth/force-change-password', {
      userId,
      currentPassword,
      newPassword,
    });
  }

  logout(): void {
    this.http.clearTokens();
  }

  // API Keys

  /**
   * Create an API key for programmatic access in the caller's tenant.
   * Tenant is derived server-side from the authenticated principal. For
   * cross-tenant API key creation, use ZnVaultSuperadminClient (when
   * available — /v1/superadmin/api-keys/* is not yet implemented on the
   * server as of vault 1.38.8).
   *
   * The key value is only shown once - save it immediately!
   */
  async createApiKey(request: CreateApiKeyRequest): Promise<CreateApiKeyResponse> {
    return this.http.post<CreateApiKeyResponse>('/auth/api-keys', {
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
    const response = await this.http.get<{ items: ApiKey[]; expiringSoon: ApiKey[] }>('/auth/api-keys');
    return { keys: response.items, expiringSoon: response.expiringSoon };
  }

  /**
   * Get a specific API key by ID.
   *
   * The server returns the bare public key object directly (not wrapped in { apiKey }).
   *
   * @param id - The API key ID
   * @returns The API key metadata
   */
  async getApiKey(id: string): Promise<ApiKey> {
    return this.http.get<ApiKey>(`/auth/api-keys/${id}`);
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
   * @param name - Optional new name for the rotated key
   * @returns The rotated API key with new key value
   */
  async rotateApiKey(id: string, name?: string): Promise<CreateApiKeyResponse> {
    return this.http.post<CreateApiKeyResponse>(`/auth/api-keys/${id}/rotate`, {
      name,
    });
  }

  /**
   * Get information about the currently authenticated API key.
   * Only works when authenticated via API key.
   *
   * @returns The current API key metadata with expiration info
   */
  async getCurrentApiKey(): Promise<ApiKey & { expiresInDays: number; isExpiringSoon: boolean }> {
    // API returns flat object with ApiKey fields + expiresInDays + isExpiringSoon
    return this.http.get<ApiKey & { expiresInDays: number; isExpiringSoon: boolean }>('/auth/api-keys/self');
  }

  /**
   * Rotate the currently authenticated API key.
   * Only works when authenticated via API key.
   *
   * @param name - Optional new name for the rotated key
   * @returns The rotated API key with new key value
   */
  async rotateCurrentApiKey(name?: string): Promise<CreateApiKeyResponse> {
    return this.http.post<CreateApiKeyResponse>('/auth/api-keys/self/rotate', {
      name,
    });
  }

  // 2FA
  async enable2fa(): Promise<TwoFactorSetupResponse> {
    return this.http.post<TwoFactorSetupResponse>('/auth/2fa/enable');
  }

  async verify2fa(totpCode: string): Promise<void> {
    await this.http.post('/auth/2fa/verify', { totpCode });
  }

  async disable2fa(password: string, totpCode?: string): Promise<void> {
    await this.http.post('/auth/2fa/disable', {
      password,
      totpCode,
    });
  }

  async get2faStatus(): Promise<TwoFactorStatus> {
    return this.http.get<TwoFactorStatus>('/auth/2fa/status');
  }

  // =========================================================================
  // Managed API Keys
  // =========================================================================
  //
  // All managed-key and registration-token methods are scoped to the
  // caller's tenant. For cross-tenant management, use ZnVaultSuperadminClient
  // (server route /v1/superadmin/api-keys/* — not yet implemented).

  /**
   * Create a managed API key with auto-rotation configuration in the
   * caller's tenant.
   *
   * Managed keys are created via POST /auth/api-keys with a nested `managed`
   * object — there is no separate /auth/api-keys/managed create endpoint.
   */
  async createManagedApiKey(request: CreateManagedApiKeyRequest): Promise<CreateManagedApiKeyResponse> {
    return this.http.post<CreateManagedApiKeyResponse>('/auth/api-keys', {
      name: request.name,
      permissions: request.permissions,
      description: request.description,
      expiresInDays: request.expiresInDays,
      managed: {
        rotationMode: request.rotationMode,
        rotationInterval: request.rotationInterval,
        gracePeriod: request.gracePeriod,
        notifyBefore: request.notifyBefore,
        webhookUrl: request.webhookUrl,
      },
    });
  }

  /** List managed API keys in the caller's tenant. */
  async listManagedApiKeys(): Promise<{ keys: ManagedApiKey[]; total: number }> {
    const response = await this.http.get<{ items: ManagedApiKey[]; pagination: { total: number } }>(
      '/auth/api-keys/managed'
    );
    return { keys: response.items, total: response.pagination.total };
  }

  /** Get a managed API key by name in the caller's tenant. */
  async getManagedApiKey(name: string): Promise<ManagedApiKey> {
    return this.http.get<ManagedApiKey>(`/auth/api-keys/managed/${encodeURIComponent(name)}`);
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
   */
  async bindManagedApiKey(name: string): Promise<ManagedKeyBindResponse> {
    return this.http.post<ManagedKeyBindResponse>(
      `/auth/api-keys/managed/${encodeURIComponent(name)}/bind`,
      {}
    );
  }

  /**
   * Force rotate a managed API key.
   *
   * Creates a new key immediately, regardless of the rotation schedule.
   * The old key remains valid during the grace period.
   */
  async rotateManagedApiKey(name: string): Promise<ManagedKeyRotateResponse> {
    return this.http.post<ManagedKeyRotateResponse>(
      `/auth/api-keys/managed/${encodeURIComponent(name)}/rotate`,
      {}
    );
  }

  /** Update managed API key configuration. */
  async updateManagedApiKeyConfig(
    name: string,
    config: UpdateManagedApiKeyConfigRequest
  ): Promise<ManagedApiKey> {
    return this.http.patch<ManagedApiKey>(
      `/auth/api-keys/managed/${encodeURIComponent(name)}/config`,
      config
    );
  }

  /** Delete a managed API key. */
  async deleteManagedApiKey(name: string): Promise<void> {
    await this.http.delete(`/auth/api-keys/managed/${encodeURIComponent(name)}`);
  }

  // =========================================================================
  // Registration Tokens (Agent Bootstrap)
  // =========================================================================

  /**
   * Create a registration token for agent bootstrapping.
   *
   * Registration tokens are one-time use tokens that allow agents to
   * obtain their managed API key without prior authentication.
   */
  async createRegistrationToken(
    managedKeyName: string,
    request: CreateRegistrationTokenRequest = {}
  ): Promise<CreateRegistrationTokenResponse> {
    return this.http.post<CreateRegistrationTokenResponse>(
      `/auth/api-keys/managed/${encodeURIComponent(managedKeyName)}/registration-tokens`,
      request
    );
  }

  /** List registration tokens for a managed key. */
  async listRegistrationTokens(
    managedKeyName: string,
    options?: { includeUsed?: boolean }
  ): Promise<RegistrationToken[]> {
    const path = options?.includeUsed
      ? `/auth/api-keys/managed/${encodeURIComponent(managedKeyName)}/registration-tokens?includeUsed=true`
      : `/auth/api-keys/managed/${encodeURIComponent(managedKeyName)}/registration-tokens`;
    const response = await this.http.get<ListRegistrationTokensResponse>(path);
    return response.tokens;
  }

  /** Revoke a registration token. */
  async revokeRegistrationToken(managedKeyName: string, tokenId: string): Promise<void> {
    await this.http.delete(
      `/auth/api-keys/managed/${encodeURIComponent(managedKeyName)}/registration-tokens/${tokenId}`
    );
  }

  /**
   * Bootstrap an agent using a registration token.
   *
   * This is the unauthenticated endpoint used by agents to exchange a
   * one-time registration token for a managed API key binding.
   *
   * Note: This method does not require prior authentication.
   *
   * @param token - The registration token (format: zrt_...)
   * @returns The API key binding response
   */
  async bootstrap(token: string): Promise<BootstrapResponse> {
    return this.http.post<BootstrapResponse>('/agent/bootstrap', { token });
  }
}
