// Path: zn-vault-sdk-node/src/superadmin/auth.ts

import type { HttpClient } from '../http/client.js';
import type {
  ApiKey,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  ManagedApiKey,
  CreateManagedApiKeyRequest,
  CreateManagedApiKeyResponse,
  ManagedKeyRotateResponse,
  UpdateManagedApiKeyConfigRequest,
  RegistrationToken,
  CreateRegistrationTokenRequest,
  CreateRegistrationTokenResponse,
  ListRegistrationTokensResponse,
} from '../types/index.js';

/**
 * Superadmin-only auth operations for cross-tenant API key and registration
 * token management.
 *
 * **Server requirement:** these methods call routes under
 * `/v1/superadmin/api-keys/` (including the `managed/` sub-tree). Those
 * routes are not yet implemented on the server (as of vault 1.38.8); calls
 * will return 404 until they ship. For tenant-scoped operations within a
 * single tenant, use `AuthClient` on a `ZnVaultClient`.
 */
export class SuperadminAuthClient {
  constructor(private http: HttpClient) {}

  /** Create a regular API key in any tenant. */
  async createApiKey(
    tenantId: string,
    request: CreateApiKeyRequest
  ): Promise<CreateApiKeyResponse> {
    return this.http.post<CreateApiKeyResponse>(
      `/v1/superadmin/api-keys?tenantId=${encodeURIComponent(tenantId)}`,
      request
    );
  }

  /** List API keys for any tenant. */
  async listApiKeys(tenantId: string): Promise<ApiKey[]> {
    const response = await this.http.get<{ items: ApiKey[] }>(
      `/v1/superadmin/api-keys?tenantId=${encodeURIComponent(tenantId)}`
    );
    return response.items;
  }

  /** Delete an API key (server resolves tenant from the key record). */
  async deleteApiKey(id: string): Promise<void> {
    await this.http.delete(`/v1/superadmin/api-keys/${id}`);
  }

  // ==================== Managed API Keys ====================

  async createManagedApiKey(
    tenantId: string,
    request: CreateManagedApiKeyRequest
  ): Promise<CreateManagedApiKeyResponse> {
    return this.http.post<CreateManagedApiKeyResponse>(
      `/v1/superadmin/api-keys/managed?tenantId=${encodeURIComponent(tenantId)}`,
      request
    );
  }

  async listManagedApiKeys(tenantId: string): Promise<ManagedApiKey[]> {
    const response = await this.http.get<{ items: ManagedApiKey[] }>(
      `/v1/superadmin/api-keys/managed?tenantId=${encodeURIComponent(tenantId)}`
    );
    return response.items;
  }

  async getManagedApiKey(tenantId: string, name: string): Promise<ManagedApiKey> {
    return this.http.get<ManagedApiKey>(
      `/v1/superadmin/api-keys/managed/${encodeURIComponent(name)}?tenantId=${encodeURIComponent(tenantId)}`
    );
  }

  async rotateManagedApiKey(tenantId: string, name: string): Promise<ManagedKeyRotateResponse> {
    return this.http.post<ManagedKeyRotateResponse>(
      `/v1/superadmin/api-keys/managed/${encodeURIComponent(name)}/rotate?tenantId=${encodeURIComponent(tenantId)}`,
      {}
    );
  }

  async updateManagedApiKeyConfig(
    tenantId: string,
    name: string,
    config: UpdateManagedApiKeyConfigRequest
  ): Promise<ManagedApiKey> {
    return this.http.patch<ManagedApiKey>(
      `/v1/superadmin/api-keys/managed/${encodeURIComponent(name)}/config?tenantId=${encodeURIComponent(tenantId)}`,
      config
    );
  }

  async deleteManagedApiKey(tenantId: string, name: string): Promise<void> {
    await this.http.delete(
      `/v1/superadmin/api-keys/managed/${encodeURIComponent(name)}?tenantId=${encodeURIComponent(tenantId)}`
    );
  }

  // ==================== Registration Tokens ====================

  async createRegistrationToken(
    tenantId: string,
    managedKeyName: string,
    request: CreateRegistrationTokenRequest = {}
  ): Promise<CreateRegistrationTokenResponse> {
    return this.http.post<CreateRegistrationTokenResponse>(
      `/v1/superadmin/api-keys/managed/${encodeURIComponent(managedKeyName)}/registration-tokens?tenantId=${encodeURIComponent(tenantId)}`,
      request
    );
  }

  async listRegistrationTokens(
    tenantId: string,
    managedKeyName: string,
    options?: { includeUsed?: boolean }
  ): Promise<RegistrationToken[]> {
    const includeUsed = options?.includeUsed ? '&includeUsed=true' : '';
    const response = await this.http.get<ListRegistrationTokensResponse>(
      `/v1/superadmin/api-keys/managed/${encodeURIComponent(managedKeyName)}/registration-tokens?tenantId=${encodeURIComponent(tenantId)}${includeUsed}`
    );
    return response.tokens;
  }

  async revokeRegistrationToken(
    tenantId: string,
    managedKeyName: string,
    tokenId: string
  ): Promise<void> {
    await this.http.delete(
      `/v1/superadmin/api-keys/managed/${encodeURIComponent(managedKeyName)}/registration-tokens/${tokenId}?tenantId=${encodeURIComponent(tenantId)}`
    );
  }
}
