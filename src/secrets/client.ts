// Path: zn-vault-sdk-node/src/secrets/client.ts

import type { HttpClient } from '../http/client.js';
import type {
  Secret,
  SecretWithData,
  CreateSecretRequest,
  UpdateSecretRequest,
  SecretFilter,
  SecretHistoryEntry,
  PaginatedResponse,
  SecretType,
  SecretSubType,
  GenerateKeypairRequest,
  GeneratedKeypair,
  PublishResult,
  PublicKeyInfo,
  PublicKeyList,
  SecretFieldsResponse,
  CanDecryptResult,
  UserSealedGrant,
} from '../types/index.js';

export class SecretsClient {
  constructor(private http: HttpClient) {}

  async create(request: CreateSecretRequest): Promise<Secret> {
    return this.http.post<Secret>('/v1/secrets', {
      alias: request.alias,
      type: request.type,
      subType: request.subType,
      data: request.data,
      fileName: request.fileName,
      expiresAt: request.expiresAt,
      ttlUntil: request.ttlUntil,
      tags: request.tags,
      contentType: request.contentType,
      protectionMode: request.protectionMode,
      grantUserIds: request.grantUserIds,
    });
  }

  async get(id: string): Promise<Secret> {
    return this.http.get<Secret>(`/v1/secrets/${id}/meta`);
  }

  async getByAlias(alias: string): Promise<Secret> {
    const encodedAlias = encodeURIComponent(alias);
    return this.http.get<Secret>(`/v1/secrets/alias/${encodedAlias}`);
  }

  async decrypt(id: string): Promise<SecretWithData> {
    return this.http.post<SecretWithData>(`/v1/secrets/${id}/decrypt`);
  }

  /**
   * List a secret's top-level field (key) names — never values.
   * Requires secret:read:metadata (not read:value).
   */
  async getFields(id: string): Promise<SecretFieldsResponse> {
    return this.http.get<SecretFieldsResponse>(`/v1/secrets/${id}/fields`);
  }

  /**
   * Preflight whether the CALLER could decrypt this secret (and its reference
   * graph). Self-check only; returns a verdict, never a value. A 'denied'
   * verdict is a successful response, not an error.
   */
  async canDecrypt(id: string): Promise<CanDecryptResult> {
    return this.http.post<CanDecryptResult>(`/v1/secrets/${id}/can-decrypt`, {});
  }

  async update(id: string, request: UpdateSecretRequest): Promise<Secret> {
    return this.http.put<Secret>(`/v1/secrets/${id}`, {
      data: request.data,
      subType: request.subType,
      fileName: request.fileName,
      expiresAt: request.expiresAt,
      ttlUntil: request.ttlUntil,
      tags: request.tags,
      contentType: request.contentType,
    });
  }

  async updateMetadata(
    id: string,
    metadata: { tags?: string[] }
  ): Promise<Secret> {
    return this.http.patch<Secret>(`/v1/secrets/${id}/metadata`, {
      tags: metadata.tags,
    });
  }

  async rotate(id: string, newData: Record<string, unknown>): Promise<Secret> {
    return this.http.post<Secret>(`/v1/secrets/${id}/rotate`, { data: newData });
  }

  async delete(id: string): Promise<void> {
    await this.http.delete(`/v1/secrets/${id}`);
  }

  async list(filter?: SecretFilter): Promise<PaginatedResponse<Secret>> {
    const params = new URLSearchParams();
    if (filter?.type) params.set('type', filter.type);
    if (filter?.subType) params.set('subType', filter.subType);
    if (filter?.fileMime) params.set('fileMime', filter.fileMime);
    if (filter?.expiringBefore) params.set('expiringBefore', filter.expiringBefore);
    // Note: the server's /v1/secrets querystring does not accept a `tags` param — omit it.
    if (filter?.aliasPrefix) params.set('aliasPrefix', filter.aliasPrefix);
    if (filter?.protectionMode) params.set('protectionMode', filter.protectionMode);
    if (filter?.limit) params.set('limit', filter.limit.toString());
    if (filter?.offset) params.set('offset', filter.offset.toString());

    const query = params.toString();
    const path = query ? `/v1/secrets?${query}` : '/v1/secrets';
    return this.http.get<PaginatedResponse<Secret>>(path);
  }

  async getHistory(
    id: string,
    opts?: { limit?: number; offset?: number }
  ): Promise<PaginatedResponse<SecretHistoryEntry>> {
    const params = new URLSearchParams();
    if (opts?.limit !== undefined) params.set('limit', opts.limit.toString());
    if (opts?.offset !== undefined) params.set('offset', opts.offset.toString());
    const query = params.toString();
    const path = query ? `/v1/secrets/${id}/history?${query}` : `/v1/secrets/${id}/history`;
    return this.http.get<PaginatedResponse<SecretHistoryEntry>>(path);
  }

  async decryptVersion(id: string, version: number): Promise<SecretWithData> {
    return this.http.post<SecretWithData>(`/v1/secrets/${id}/history/${version}/decrypt`);
  }

  /** List users holding a wrapped Secret Access Key grant. */
  async listUserSealedGrants(id: string): Promise<{
    items: UserSealedGrant[];
    rootRecoveryAvailable: boolean;
    isTenantRoot: boolean;
  }> {
    return this.http.get(`/v1/secrets/${encodeURIComponent(id)}/user-grants`);
  }

  /** Grant a user access from a password-authenticated human session. */
  async grantUserSealedAccess(id: string, userId: string): Promise<{secretId: string; userId: string}> {
    return this.http.post(`/v1/secrets/${encodeURIComponent(id)}/user-grants`, {userId});
  }

  /** Revoke a user's wrapped SAK grant. */
  async revokeUserSealedAccess(id: string, userId: string): Promise<void> {
    await this.http.delete(`/v1/secrets/${encodeURIComponent(id)}/user-grants/${encodeURIComponent(userId)}`);
  }

  /** Explicitly decrypt through tenant-root recovery. */
  async recoverUserSealedSecret(id: string): Promise<SecretWithData> {
    return this.http.post(`/v1/secrets/${encodeURIComponent(id)}/root-recover`, {});
  }

  /** Recover the SAK as tenant root and issue a user grant. */
  async recoverAndGrantUserSealedAccess(id: string, userId: string): Promise<{
    secretId: string;
    userId: string;
    viaRootRecovery: true;
  }> {
    return this.http.post(`/v1/secrets/${encodeURIComponent(id)}/root-recover/user-grants`, {userId});
  }

  async getUserSealedRecoverySetting(): Promise<{enabled: boolean}> {
    return this.http.get('/v1/tenant/user-sealed-settings');
  }

  async setUserSealedRecovery(enabled: boolean): Promise<{enabled: boolean}> {
    return this.http.put('/v1/tenant/user-sealed-settings', {rootRecoveryEnabled: enabled});
  }

  // ============================================================================
  // Convenience Methods for Typed Secret Creation
  // ============================================================================

  /**
   * Create a password credential secret.
   */
  async createPassword(
    alias: string,
    data: { username: string; password: string; url?: string; notes?: string },
    options?: { tags?: string[]; ttlUntil?: string }
  ): Promise<Secret> {
    return this.create({
      alias,
      type: 'credential',
      subType: 'password',
      data,
      tags: options?.tags,
      ttlUntil: options?.ttlUntil,
    });
  }

  /**
   * Create an API key credential secret.
   */
  async createApiKey(
    alias: string,
    data: { key: string; secret?: string; endpoint?: string; notes?: string },
    options?: { tags?: string[]; ttlUntil?: string }
  ): Promise<Secret> {
    return this.create({
      alias,
      type: 'credential',
      subType: 'api_key',
      data,
      tags: options?.tags,
      ttlUntil: options?.ttlUntil,
    });
  }

  /**
   * Create a certificate secret with automatic expiration tracking.
   */
  async createCertificate(
    alias: string,
    content: Buffer | string,
    options?: {
      fileName?: string;
      chain?: string[];
      expiresAt?: string;
      tags?: string[];
    }
  ): Promise<Secret> {
    const base64Content = Buffer.isBuffer(content)
      ? content.toString('base64')
      : content;

    const data: Record<string, unknown> = { content: base64Content };
    if (options?.chain) {
      data.chain = options.chain;
    }

    return this.create({
      alias,
      type: 'opaque',
      subType: 'certificate',
      data,
      fileName: options?.fileName,
      expiresAt: options?.expiresAt,
      tags: options?.tags,
      contentType: 'application/x-pem-file',
    });
  }

  /**
   * Create a private key secret.
   */
  async createPrivateKey(
    alias: string,
    privateKey: Buffer | string,
    options?: {
      fileName?: string;
      passphrase?: string;
      tags?: string[];
    }
  ): Promise<Secret> {
    const base64Content = Buffer.isBuffer(privateKey)
      ? privateKey.toString('base64')
      : privateKey;

    const data: Record<string, unknown> = { privateKey: base64Content };
    if (options?.passphrase) {
      data.passphrase = options.passphrase;
    }

    return this.create({
      alias,
      type: 'opaque',
      subType: 'private_key',
      data,
      fileName: options?.fileName,
      tags: options?.tags,
    });
  }

  /**
   * Create a key pair secret (public + private key).
   */
  async createKeypair(
    alias: string,
    privateKey: Buffer | string,
    publicKey: Buffer | string,
    options?: {
      fileName?: string;
      passphrase?: string;
      tags?: string[];
    }
  ): Promise<Secret> {
    const privateKeyB64 = Buffer.isBuffer(privateKey)
      ? privateKey.toString('base64')
      : privateKey;
    const publicKeyB64 = Buffer.isBuffer(publicKey)
      ? publicKey.toString('base64')
      : publicKey;

    const data: Record<string, unknown> = {
      privateKey: privateKeyB64,
      publicKey: publicKeyB64,
    };
    if (options?.passphrase) {
      data.passphrase = options.passphrase;
    }

    return this.create({
      alias,
      type: 'opaque',
      subType: 'keypair',
      data,
      fileName: options?.fileName,
      tags: options?.tags,
    });
  }

  /**
   * Create a token secret (JWT, OAuth, bearer token).
   */
  async createToken(
    alias: string,
    token: string,
    options?: {
      tokenType?: string;
      refreshToken?: string;
      expiresAt?: string;
      tags?: string[];
    }
  ): Promise<Secret> {
    const data: Record<string, unknown> = { token };
    if (options?.tokenType) {
      data.tokenType = options.tokenType;
    }
    if (options?.refreshToken) {
      data.refreshToken = options.refreshToken;
    }

    return this.create({
      alias,
      type: 'opaque',
      subType: 'token',
      data,
      expiresAt: options?.expiresAt,
      tags: options?.tags,
    });
  }

  /**
   * Create a JSON configuration setting.
   */
  async createJsonSetting(
    alias: string,
    content: Record<string, unknown>,
    options?: { tags?: string[] }
  ): Promise<Secret> {
    return this.create({
      alias,
      type: 'setting',
      subType: 'json',
      data: { content },
      contentType: 'application/json',
      tags: options?.tags,
    });
  }

  /**
   * Create a YAML configuration setting.
   */
  async createYamlSetting(
    alias: string,
    content: string,
    options?: { tags?: string[] }
  ): Promise<Secret> {
    return this.create({
      alias,
      type: 'setting',
      subType: 'yaml',
      data: { content },
      contentType: 'application/x-yaml',
      tags: options?.tags,
    });
  }

  /**
   * Create an environment variables setting (.env format).
   */
  async createEnvSetting(
    alias: string,
    content: string | Record<string, string>,
    options?: { tags?: string[] }
  ): Promise<Secret> {
    // Convert object to .env format if needed
    const envContent = typeof content === 'string'
      ? content
      : Object.entries(content)
          .map(([k, v]) => `${k}=${v}`)
          .join('\n');

    return this.create({
      alias,
      type: 'setting',
      subType: 'env',
      data: { content: envContent },
      contentType: 'text/plain',
      tags: options?.tags,
    });
  }

  // ============================================================================
  // Convenience Methods for Filtering
  // ============================================================================

  /**
   * List secrets by sub-type.
   */
  async listBySubType(
    subType: SecretSubType,
    options?: { limit?: number; offset?: number }
  ): Promise<PaginatedResponse<Secret>> {
    return this.list({
      subType,
      limit: options?.limit,
      offset: options?.offset,
    });
  }

  /**
   * List secrets by type.
   */
  async listByType(
    type: SecretType,
    options?: { limit?: number; offset?: number }
  ): Promise<PaginatedResponse<Secret>> {
    return this.list({
      type,
      limit: options?.limit,
      offset: options?.offset,
    });
  }

  /**
   * List certificates expiring before a specific date.
   */
  async listExpiringCertificates(
    beforeDate: Date | string,
    options?: { limit?: number; offset?: number }
  ): Promise<PaginatedResponse<Secret>> {
    const expiringBefore = beforeDate instanceof Date
      ? beforeDate.toISOString()
      : beforeDate;

    return this.list({
      subType: 'certificate',
      expiringBefore,
      limit: options?.limit,
      offset: options?.offset,
    });
  }

  /**
   * List all expiring secrets (certificates, tokens) before a specific date.
   */
  async listExpiring(
    beforeDate: Date | string,
    options?: { limit?: number; offset?: number }
  ): Promise<PaginatedResponse<Secret>> {
    const expiringBefore = beforeDate instanceof Date
      ? beforeDate.toISOString()
      : beforeDate;

    return this.list({
      expiringBefore,
      limit: options?.limit,
      offset: options?.offset,
    });
  }

  /**
   * List secrets by alias prefix (hierarchical path).
   */
  async listByPath(
    aliasPrefix: string,
    options?: { limit?: number; offset?: number }
  ): Promise<PaginatedResponse<Secret>> {
    return this.list({
      aliasPrefix,
      limit: options?.limit,
      offset: options?.offset,
    });
  }

  // ============================================================================
  // File Upload/Download Helpers
  // ============================================================================

  /**
   * Upload a file as a secret with automatic MIME detection.
   */
  async uploadFile(
    alias: string,
    filename: string,
    content: Buffer | string,
    options?: {
      subType?: SecretSubType;
      contentType?: string;
      expiresAt?: string;
      tags?: string[];
    }
  ): Promise<Secret> {
    const base64Content = Buffer.isBuffer(content)
      ? content.toString('base64')
      : Buffer.from(content).toString('base64');

    return this.create({
      alias,
      type: 'opaque',
      subType: options?.subType ?? 'file',
      data: {
        filename,
        content: base64Content,
        contentType: options?.contentType,
      },
      fileName: filename,
      expiresAt: options?.expiresAt,
      tags: options?.tags,
      contentType: options?.contentType,
    });
  }

  /**
   * Download a file secret.
   */
  async downloadFile(id: string): Promise<{
    filename: string;
    content: Buffer;
    contentType?: string;
    checksum?: string;
  }> {
    const secret = await this.decrypt(id);
    const data = secret.data as {
      filename?: string;
      content: string;
      contentType?: string;
    };

    return {
      filename: data.filename ?? secret.fileName ?? 'unknown',
      content: Buffer.from(data.content, 'base64'),
      contentType: data.contentType ?? secret.fileMime ?? undefined,
      checksum: secret.fileChecksum ?? undefined,
    };
  }

  // ============================================================================
  // Keypair Generation & Public Key Publishing
  // ============================================================================

  /**
   * Generate a cryptographic keypair (RSA, Ed25519, or ECDSA).
   *
   * The private key is stored as a secret with the given alias.
   * The public key is stored with "-public" suffix.
   *
   * @param request - Keypair generation options
   * @returns Generated keypair with private and public key information
   *
   * @example
   * ```typescript
   * // Generate Ed25519 keypair
   * const keypair = await client.secrets.generateKeypair({
   *   algorithm: 'Ed25519',
   *   alias: 'keys/prod/api-signing',
   *   publishPublicKey: true,
   *   tags: ['signing', 'api']
   * });
   *
   * // Generate RSA 4096 keypair
   * const rsaKeypair = await client.secrets.generateKeypair({
   *   algorithm: 'RSA',
   *   alias: 'keys/prod/ssh-key',
   *   rsaBits: 4096,
   *   comment: 'Production SSH key'
   * });
   * ```
   */
  async generateKeypair(request: GenerateKeypairRequest): Promise<GeneratedKeypair> {
    return this.http.post<GeneratedKeypair>('/v1/secrets/generate-keypair', {
      algorithm: request.algorithm,
      alias: request.alias,
      rsaBits: request.rsaBits,
      ecdsaCurve: request.ecdsaCurve,
      comment: request.comment,
      publishPublicKey: request.publishPublicKey,
      tags: request.tags,
    });
  }

  /**
   * Publish a public key to make it publicly accessible without authentication.
   *
   * Only works for public key sub-types (ed25519_public_key, rsa_public_key, ecdsa_public_key).
   * Once published, the key can be accessed via GET /v1/public/:tenant/:alias.
   *
   * @param secretId - ID of the public key secret to publish
   * @returns Publication result with public URL and fingerprint
   *
   * @example
   * ```typescript
   * const result = await client.secrets.publish('secret-id-123');
   * console.log(`Public key available at: ${result.publicUrl}`);
   * console.log(`Fingerprint: ${result.fingerprint}`);
   * ```
   */
  async publish(secretId: string): Promise<PublishResult> {
    return this.http.post<PublishResult>(`/v1/secrets/${secretId}/publish`);
  }

  /**
   * Unpublish a public key to make it private again.
   *
   * The key will no longer be accessible via the public endpoint.
   *
   * @param secretId - ID of the public key secret to unpublish
   *
   * @example
   * ```typescript
   * await client.secrets.unpublish('secret-id-123');
   * ```
   */
  async unpublish(secretId: string): Promise<void> {
    await this.http.post(`/v1/secrets/${secretId}/unpublish`);
  }

  /**
   * Get a published public key by tenant and alias (no authentication required).
   *
   * This method does NOT require authentication and can be used to retrieve
   * publicly published keys.
   *
   * @param tenant - Tenant ID
   * @param alias - Public key alias
   * @returns Public key information
   *
   * @example
   * ```typescript
   * // No authentication needed
   * const publicKey = await client.secrets.getPublicKey('acme', 'keys/prod/api-signing-public');
   * console.log(publicKey.publicKey); // PEM or OpenSSH format
   * console.log(publicKey.fingerprint);
   * ```
   */
  async getPublicKey(tenant: string, alias: string): Promise<PublicKeyInfo> {
    const encodedAlias = encodeURIComponent(alias);
    return this.http.get<PublicKeyInfo>(`/v1/public/${tenant}/${encodedAlias}`);
  }

  /**
   * List all published public keys for a tenant (no authentication required).
   *
   * This method does NOT require authentication and can be used to browse
   * all publicly published keys for a tenant.
   *
   * @param tenant - Tenant ID
   * @returns List of published public keys
   *
   * @example
   * ```typescript
   * // No authentication needed
   * const publicKeys = await client.secrets.listPublicKeys('acme');
   * publicKeys.keys.forEach(key => {
   *   console.log(`${key.alias}: ${key.fingerprint}`);
   * });
   * ```
   */
  async listPublicKeys(tenant: string): Promise<PublicKeyList> {
    return this.http.get<PublicKeyList>(`/v1/public/${tenant}`);
  }
}
