// Path: zn-vault-sdk-node/src/index.ts

import { HttpClient, type HttpClientConfig } from './http/client.js';
import { AuthClient } from './auth/client.js';
import { SecretsClient } from './secrets/client.js';
import { KmsClient } from './kms/client.js';
import { CertificatesClient } from './certificates/client.js';
import { UsersClient } from './admin/users.js';
import { RolesClient } from './admin/roles.js';
import { TenantsClient } from './admin/tenants.js';
import { PoliciesClient } from './admin/policies.js';
import { AuditClient } from './audit/client.js';
import { HealthClient } from './health/client.js';
import {
  type AuthProvider,
  FileApiKeyAuth,
} from './auth/provider.js';

import type { ManagedKeyConfig, ManagedKeyBindResponse } from './types/index.js';

/** Default environment variable name for vault URL */
export const DEFAULT_URL_ENV = 'ZINC_CONFIG_VAULT_URL';

/** Default environment variable name for API key */
export const DEFAULT_API_KEY_ENV = 'ZINC_CONFIG_VAULT_API_KEY';

/** Default base URL when not specified */
export const DEFAULT_BASE_URL = 'https://localhost:8443';

export interface ZnVaultConfig {
  /** Base URL of the ZnVault server (e.g., 'https://vault.example.com:8443') */
  baseUrl: string;
  /** API key for authentication (optional, use instead of JWT) */
  apiKey?: string;
  /** Path to file containing API key (supports auto-refresh on rotation) */
  apiKeyFile?: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Number of retry attempts for failed requests (default: 3) */
  retries?: number;
  /** Skip TLS certificate verification (not recommended for production) */
  rejectUnauthorized?: boolean;
  /** Configuration for managed API key auto-rotation */
  managedKey?: ManagedKeyConfig;
}

export class ZnVaultClient {
  private httpClient: HttpClient;
  private _auth: AuthClient;
  private _secrets: SecretsClient;
  private _kms: KmsClient;
  private _certificates: CertificatesClient;
  private _users: UsersClient;
  private _roles: RolesClient;
  private _tenants: TenantsClient;
  private _policies: PoliciesClient;
  private _audit: AuditClient;
  private _health: HealthClient;

  constructor(config: ZnVaultConfig) {
    // Determine auth provider based on config priority:
    // 1. Direct apiKey
    // 2. apiKeyFile (file-based with auto-refresh)
    let authProvider: AuthProvider | undefined;
    if (config.apiKeyFile && !config.apiKey) {
      authProvider = new FileApiKeyAuth(config.apiKeyFile);
    }

    const httpConfig: HttpClientConfig = {
      baseUrl: config.baseUrl,
      apiKey: config.apiKey,
      authProvider,
      timeout: config.timeout ?? 30000,
      retries: config.retries ?? 3,
      rejectUnauthorized: config.rejectUnauthorized, // Let HttpClient handle default (respects NODE_TLS_REJECT_UNAUTHORIZED)
      managedKey: config.managedKey,
    };

    this.httpClient = new HttpClient(httpConfig);

    // Initialize all clients
    this._auth = new AuthClient(this.httpClient);
    this._secrets = new SecretsClient(this.httpClient);
    this._kms = new KmsClient(this.httpClient);
    this._certificates = new CertificatesClient(this.httpClient);
    this._users = new UsersClient(this.httpClient);
    this._roles = new RolesClient(this.httpClient);
    this._tenants = new TenantsClient(this.httpClient);
    this._policies = new PoliciesClient(this.httpClient);
    this._audit = new AuditClient(this.httpClient);
    this._health = new HealthClient(this.httpClient);

    // Set up automatic token refresh
    this.httpClient.onTokenRefresh(async () => {
      const refreshToken = this.httpClient.getRefreshToken();
      if (refreshToken) {
        const result = await this._auth.refresh(refreshToken);
        return result.accessToken;
      }
      throw new Error('No refresh token available');
    });
  }

  /** Authentication operations */
  get auth(): AuthClient {
    return this._auth;
  }

  /** Secret management operations */
  get secrets(): SecretsClient {
    return this._secrets;
  }

  /** KMS (Key Management Service) operations */
  get kms(): KmsClient {
    return this._kms;
  }

  /** Certificate lifecycle management operations */
  get certificates(): CertificatesClient {
    return this._certificates;
  }

  /** User management (admin) */
  get users(): UsersClient {
    return this._users;
  }

  /** Role management (admin) */
  get roles(): RolesClient {
    return this._roles;
  }

  /** Tenant management (admin) */
  get tenants(): TenantsClient {
    return this._tenants;
  }

  /** Policy management (admin) */
  get policies(): PoliciesClient {
    return this._policies;
  }

  /** Audit log operations */
  get audit(): AuditClient {
    return this._audit;
  }

  /** Health check operations */
  get health(): HealthClient {
    return this._health;
  }

  /**
   * Login with username and password
   * Automatically stores tokens for subsequent requests
   */
  async login(username: string, password: string, totpCode?: string) {
    const result = await this._auth.login({ username, password, totpCode });
    this.httpClient.setTokens(result.accessToken, result.refreshToken);
    return result;
  }

  /**
   * Logout and clear stored tokens
   */
  async logout() {
    try {
      await this._auth.logout();
    } finally {
      this.httpClient.clearTokens();
    }
  }

  /**
   * Manually set authentication tokens
   */
  setTokens(accessToken: string, refreshToken?: string) {
    this.httpClient.setTokens(accessToken, refreshToken);
  }

  /**
   * Clear stored authentication tokens
   */
  clearTokens() {
    this.httpClient.clearTokens();
  }

  // =========================================================================
  // Managed API Key Auto-Rotation
  // =========================================================================

  /**
   * Initialize managed key mode for automatic rotation.
   *
   * This sets up the SDK to automatically rotate the API key before it expires.
   * The SDK will call the bind endpoint to get new keys during the grace period.
   *
   * @example
   * ```typescript
   * const client = new ZnVaultClient({
   *   baseUrl: 'https://vault.example.com:8443',
   *   managedKey: {
   *     name: 'my-agent-key',
   *     onKeyRotated: (newKey, oldKey) => {
   *       console.log('Key rotated!');
   *     },
   *   },
   * });
   *
   * // Initialize with your current key value
   * await client.initManagedKey('znv_xxx...');
   *
   * // Now use the client normally - keys will auto-rotate
   * const secret = await client.secrets.get('my-secret');
   * ```
   *
   * @param initialKey - The initial API key value (znv_xxx)
   * @param config - Optional override config (uses constructor config if not provided)
   * @returns The bind response with current key and rotation metadata
   */
  async initManagedKey(initialKey: string, config?: ManagedKeyConfig): Promise<ManagedKeyBindResponse> {
    return this.httpClient.initManagedKey(initialKey, config);
  }

  /**
   * Get the current API key value.
   * Useful for debugging or passing to other systems.
   */
  getCurrentApiKey(): string | undefined {
    return this.httpClient.getCurrentApiKey();
  }

  /**
   * Check if using managed key mode with auto-rotation.
   */
  isManagedKeyMode(): boolean {
    return this.httpClient.isManagedKeyMode();
  }

  /**
   * Get managed key rotation information.
   */
  getManagedKeyInfo(): {
    name: string;
    nextRotationAt?: Date;
    graceExpiresAt?: Date;
    isRefreshing: boolean;
  } | undefined {
    return this.httpClient.getManagedKeyInfo();
  }

  /**
   * Force refresh the managed key immediately.
   * Useful if you detect a key issue or want to proactively rotate.
   */
  async refreshManagedKey(): Promise<ManagedKeyBindResponse> {
    return this.httpClient.refreshManagedKey();
  }

  /**
   * Stop managed key auto-rotation and clear state.
   */
  stopManagedKeyRotation() {
    this.httpClient.stopManagedKeyRotation();
  }

  /**
   * Create a new client instance with a builder pattern
   */
  static builder(): ZnVaultClientBuilder {
    return new ZnVaultClientBuilder();
  }

  /**
   * Create a client with minimal configuration
   */
  static create(baseUrl: string): ZnVaultClient {
    return new ZnVaultClient({ baseUrl });
  }

  /**
   * Create a client from environment variables.
   *
   * Uses default environment variable names:
   * - `ZINC_CONFIG_VAULT_URL` for the vault URL (defaults to https://localhost:8443)
   * - `ZINC_CONFIG_VAULT_API_KEY` for the API key
   * - `ZINC_CONFIG_VAULT_API_KEY_FILE` for file-based API key (takes precedence, supports auto-refresh)
   *
   * ## Example
   *
   * ```typescript
   * // Agent injects:
   * //   ZINC_CONFIG_VAULT_URL=https://vault.example.com
   * //   ZINC_CONFIG_VAULT_API_KEY_FILE=/run/zn-vault-agent/secrets/ZINC_CONFIG_VAULT_API_KEY
   *
   * const client = ZnVaultClient.fromEnv();
   * const secret = await client.secrets.get('my-secret');  // Auto-refreshes on key rotation
   * ```
   *
   * @returns ZnVaultClient configured from environment
   * @throws Error if required environment variables are not set
   */
  static fromEnv(): ZnVaultClient {
    const baseUrl = process.env[DEFAULT_URL_ENV] ?? DEFAULT_BASE_URL;
    return ZnVaultClient.builder()
      .baseUrl(baseUrl)
      .apiKeyFromEnv(DEFAULT_API_KEY_ENV)
      .build();
  }

  /**
   * Create a client from custom environment variable names.
   *
   * ## Example
   *
   * ```typescript
   * // Custom env vars:
   * //   MY_VAULT_URL=https://vault.example.com
   * //   MY_API_KEY_FILE=/path/to/api-key
   *
   * const client = ZnVaultClient.fromEnv('MY_VAULT_URL', 'MY_API_KEY');
   * ```
   *
   * @param urlEnvName Environment variable name for vault URL
   * @param apiKeyEnvName Environment variable name for API key (checks _FILE suffix first)
   * @returns ZnVaultClient configured from environment
   * @throws Error if required environment variables are not set
   */
  static fromEnvCustom(urlEnvName: string, apiKeyEnvName: string): ZnVaultClient {
    const baseUrl = process.env[urlEnvName];
    if (!baseUrl) {
      throw new Error(`Environment variable ${urlEnvName} not set`);
    }
    return ZnVaultClient.builder()
      .baseUrl(baseUrl)
      .apiKeyFromEnv(apiKeyEnvName)
      .build();
  }
}

export class ZnVaultClientBuilder {
  private config: Partial<ZnVaultConfig> = {};
  private _apiKeyEnvName?: string;

  baseUrl(url: string): this {
    this.config.baseUrl = url;
    return this;
  }

  /**
   * Set API key for authentication.
   *
   * When set, the client will use API key authentication instead of JWT.
   * For automatic key rotation support, use `apiKeyFile()` or `apiKeyFromEnv()` instead.
   *
   * @param key API key (e.g., "znv_xxxx_secretkey")
   */
  apiKey(key: string): this {
    this.config.apiKey = key;
    this.config.apiKeyFile = undefined;
    this._apiKeyEnvName = undefined;
    return this;
  }

  /**
   * Set API key file path for authentication with automatic refresh.
   *
   * The API key will be read from the specified file. When a 401 error
   * occurs, the file will be re-read and the request retried if the
   * key has changed. This supports automatic key rotation by zn-vault-agent.
   *
   * @param filePath Path to file containing the API key
   */
  apiKeyFile(filePath: string): this {
    this.config.apiKeyFile = filePath;
    this.config.apiKey = undefined;
    this._apiKeyEnvName = undefined;
    return this;
  }

  /**
   * Set API key from environment variable with automatic file detection.
   *
   * Checks for the API key in this order:
   * 1. `{envName}_FILE` - path to file containing the key (supports auto-refresh)
   * 2. `{envName}` - direct API key value
   *
   * This is the recommended approach when using zn-vault-agent, which sets
   * the _FILE variant automatically.
   *
   * @example
   * ```typescript
   * // With env: VAULT_API_KEY_FILE=/run/zn-vault-agent/secrets/api-key
   * const client = ZnVaultClient.builder()
   *   .baseUrl('https://vault.example.com')
   *   .apiKeyFromEnv('VAULT_API_KEY')
   *   .build();
   * ```
   *
   * @param envName Base environment variable name
   */
  apiKeyFromEnv(envName: string): this {
    this._apiKeyEnvName = envName;
    this.config.apiKey = undefined;
    this.config.apiKeyFile = undefined;
    return this;
  }

  timeout(ms: number): this {
    this.config.timeout = ms;
    return this;
  }

  retries(count: number): this {
    this.config.retries = count;
    return this;
  }

  rejectUnauthorized(value: boolean): this {
    this.config.rejectUnauthorized = value;
    return this;
  }

  /**
   * Configure managed API key auto-rotation.
   *
   * @example
   * ```typescript
   * const client = ZnVaultClient.builder()
   *   .baseUrl('https://vault.example.com:8443')
   *   .managedKey({
   *     name: 'my-agent-key',
   *     onKeyRotated: (newKey) => console.log('Rotated to', newKey),
   *   })
   *   .build();
   *
   * // Initialize with initial key
   * await client.initManagedKey('znv_xxx...');
   * ```
   */
  managedKey(config: ManagedKeyConfig): this {
    this.config.managedKey = config;
    return this;
  }

  build(): ZnVaultClient {
    if (!this.config.baseUrl) {
      throw new Error('baseUrl is required');
    }

    // Resolve apiKeyFromEnv if set
    if (this._apiKeyEnvName) {
      const filePath = process.env[`${this._apiKeyEnvName}_FILE`];
      const directValue = process.env[this._apiKeyEnvName];

      if (filePath) {
        this.config.apiKeyFile = filePath;
      } else if (directValue) {
        this.config.apiKey = directValue;
      } else {
        throw new Error(
          `No API key configured. Set either ${this._apiKeyEnvName}_FILE (recommended) or ${this._apiKeyEnvName} environment variable.`
        );
      }
    }

    return new ZnVaultClient(this.config as ZnVaultConfig);
  }
}

// Re-export types
export * from './types/index.js';

// Re-export clients
export { AuthClient } from './auth/index.js';
export { SecretsClient } from './secrets/index.js';
export { KmsClient } from './kms/index.js';
export { CertificatesClient } from './certificates/index.js';
export { UsersClient, RolesClient, TenantsClient, PoliciesClient } from './admin/index.js';
export { AuditClient, type AuditVerifyResult } from './audit/index.js';
export { HealthClient, type HealthStatus, type ReadinessStatus } from './health/index.js';

// Re-export auth providers
export {
  type AuthProvider,
  type RefreshableAuthProvider,
  ApiKeyAuth,
  FileApiKeyAuth,
  isRefreshableAuthProvider,
} from './auth/index.js';

// Re-export errors
export {
  ZnVaultError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  RateLimitError,
  ValidationError,
} from './http/client.js';

// Re-export SSO client for token validation
export {
  SSOClient,
  SSOError,
  SSOAuthError,
  createSSOClient,
  createFastifySSOAuth,
  createExpressSSOAuth,
  type SSOClientConfig,
  type ValidatedToken,
  type TokenIntrospectionResponse,
  type SSORequest,
} from './sso/index.js';
