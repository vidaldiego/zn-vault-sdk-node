// Path: zn-vault-sdk-node/src/index.ts

import { HttpClient, type HttpClientConfig } from './http/client.js';
import { AuthClient } from './auth/client.js';
import { SecretsClient } from './secrets/client.js';
import { KmsClient } from './kms/client.js';
import { UsersClient } from './admin/users.js';
import { RolesClient } from './admin/roles.js';
import { TenantsClient } from './admin/tenants.js';
import { PoliciesClient } from './admin/policies.js';
import { AuditClient } from './audit/client.js';
import { HealthClient } from './health/client.js';

export interface ZnVaultConfig {
  /** Base URL of the ZN-Vault server (e.g., 'https://vault.example.com:8443') */
  baseUrl: string;
  /** API key for authentication (optional, use instead of JWT) */
  apiKey?: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Number of retry attempts for failed requests (default: 3) */
  retries?: number;
  /** Skip TLS certificate verification (not recommended for production) */
  rejectUnauthorized?: boolean;
}

export class ZnVaultClient {
  private httpClient: HttpClient;
  private _auth: AuthClient;
  private _secrets: SecretsClient;
  private _kms: KmsClient;
  private _users: UsersClient;
  private _roles: RolesClient;
  private _tenants: TenantsClient;
  private _policies: PoliciesClient;
  private _audit: AuditClient;
  private _health: HealthClient;

  constructor(config: ZnVaultConfig) {
    const httpConfig: HttpClientConfig = {
      baseUrl: config.baseUrl,
      apiKey: config.apiKey,
      timeout: config.timeout ?? 30000,
      retries: config.retries ?? 3,
      rejectUnauthorized: config.rejectUnauthorized ?? true,
    };

    this.httpClient = new HttpClient(httpConfig);

    // Initialize all clients
    this._auth = new AuthClient(this.httpClient);
    this._secrets = new SecretsClient(this.httpClient);
    this._kms = new KmsClient(this.httpClient);
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
}

export class ZnVaultClientBuilder {
  private config: Partial<ZnVaultConfig> = {};

  baseUrl(url: string): this {
    this.config.baseUrl = url;
    return this;
  }

  apiKey(key: string): this {
    this.config.apiKey = key;
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

  build(): ZnVaultClient {
    if (!this.config.baseUrl) {
      throw new Error('baseUrl is required');
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
export { UsersClient, RolesClient, TenantsClient, PoliciesClient } from './admin/index.js';
export { AuditClient, type AuditVerifyResult } from './audit/index.js';
export { HealthClient, type HealthStatus, type ReadinessStatus } from './health/index.js';

// Re-export errors
export {
  ZnVaultError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  RateLimitError,
  ValidationError,
} from './http/client.js';
