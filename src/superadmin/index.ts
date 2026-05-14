// Path: zn-vault-sdk-node/src/superadmin/index.ts

import { HttpClient, type HttpClientConfig } from '../http/client.js';
import { AuditClient } from '../audit/client.js';
import { HealthClient } from '../health/client.js';
import { TenantsClient } from '../admin/tenants.js';
import { type AuthProvider, FileApiKeyAuth } from '../auth/provider.js';
import { SuperadminAuthClient } from './auth.js';

export interface ZnVaultSuperadminConfig {
  /** Base URL of the ZnVault server */
  baseUrl: string;
  /** API key for authentication (must belong to a superadmin) */
  apiKey?: string;
  /** Path to file containing API key (supports auto-refresh on rotation) */
  apiKeyFile?: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Number of retry attempts for failed requests (default: 3) */
  retries?: number;
  /** Skip TLS certificate verification (not recommended for production) */
  rejectUnauthorized?: boolean;
}

/**
 * Superadmin-scoped client for cross-tenant administrative operations.
 *
 * Use this client only with a superadmin principal. For tenant operations
 * (encrypt/decrypt, secrets, your own tenant's users/roles/policies), use
 * `ZnVaultClient`.
 *
 * The split is intentional: a service that holds a tenant-scoped API key
 * cannot compile against the superadmin surface, so it can't accidentally
 * call cross-tenant operations even if it wanted to.
 *
 * **Note:** the cross-tenant API key and registration token operations on
 * `auth` (a `SuperadminAuthClient`) target `/v1/superadmin/api-keys/*`
 * routes which are not yet implemented on the vault server (as of 1.38.8).
 * Those calls will 404 until the server adds them.
 *
 * ## Example
 * ```typescript
 * const admin = new ZnVaultSuperadminClient({
 *   baseUrl: 'https://vault.example.com:8443',
 *   apiKey: 'znv_superadmin_xxx',
 * });
 *
 * const tenant = await admin.tenants.create({ id: 'acme', name: 'Acme' });
 * ```
 */
export class ZnVaultSuperadminClient {
  private httpClient: HttpClient;
  private _tenants: TenantsClient;
  private _auth: SuperadminAuthClient;
  private _audit: AuditClient;
  private _health: HealthClient;

  constructor(config: ZnVaultSuperadminConfig) {
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
      rejectUnauthorized: config.rejectUnauthorized,
    };

    this.httpClient = new HttpClient(httpConfig);
    this._tenants = new TenantsClient(this.httpClient);
    this._auth = new SuperadminAuthClient(this.httpClient);
    this._audit = new AuditClient(this.httpClient);
    this._health = new HealthClient(this.httpClient);
  }

  /** Tenant CRUD (superadmin only). */
  get tenants(): TenantsClient {
    return this._tenants;
  }

  /**
   * Cross-tenant API key / managed-key / registration-token management.
   *
   * Calls routes under `/v1/superadmin/api-keys/` — not yet implemented on
   * the server (will 404 until those routes ship).
   */
  get auth(): SuperadminAuthClient {
    return this._auth;
  }

  /** Audit log across all tenants. */
  get audit(): AuditClient {
    return this._audit;
  }

  /** Health check operations. */
  get health(): HealthClient {
    return this._health;
  }

  /** Manually set authentication tokens (e.g., after login). */
  setTokens(accessToken: string, refreshToken?: string): void {
    this.httpClient.setTokens(accessToken, refreshToken);
  }

  /** Clear stored authentication tokens. */
  clearTokens(): void {
    this.httpClient.clearTokens();
  }
}

export { SuperadminAuthClient } from './auth.js';
