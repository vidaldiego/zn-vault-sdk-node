// Path: zn-vault-sdk-node/src/http/client.ts

import https from 'node:https';
import type { ZnVaultErrorResponse, ManagedKeyBindResponse, ManagedKeyConfig } from '../types/index.js';
import type { AuthProvider } from '../auth/provider.js';
import { isRefreshableAuthProvider } from '../auth/provider.js';

export interface HttpClientConfig {
  baseUrl: string;
  apiKey?: string;
  /** Auth provider for API key authentication (alternative to apiKey) */
  authProvider?: AuthProvider;
  timeout?: number;
  retries?: number;
  rejectUnauthorized?: boolean;
  /** Configuration for managed API key auto-rotation */
  managedKey?: ManagedKeyConfig;
}

export type TokenRefreshCallback = () => Promise<string>;

/**
 * Internal state for managed key rotation
 */
interface ManagedKeyState {
  /** The managed key name */
  name: string;
  /** Tenant ID for cross-tenant access */
  tenantId?: string;
  /** Current key value */
  currentKey: string;
  /** When the next rotation will occur */
  nextRotationAt?: Date;
  /** When the grace period expires */
  graceExpiresAt?: Date;
  /** How early to refresh before expiry (ms) */
  refreshBeforeExpiryMs: number;
  /** Scheduled refresh timer */
  refreshTimer?: ReturnType<typeof setTimeout>;
  /** Whether a refresh is in progress */
  isRefreshing: boolean;
  /** Callback when key rotates */
  onKeyRotated?: (newKey: string, oldKey: string) => void;
  /** Callback on rotation error */
  onRotationError?: (error: Error) => void;
}

export class ZnVaultError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public errorCode?: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'ZnVaultError';
  }
}

export class AuthenticationError extends ZnVaultError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 401, 'AUTHENTICATION_ERROR', details);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends ZnVaultError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 403, 'AUTHORIZATION_ERROR', details);
    this.name = 'AuthorizationError';
  }
}

export class NotFoundError extends ZnVaultError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 404, 'NOT_FOUND', details);
    this.name = 'NotFoundError';
  }
}

export class RateLimitError extends ZnVaultError {
  constructor(message: string, public retryAfter?: number) {
    super(message, 429, 'RATE_LIMIT_EXCEEDED');
    this.name = 'RateLimitError';
  }
}

export class ValidationError extends ZnVaultError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 400, 'VALIDATION_ERROR', details);
    this.name = 'ValidationError';
  }
}

interface RequestOptions {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  body?: unknown;
  headers?: Record<string, string>;
  timeout?: number;
}

export class HttpClient {
  private baseUrl: string;
  private apiKey?: string;
  private authProvider?: AuthProvider;
  private accessToken?: string;
  private refreshToken?: string;
  private timeout: number;
  private retryAttempts: number;
  private retryDelay: number;
  private rejectUnauthorized: boolean;
  private tokenRefreshCallback?: TokenRefreshCallback;
  private managedKeyState?: ManagedKeyState;
  private managedKeyConfig?: ManagedKeyConfig;

  constructor(config: HttpClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.apiKey = config.apiKey;
    this.authProvider = config.authProvider;
    this.timeout = config.timeout ?? 30000;
    this.retryAttempts = config.retries ?? 3;
    this.retryDelay = 1000;
    // Respect NODE_TLS_REJECT_UNAUTHORIZED env var if rejectUnauthorized not explicitly set
    this.rejectUnauthorized =
      config.rejectUnauthorized ?? (process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0');
    this.managedKeyConfig = config.managedKey;
  }

  setTokens(accessToken: string, refreshToken?: string): void {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
  }

  getRefreshToken(): string | undefined {
    return this.refreshToken;
  }

  clearTokens(): void {
    this.accessToken = undefined;
    this.refreshToken = undefined;
  }

  onTokenRefresh(callback: TokenRefreshCallback): void {
    this.tokenRefreshCallback = callback;
  }

  // =========================================================================
  // Managed API Key Auto-Rotation
  // =========================================================================

  /**
   * Initialize managed key mode with an initial key value.
   *
   * Call this when you have a managed API key and want the SDK to
   * automatically rotate it before expiration.
   *
   * @param initialKey - The initial API key value (znv_xxx)
   * @param config - Optional override config (uses constructor config if not provided)
   */
  async initManagedKey(initialKey: string, config?: ManagedKeyConfig): Promise<ManagedKeyBindResponse> {
    const effectiveConfig = config ?? this.managedKeyConfig;
    if (!effectiveConfig) {
      throw new Error('Managed key config required - provide via constructor or initManagedKey');
    }

    // Set the initial key so we can make the bind request
    this.apiKey = initialKey;

    // Bind to get current key and rotation metadata
    const bindResponse = await this.bindManagedKeyInternal(
      effectiveConfig.name,
      effectiveConfig.tenantId
    );

    // Initialize state
    this.managedKeyState = {
      name: effectiveConfig.name,
      tenantId: effectiveConfig.tenantId,
      currentKey: bindResponse.key,
      nextRotationAt: bindResponse.nextRotationAt ? new Date(bindResponse.nextRotationAt) : undefined,
      graceExpiresAt: bindResponse.graceExpiresAt ? new Date(bindResponse.graceExpiresAt) : undefined,
      refreshBeforeExpiryMs: effectiveConfig.refreshBeforeExpiryMs ?? 30000,
      isRefreshing: false,
      onKeyRotated: effectiveConfig.onKeyRotated,
      onRotationError: effectiveConfig.onRotationError,
    };

    // Update to the bound key (may be same or new after rotation)
    this.apiKey = bindResponse.key;

    // Schedule next refresh
    this.scheduleManagedKeyRefresh();

    return bindResponse;
  }

  /**
   * Get the current API key value.
   * Useful for debugging or passing to other systems.
   */
  getCurrentApiKey(): string | undefined {
    // Priority: managed key state > direct apiKey > auth provider
    if (this.managedKeyState) {
      return this.managedKeyState.currentKey;
    }
    if (this.apiKey) {
      return this.apiKey;
    }
    return this.authProvider?.getApiKey();
  }

  /**
   * Get the auth provider if set.
   */
  getAuthProvider(): AuthProvider | undefined {
    return this.authProvider;
  }

  /**
   * Check if using managed key mode.
   */
  isManagedKeyMode(): boolean {
    return !!this.managedKeyState;
  }

  /**
   * Get managed key rotation info.
   */
  getManagedKeyInfo(): {
    name: string;
    nextRotationAt?: Date;
    graceExpiresAt?: Date;
    isRefreshing: boolean;
  } | undefined {
    if (!this.managedKeyState) return undefined;
    return {
      name: this.managedKeyState.name,
      nextRotationAt: this.managedKeyState.nextRotationAt,
      graceExpiresAt: this.managedKeyState.graceExpiresAt,
      isRefreshing: this.managedKeyState.isRefreshing,
    };
  }

  /**
   * Force refresh the managed key now.
   * Useful if you detect a key issue or want to proactively rotate.
   */
  async refreshManagedKey(): Promise<ManagedKeyBindResponse> {
    if (!this.managedKeyState) {
      throw new Error('Not in managed key mode - call initManagedKey first');
    }

    return this.doManagedKeyRefresh();
  }

  /**
   * Stop managed key auto-rotation and clear state.
   */
  stopManagedKeyRotation(): void {
    if (this.managedKeyState?.refreshTimer) {
      clearTimeout(this.managedKeyState.refreshTimer);
    }
    this.managedKeyState = undefined;
  }

  /**
   * Internal: bind to managed key endpoint
   */
  private async bindManagedKeyInternal(name: string, tenantId?: string): Promise<ManagedKeyBindResponse> {
    const params = new URLSearchParams();
    if (tenantId) params.append('tenantId', tenantId);
    const query = params.toString();

    return this.request<ManagedKeyBindResponse>({
      method: 'POST',
      path: `/auth/api-keys/managed/${encodeURIComponent(name)}/bind${query ? `?${query}` : ''}`,
      body: {},
    });
  }

  /**
   * Internal: schedule the next managed key refresh
   */
  private scheduleManagedKeyRefresh(): void {
    if (!this.managedKeyState) return;

    // Clear any existing timer
    if (this.managedKeyState.refreshTimer) {
      clearTimeout(this.managedKeyState.refreshTimer);
      this.managedKeyState.refreshTimer = undefined;
    }

    // Determine when to refresh
    const now = Date.now();
    let refreshAt: number | undefined;

    // For scheduled rotation, refresh before nextRotationAt
    if (this.managedKeyState.nextRotationAt) {
      refreshAt = this.managedKeyState.nextRotationAt.getTime() - this.managedKeyState.refreshBeforeExpiryMs;
    }
    // Fallback: refresh before grace period expires
    else if (this.managedKeyState.graceExpiresAt) {
      refreshAt = this.managedKeyState.graceExpiresAt.getTime() - this.managedKeyState.refreshBeforeExpiryMs;
    }

    if (!refreshAt || refreshAt <= now) {
      // Already past refresh time - refresh immediately on next tick
      // (but not synchronously to avoid infinite loops)
      this.managedKeyState.refreshTimer = setTimeout(() => {
        this.doManagedKeyRefresh().catch((err) => {
          this.managedKeyState?.onRotationError?.(err);
        });
      }, 100);
      return;
    }

    // Schedule refresh
    const delay = refreshAt - now;
    this.managedKeyState.refreshTimer = setTimeout(() => {
      this.doManagedKeyRefresh().catch((err) => {
        this.managedKeyState?.onRotationError?.(err);
      });
    }, delay);
  }

  /**
   * Internal: perform managed key refresh
   */
  private async doManagedKeyRefresh(): Promise<ManagedKeyBindResponse> {
    if (!this.managedKeyState) {
      throw new Error('Not in managed key mode');
    }

    // Prevent concurrent refreshes
    if (this.managedKeyState.isRefreshing) {
      // Wait a bit and return current state
      await this.sleep(100);
      return {
        id: '',
        key: this.managedKeyState.currentKey,
        prefix: '',
        name: this.managedKeyState.name,
        expiresAt: '',
        gracePeriod: '',
        rotationMode: 'scheduled',
        permissions: [],
        nextRotationAt: this.managedKeyState.nextRotationAt?.toISOString(),
        graceExpiresAt: this.managedKeyState.graceExpiresAt?.toISOString(),
      };
    }

    this.managedKeyState.isRefreshing = true;
    const oldKey = this.managedKeyState.currentKey;

    try {
      // Bind to get new key
      const bindResponse = await this.bindManagedKeyInternal(
        this.managedKeyState.name,
        this.managedKeyState.tenantId
      );

      // Update state
      const newKey = bindResponse.key;
      this.managedKeyState.currentKey = newKey;
      this.managedKeyState.nextRotationAt = bindResponse.nextRotationAt
        ? new Date(bindResponse.nextRotationAt)
        : undefined;
      this.managedKeyState.graceExpiresAt = bindResponse.graceExpiresAt
        ? new Date(bindResponse.graceExpiresAt)
        : undefined;

      // Update the API key used for requests
      this.apiKey = newKey;

      // Notify callback if key changed
      if (newKey !== oldKey) {
        this.managedKeyState.onKeyRotated?.(newKey, oldKey);
      }

      // Schedule next refresh
      this.scheduleManagedKeyRefresh();

      return bindResponse;
    } finally {
      if (this.managedKeyState) {
        this.managedKeyState.isRefreshing = false;
      }
    }
  }

  async request<T>(options: RequestOptions): Promise<T> {
    let lastError: Error | undefined;
    let authProviderRefreshAttempted = false;

    for (let attempt = 0; attempt <= this.retryAttempts; attempt++) {
      try {
        return await this.executeRequest<T>(options);
      } catch (error) {
        lastError = error as Error;

        // Handle 401 with JWT token refresh (only if we have a refresh token)
        if (
          error instanceof AuthenticationError &&
          this.tokenRefreshCallback &&
          this.refreshToken &&
          attempt === 0
        ) {
          try {
            const newToken = await this.tokenRefreshCallback();
            this.accessToken = newToken;
            continue;
          } catch {
            throw error;
          }
        }

        // Handle 401 with refreshable auth provider (file-based API key)
        if (
          error instanceof AuthenticationError &&
          this.authProvider &&
          isRefreshableAuthProvider(this.authProvider) &&
          !authProviderRefreshAttempted
        ) {
          authProviderRefreshAttempted = true;
          if (this.authProvider.onAuthenticationError()) {
            // Key was refreshed, retry the request
            continue;
          }
          // Key unchanged, don't retry - it's a real auth error
          throw error;
        }

        if (error instanceof RateLimitError) {
          const delay = error.retryAfter ? error.retryAfter * 1000 : this.retryDelay * Math.pow(2, attempt);
          await this.sleep(delay);
          continue;
        }

        if (error instanceof ZnVaultError && error.statusCode >= 400 && error.statusCode < 500) {
          throw error;
        }

        if (attempt < this.retryAttempts) {
          await this.sleep(this.retryDelay * Math.pow(2, attempt));
        }
      }
    }

    throw lastError;
  }

  private async executeRequest<T>(options: RequestOptions): Promise<T> {
    return new Promise((resolve, reject) => {
      const url = new URL(options.path, this.baseUrl);
      const headers: Record<string, string> = {
        'Accept': 'application/json',
        ...options.headers,
      };

      // Only set Content-Type for requests that have a body
      if (options.body !== undefined) {
        headers['Content-Type'] = 'application/json';
      }

      // Get API key from: direct apiKey > auth provider
      const apiKey = this.apiKey ?? this.authProvider?.getApiKey();
      if (apiKey) {
        headers['X-API-Key'] = apiKey;
      } else if (this.accessToken) {
        headers['Authorization'] = `Bearer ${this.accessToken}`;
      }

      const requestOptions: https.RequestOptions = {
        method: options.method,
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname + url.search,
        headers,
        timeout: options.timeout ?? this.timeout,
        rejectUnauthorized: this.rejectUnauthorized,
      };

      const req = https.request(requestOptions, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          const statusCode = res.statusCode ?? 500;

          if (statusCode >= 200 && statusCode < 300) {
            if (!data) {
              resolve(undefined as T);
              return;
            }
            try {
              resolve(JSON.parse(data) as T);
            } catch {
              resolve(data as T);
            }
            return;
          }

          let errorResponse: ZnVaultErrorResponse;
          try {
            errorResponse = JSON.parse(data);
          } catch {
            errorResponse = {
              error: 'Unknown Error',
              message: data || 'Request failed',
              statusCode,
            };
          }

          const error = this.createError(statusCode, errorResponse, res.headers);
          reject(error);
        });
      });

      req.on('error', (error) => {
        reject(new ZnVaultError(`Connection error: ${error.message}`, 0, 'CONNECTION_ERROR'));
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new ZnVaultError('Request timeout', 0, 'TIMEOUT'));
      });

      if (options.body) {
        req.write(JSON.stringify(options.body));
      }

      req.end();
    });
  }

  private createError(
    statusCode: number,
    response: ZnVaultErrorResponse,
    headers: Record<string, unknown>
  ): ZnVaultError {
    const message = response.message || response.error || 'Request failed';
    const details = response.details;

    switch (statusCode) {
      case 400:
        return new ValidationError(message, details);
      case 401:
        return new AuthenticationError(message, details);
      case 403:
        return new AuthorizationError(message, details);
      case 404:
        return new NotFoundError(message, details);
      case 429: {
        const retryAfter = headers['retry-after'];
        return new RateLimitError(
          message,
          typeof retryAfter === 'string' ? parseInt(retryAfter, 10) : undefined
        );
      }
      default:
        return new ZnVaultError(message, statusCode, response.error, details);
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async get<T>(path: string, headers?: Record<string, string>): Promise<T> {
    return this.request<T>({ method: 'GET', path, headers });
  }

  async post<T>(path: string, body?: unknown, headers?: Record<string, string>): Promise<T> {
    return this.request<T>({ method: 'POST', path, body, headers });
  }

  async put<T>(path: string, body?: unknown, headers?: Record<string, string>): Promise<T> {
    return this.request<T>({ method: 'PUT', path, body, headers });
  }

  async patch<T>(path: string, body?: unknown, headers?: Record<string, string>): Promise<T> {
    return this.request<T>({ method: 'PATCH', path, body, headers });
  }

  async delete<T>(path: string, headers?: Record<string, string>): Promise<T> {
    return this.request<T>({ method: 'DELETE', path, headers });
  }
}
