// Path: zn-vault-sdk-node/src/sso/client.ts
// SSO Client for token validation and OAuth2 flows

import https from 'node:https';
import crypto from 'node:crypto';
import type {
  SSOClientConfig,
  TokenIntrospectionResponse,
  ValidatedToken,
  UserInfoResponse,
  TokenResponse,
  AuthorizationUrlOptions,
  TokenExchangeOptions,
} from './types.js';

/**
 * Error thrown for SSO-related failures
 */
export class SSOError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode?: number
  ) {
    super(message);
    this.name = 'SSOError';
  }
}

/**
 * Simple LRU cache for introspection results
 */
class IntrospectionCache {
  private cache: Map<string, { response: TokenIntrospectionResponse; expiresAt: number }> = new Map();
  private maxSize = 1000;

  get(tokenHash: string): TokenIntrospectionResponse | undefined {
    const entry = this.cache.get(tokenHash);
    if (!entry) return undefined;

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(tokenHash);
      return undefined;
    }

    return entry.response;
  }

  set(tokenHash: string, response: TokenIntrospectionResponse, ttlMs: number): void {
    // Evict old entries if cache is full
    if (this.cache.size >= this.maxSize) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) this.cache.delete(oldestKey);
    }

    this.cache.set(tokenHash, {
      response,
      expiresAt: Date.now() + ttlMs,
    });
  }

  invalidate(tokenHash: string): void {
    this.cache.delete(tokenHash);
  }

  clear(): void {
    this.cache.clear();
  }
}

/**
 * SSO Client for validating tokens and OAuth2 flows
 *
 * @example Token validation (resource server)
 * ```typescript
 * const sso = new SSOClient({
 *   vaultUrl: 'https://vault.example.com',
 *   clientId: 'sso_abc123',
 *   clientSecret: 'znsso_xxx...',
 * });
 *
 * // Validate an access token
 * const token = await sso.validateToken('Bearer xxx...');
 * if (token) {
 *   console.log(`User: ${token.username}, Role: ${token.role}`);
 * }
 * ```
 *
 * @example OAuth2 authorization code flow (client app)
 * ```typescript
 * // 1. Generate authorization URL
 * const { url, codeVerifier, state } = sso.createAuthorizationUrl({
 *   redirectUri: 'https://myapp.com/callback',
 *   scopes: ['openid', 'profile', 'email'],
 * });
 *
 * // 2. Redirect user to `url`
 *
 * // 3. Handle callback and exchange code for tokens
 * const tokens = await sso.exchangeCode({
 *   code: callbackCode,
 *   redirectUri: 'https://myapp.com/callback',
 *   codeVerifier,
 * });
 * ```
 */
export class SSOClient {
  private config: Required<Omit<SSOClientConfig, 'clientSecret'>> & Pick<SSOClientConfig, 'clientSecret'>;
  private cache: IntrospectionCache | null;

  constructor(config: SSOClientConfig) {
    this.config = {
      vaultUrl: config.vaultUrl.replace(/\/$/, ''),
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      timeout: config.timeout ?? 10000,
      rejectUnauthorized: config.rejectUnauthorized ?? true,
      cacheIntrospection: config.cacheIntrospection ?? true,
      introspectionCacheTtlMs: config.introspectionCacheTtlMs ?? 60000,
    };

    this.cache = this.config.cacheIntrospection ? new IntrospectionCache() : null;
  }

  // ===========================================================================
  // Token Validation (Resource Server)
  // ===========================================================================

  /**
   * Validate an access token using the introspection endpoint.
   *
   * This is the primary method for resource servers to validate incoming tokens.
   * Results are cached by default to reduce latency on subsequent requests.
   *
   * @param token - The access token (with or without 'Bearer ' prefix)
   * @returns ValidatedToken if valid, null if invalid/expired
   * @throws SSOError on network or server errors
   */
  async validateToken(token: string): Promise<ValidatedToken | null> {
    const cleanToken = token.replace(/^Bearer\s+/i, '');
    const tokenHash = this.hashToken(cleanToken);

    // Check cache first
    if (this.cache) {
      const cached = this.cache.get(tokenHash);
      if (cached !== undefined) {
        return cached.active ? this.parseIntrospectionResponse(cached) : null;
      }
    }

    // Call introspection endpoint
    const response = await this.introspect(cleanToken);

    // Cache the result
    if (this.cache) {
      // Cache valid tokens for configured TTL, cache invalid tokens for shorter time
      const ttl = response.active
        ? this.config.introspectionCacheTtlMs
        : Math.min(10000, this.config.introspectionCacheTtlMs);
      this.cache.set(tokenHash, response, ttl);
    }

    if (!response.active) {
      return null;
    }

    return this.parseIntrospectionResponse(response);
  }

  /**
   * Raw token introspection call (RFC 7662).
   * Use validateToken() for most cases.
   */
  async introspect(token: string): Promise<TokenIntrospectionResponse> {
    const body = new URLSearchParams();
    body.append('token', token);
    body.append('token_type_hint', 'access_token');

    const response = await this.request<TokenIntrospectionResponse>('POST', '/oauth/introspect', body);
    return response;
  }

  /**
   * Get user info for a valid access token.
   */
  async getUserInfo(accessToken: string): Promise<UserInfoResponse> {
    const cleanToken = accessToken.replace(/^Bearer\s+/i, '');
    return this.request<UserInfoResponse>('GET', '/oauth/userinfo', undefined, {
      Authorization: `Bearer ${cleanToken}`,
    });
  }

  /**
   * Check if a token has a specific scope.
   */
  hasScope(token: ValidatedToken, scope: string): boolean {
    return token.scopes.includes(scope);
  }

  /**
   * Check if a token has all of the specified scopes.
   */
  hasAllScopes(token: ValidatedToken, scopes: string[]): boolean {
    return scopes.every(scope => token.scopes.includes(scope));
  }

  /**
   * Check if a token has any of the specified scopes.
   */
  hasAnyScope(token: ValidatedToken, scopes: string[]): boolean {
    return scopes.some(scope => token.scopes.includes(scope));
  }

  /**
   * Check if a token has a specific role.
   */
  hasRole(token: ValidatedToken, role: string): boolean {
    return token.role === role;
  }

  /**
   * Check if a token has any of the specified roles.
   */
  hasAnyRole(token: ValidatedToken, roles: string[]): boolean {
    return roles.includes(token.role);
  }

  /**
   * Invalidate a cached token (e.g., after logout).
   */
  invalidateCachedToken(token: string): void {
    if (this.cache) {
      const cleanToken = token.replace(/^Bearer\s+/i, '');
      this.cache.invalidate(this.hashToken(cleanToken));
    }
  }

  /**
   * Clear the entire introspection cache.
   */
  clearCache(): void {
    this.cache?.clear();
  }

  // ===========================================================================
  // OAuth2 Authorization Code Flow (Client Application)
  // ===========================================================================

  /**
   * Create an authorization URL for the OAuth2 authorization code flow.
   *
   * @param options - Authorization options
   * @returns URL to redirect the user to, plus state and codeVerifier for PKCE
   */
  createAuthorizationUrl(options: AuthorizationUrlOptions): {
    url: string;
    state: string;
    codeVerifier?: string;
    codeChallenge?: string;
  } {
    const state = options.state ?? crypto.randomBytes(32).toString('base64url');
    const scopes = options.scopes ?? ['openid', 'profile', 'email'];

    let codeVerifier: string | undefined;
    let codeChallenge = options.codeChallenge;
    const codeChallengeMethod = options.codeChallengeMethod ?? 'S256';

    // Generate PKCE challenge if not provided
    if (!codeChallenge) {
      codeVerifier = crypto.randomBytes(32).toString('base64url');
      codeChallenge = crypto
        .createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');
    }

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: options.redirectUri,
      scope: scopes.join(' '),
      state,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
    });

    if (options.nonce) {
      params.append('nonce', options.nonce);
    }

    return {
      url: `${this.config.vaultUrl}/oauth/authorize?${params.toString()}`,
      state,
      codeVerifier,
      codeChallenge,
    };
  }

  /**
   * Exchange an authorization code for tokens.
   *
   * @param options - Token exchange options
   * @returns Access token, refresh token, and optionally ID token
   */
  async exchangeCode(options: TokenExchangeOptions): Promise<TokenResponse> {
    const body = new URLSearchParams();
    body.append('grant_type', 'authorization_code');
    body.append('code', options.code);
    body.append('redirect_uri', options.redirectUri);
    body.append('client_id', this.config.clientId);

    if (this.config.clientSecret) {
      body.append('client_secret', this.config.clientSecret);
    }

    if (options.codeVerifier) {
      body.append('code_verifier', options.codeVerifier);
    }

    const response = await this.request<{
      access_token: string;
      token_type: string;
      expires_in: number;
      refresh_token?: string;
      id_token?: string;
      scope?: string;
    }>('POST', '/oauth/token', body);

    return {
      accessToken: response.access_token,
      tokenType: 'Bearer',
      expiresIn: response.expires_in,
      refreshToken: response.refresh_token,
      idToken: response.id_token,
      scope: response.scope,
    };
  }

  /**
   * Refresh an access token using a refresh token.
   */
  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    const body = new URLSearchParams();
    body.append('grant_type', 'refresh_token');
    body.append('refresh_token', refreshToken);
    body.append('client_id', this.config.clientId);

    if (this.config.clientSecret) {
      body.append('client_secret', this.config.clientSecret);
    }

    const response = await this.request<{
      access_token: string;
      token_type: string;
      expires_in: number;
      scope?: string;
    }>('POST', '/oauth/token', body);

    return {
      accessToken: response.access_token,
      tokenType: 'Bearer',
      expiresIn: response.expires_in,
      scope: response.scope,
    };
  }

  /**
   * Revoke a token (access or refresh).
   */
  async revokeToken(token: string, tokenTypeHint?: 'access_token' | 'refresh_token'): Promise<void> {
    const body = new URLSearchParams();
    body.append('token', token);
    if (tokenTypeHint) {
      body.append('token_type_hint', tokenTypeHint);
    }

    await this.request('POST', '/oauth/revoke', body);

    // Invalidate from cache if it was an access token
    if (!tokenTypeHint || tokenTypeHint === 'access_token') {
      this.invalidateCachedToken(token);
    }
  }

  // ===========================================================================
  // Discovery
  // ===========================================================================

  /**
   * Get the OpenID Connect discovery document.
   */
  async getDiscoveryDocument(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('GET', '/.well-known/openid-configuration');
  }

  /**
   * Get the JSON Web Key Set (JWKS).
   */
  async getJwks(): Promise<{ keys: Array<Record<string, unknown>> }> {
    return this.request<{ keys: Array<Record<string, unknown>> }>('GET', '/.well-known/jwks.json');
  }

  // ===========================================================================
  // Internal
  // ===========================================================================

  private parseIntrospectionResponse(response: TokenIntrospectionResponse): ValidatedToken {
    // Extract app slug from apps object if available
    let appSlug: string | undefined;
    if (response.apps) {
      const slugs = Object.keys(response.apps);
      appSlug = slugs.length > 0 ? slugs[0] : undefined;
    }

    return {
      userId: response.sub!,
      username: response.username!,
      email: response.email,
      tenantId: response.tenantId!,
      clientId: response.clientId ?? response.aud!,
      appSlug,
      role: response.role!,
      scopes: response.scope?.split(' ') ?? [],
      expiresAt: new Date(response.exp! * 1000),
      issuedAt: new Date(response.iat! * 1000),
      raw: response,
    };
  }

  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex').slice(0, 32);
  }

  private async request<T>(
    method: 'GET' | 'POST',
    path: string,
    body?: URLSearchParams,
    extraHeaders?: Record<string, string>
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      const url = new URL(path, this.config.vaultUrl);
      const headers: Record<string, string> = {
        Accept: 'application/json',
        ...extraHeaders,
      };

      if (body) {
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
      }

      // Add client credentials for introspection/token endpoints
      if (this.config.clientSecret && (path === '/oauth/introspect' || path === '/oauth/token' || path === '/oauth/revoke')) {
        const credentials = Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString('base64');
        headers['Authorization'] = `Basic ${credentials}`;
      }

      const requestOptions: https.RequestOptions = {
        method,
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname + url.search,
        headers,
        timeout: this.config.timeout,
        rejectUnauthorized: this.config.rejectUnauthorized,
      };

      const req = https.request(requestOptions, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          const statusCode = res.statusCode ?? 500;

          // 200 OK with empty body (e.g., revoke endpoint)
          if (statusCode === 200 && !data) {
            resolve(undefined as T);
            return;
          }

          let parsed: unknown;
          try {
            parsed = JSON.parse(data);
          } catch {
            if (statusCode >= 200 && statusCode < 300) {
              resolve(data as T);
              return;
            }
            reject(new SSOError(`Invalid response: ${data}`, 'INVALID_RESPONSE', statusCode));
            return;
          }

          if (statusCode >= 200 && statusCode < 300) {
            resolve(parsed as T);
            return;
          }

          // OAuth2 error format
          const errorResponse = parsed as { error?: string; error_description?: string };
          const message = errorResponse.error_description || errorResponse.error || 'Request failed';
          reject(new SSOError(message, errorResponse.error || 'REQUEST_FAILED', statusCode));
        });
      });

      req.on('error', (error) => {
        reject(new SSOError(`Connection error: ${error.message}`, 'CONNECTION_ERROR'));
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new SSOError('Request timeout', 'TIMEOUT'));
      });

      if (body) {
        req.write(body.toString());
      }
      req.end();
    });
  }
}
