// Path: zn-vault-sdk-node/src/sso/types.ts
// SSO Client Types

/**
 * SSO App registration info
 */
export interface SSOApp {
  id: string;
  tenantId: string;
  slug: string;
  name: string;
  description?: string;
  iconUrl?: string;
  clientId: string;
  redirectUris: string[];
  allowedScopes: string[];
  roles: string[];
  defaultRole: string;
  active: boolean;
}

/**
 * Token introspection response from /oauth/introspect
 */
export interface TokenIntrospectionResponse {
  /** Whether the token is currently active */
  active: boolean;

  // Standard OAuth2 claims (when active=true)
  tokenType?: 'Bearer';
  scope?: string;
  clientId?: string;
  username?: string;
  /** User ID */
  sub?: string;
  /** Token expiration (Unix timestamp) */
  exp?: number;
  /** Token issued at (Unix timestamp) */
  iat?: number;
  /** Issuer */
  iss?: string;
  /** Audience (client_id) */
  aud?: string;

  // ZnVault custom claims
  /** Tenant ID */
  tenantId?: string;
  /** User's role in the app */
  role?: string;
  /** User's email */
  email?: string;
  /** Apps the user has access to with their roles */
  apps?: Record<string, { role: string }>;
}

/**
 * Validated token info (convenience wrapper)
 */
export interface ValidatedToken {
  /** User ID */
  userId: string;
  /** Username */
  username: string;
  /** User's email */
  email?: string;
  /** Tenant ID */
  tenantId: string;
  /** Client ID of the app */
  clientId: string;
  /** App slug */
  appSlug?: string;
  /** User's role in this app */
  role: string;
  /** Granted scopes */
  scopes: string[];
  /** Token expiration */
  expiresAt: Date;
  /** Token issued at */
  issuedAt: Date;
  /** Raw introspection response */
  raw: TokenIntrospectionResponse;
}

/**
 * User info response from /oauth/userinfo
 */
export interface UserInfoResponse {
  /** User ID */
  sub: string;
  /** Display name */
  name?: string;
  /** Preferred username */
  preferredUsername?: string;
  /** Email address */
  email?: string;
  /** Whether email is verified */
  emailVerified?: boolean;
  /** Tenant ID */
  tenantId?: string;
  /** User's role in the current app */
  role?: string;
  /** Apps the user has access to */
  apps?: Record<string, { role: string }>;
}

/**
 * OAuth2 token response from /oauth/token
 */
export interface TokenResponse {
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  refreshToken?: string;
  idToken?: string;
  scope?: string;
}

/**
 * OAuth2 error response
 */
export interface OAuthError {
  error: string;
  errorDescription?: string;
}

/**
 * Authorization URL builder options
 */
export interface AuthorizationUrlOptions {
  /** OAuth2 redirect URI (must be registered in the app) */
  redirectUri: string;
  /** Requested scopes (default: ['openid', 'profile', 'email']) */
  scopes?: string[];
  /** State parameter for CSRF protection */
  state?: string;
  /** Nonce for ID token validation */
  nonce?: string;
  /** PKCE code challenge (base64url encoded) */
  codeChallenge?: string;
  /** PKCE code challenge method (default: 'S256') */
  codeChallengeMethod?: 'S256' | 'plain';
}

/**
 * Token exchange options
 */
export interface TokenExchangeOptions {
  /** Authorization code from callback */
  code: string;
  /** Redirect URI (must match authorization request) */
  redirectUri: string;
  /** PKCE code verifier (if code_challenge was used) */
  codeVerifier?: string;
}

/**
 * SSO Client configuration
 */
export interface SSOClientConfig {
  /** ZnVault server URL (e.g., 'https://vault.example.com') */
  vaultUrl: string;
  /** OAuth2 client ID */
  clientId: string;
  /** OAuth2 client secret (for confidential clients) */
  clientSecret?: string;
  /** Request timeout in milliseconds (default: 10000) */
  timeout?: number;
  /** Skip TLS certificate verification (not recommended for production) */
  rejectUnauthorized?: boolean;
  /** Cache introspection results (default: true, 60s TTL) */
  cacheIntrospection?: boolean;
  /** Introspection cache TTL in milliseconds (default: 60000) */
  introspectionCacheTtlMs?: number;
}

/**
 * Middleware configuration
 */
export interface SSOMiddlewareConfig extends SSOClientConfig {
  /** Required scopes for all requests */
  requiredScopes?: string[];
  /** Required role for all requests */
  requiredRole?: string;
  /** Function to extract token from request (default: Authorization header) */
  tokenExtractor?: (req: unknown) => string | undefined;
  /** Called when authentication fails */
  onAuthError?: (error: Error, req: unknown, res: unknown) => void;
}
