// Path: zn-vault-sdk-node/src/sso/index.ts
// SSO Module - Token validation and OAuth2 client helpers

export { SSOClient, SSOError } from './client.js';

export {
  // Fastify middleware
  createFastifySSOAuth,
  createFastifySSOScopes,
  createFastifySSORoles,
  // Express middleware
  createExpressSSOAuth,
  createExpressSSOScopes,
  // Helpers
  createSSOClient,
  requireScopes,
  requireRole,
  // Errors
  SSOAuthError,
  // Request types
  type SSORequest,
} from './middleware.js';

export type {
  // Configuration
  SSOClientConfig,
  SSOMiddlewareConfig,
  // Token types
  TokenIntrospectionResponse,
  ValidatedToken,
  UserInfoResponse,
  TokenResponse,
  OAuthError,
  // OAuth2 flow types
  AuthorizationUrlOptions,
  TokenExchangeOptions,
  // App info
  SSOApp,
} from './types.js';
