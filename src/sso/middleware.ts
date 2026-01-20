// Path: zn-vault-sdk-node/src/sso/middleware.ts
// SSO Middleware helpers for Fastify and Express

import { SSOClient, SSOError } from './client.js';
import type { SSOMiddlewareConfig, ValidatedToken, SSOClientConfig } from './types.js';

/**
 * Request with SSO user attached
 */
export interface SSORequest {
  ssoUser?: ValidatedToken;
  ssoToken?: string;
}

/**
 * Authentication error with details
 */
export class SSOAuthError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 401
  ) {
    super(message);
    this.name = 'SSOAuthError';
  }
}

/**
 * Default token extractor - looks for Authorization: Bearer header
 */
function defaultTokenExtractor(req: unknown): string | undefined {
  const request = req as { headers?: Record<string, string | string[] | undefined> };
  const authHeader = request.headers?.authorization;
  if (typeof authHeader === 'string' && authHeader.toLowerCase().startsWith('bearer ')) {
    return authHeader;
  }
  return undefined;
}

// =============================================================================
// Fastify Middleware
// =============================================================================

/**
 * Create a Fastify preHandler hook for SSO authentication.
 *
 * @example
 * ```typescript
 * import Fastify from 'fastify';
 * import { createFastifySSOAuth } from '@zincapp/znvault-sdk/sso';
 *
 * const fastify = Fastify();
 *
 * const ssoAuth = createFastifySSOAuth({
 *   vaultUrl: 'https://vault.example.com',
 *   clientId: 'sso_abc123',
 *   clientSecret: 'znsso_xxx...',
 * });
 *
 * // Protect all routes
 * fastify.addHook('preHandler', ssoAuth);
 *
 * // Or protect specific routes
 * fastify.get('/protected', { preHandler: [ssoAuth] }, (req, reply) => {
 *   const user = req.ssoUser;
 *   reply.send({ message: `Hello ${user.username}!` });
 * });
 * ```
 */
export function createFastifySSOAuth(config: SSOMiddlewareConfig) {
  const ssoClient = new SSOClient(config);
  const tokenExtractor = config.tokenExtractor ?? defaultTokenExtractor;

  return async function fastifySSOAuth(
    request: unknown,
    reply: { code: (status: number) => { send: (body: unknown) => void } }
  ): Promise<void> {
    const req = request as SSORequest & { headers?: Record<string, string> };

    try {
      const token = tokenExtractor(request);
      if (!token) {
        throw new SSOAuthError('No authorization token provided', 'NO_TOKEN');
      }

      const validatedToken = await ssoClient.validateToken(token);
      if (!validatedToken) {
        throw new SSOAuthError('Invalid or expired token', 'INVALID_TOKEN');
      }

      // Check required scopes
      if (config.requiredScopes?.length) {
        const hasScopes = ssoClient.hasAllScopes(validatedToken, config.requiredScopes);
        if (!hasScopes) {
          throw new SSOAuthError(
            `Missing required scopes: ${config.requiredScopes.join(', ')}`,
            'INSUFFICIENT_SCOPE',
            403
          );
        }
      }

      // Check required role
      if (config.requiredRole) {
        if (!ssoClient.hasRole(validatedToken, config.requiredRole)) {
          throw new SSOAuthError(
            `Required role: ${config.requiredRole}`,
            'INSUFFICIENT_ROLE',
            403
          );
        }
      }

      // Attach to request
      req.ssoUser = validatedToken;
      req.ssoToken = token;
    } catch (error) {
      if (config.onAuthError) {
        config.onAuthError(error as Error, request, reply);
        return;
      }

      const authError = error instanceof SSOAuthError
        ? error
        : error instanceof SSOError
          ? new SSOAuthError(error.message, error.code, error.statusCode ?? 401)
          : new SSOAuthError('Authentication failed', 'AUTH_FAILED');

      reply.code(authError.statusCode).send({
        error: authError.code,
        message: authError.message,
      });
    }
  };
}

/**
 * Create a Fastify preHandler that requires specific scopes.
 *
 * @example
 * ```typescript
 * const requireScopes = createFastifySSOScopes(ssoClient, ['read:data', 'write:data']);
 * fastify.post('/data', { preHandler: [ssoAuth, requireScopes] }, handler);
 * ```
 */
export function createFastifySSOScopes(client: SSOClient, requiredScopes: string[]) {
  return async function fastifySSOScopes(
    request: unknown,
    reply: { code: (status: number) => { send: (body: unknown) => void } }
  ): Promise<void> {
    const req = request as SSORequest;
    const token = req.ssoUser;

    if (!token) {
      reply.code(401).send({
        error: 'NO_USER',
        message: 'Authentication required before scope check',
      });
      return;
    }

    if (!client.hasAllScopes(token, requiredScopes)) {
      reply.code(403).send({
        error: 'INSUFFICIENT_SCOPE',
        message: `Missing required scopes: ${requiredScopes.join(', ')}`,
      });
    }
  };
}

/**
 * Create a Fastify preHandler that requires specific roles.
 *
 * @example
 * ```typescript
 * const requireAdmin = createFastifySSORoles(ssoClient, ['admin']);
 * fastify.delete('/resource', { preHandler: [ssoAuth, requireAdmin] }, handler);
 * ```
 */
export function createFastifySSORoles(client: SSOClient, allowedRoles: string[]) {
  return async function fastifySSORoles(
    request: unknown,
    reply: { code: (status: number) => { send: (body: unknown) => void } }
  ): Promise<void> {
    const req = request as SSORequest;
    const token = req.ssoUser;

    if (!token) {
      reply.code(401).send({
        error: 'NO_USER',
        message: 'Authentication required before role check',
      });
      return;
    }

    if (!client.hasAnyRole(token, allowedRoles)) {
      reply.code(403).send({
        error: 'INSUFFICIENT_ROLE',
        message: `Required role: ${allowedRoles.join(' or ')}`,
      });
    }
  };
}

// =============================================================================
// Express Middleware
// =============================================================================

type ExpressNextFunction = (err?: unknown) => void;

/**
 * Create Express middleware for SSO authentication.
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { createExpressSSOAuth } from '@zincapp/znvault-sdk/sso';
 *
 * const app = express();
 *
 * const ssoAuth = createExpressSSOAuth({
 *   vaultUrl: 'https://vault.example.com',
 *   clientId: 'sso_abc123',
 *   clientSecret: 'znsso_xxx...',
 * });
 *
 * // Protect specific routes
 * app.get('/protected', ssoAuth, (req, res) => {
 *   const user = req.ssoUser;
 *   res.json({ message: `Hello ${user.username}!` });
 * });
 *
 * // Or protect all routes
 * app.use(ssoAuth);
 * ```
 */
export function createExpressSSOAuth(config: SSOMiddlewareConfig) {
  const ssoClient = new SSOClient(config);
  const tokenExtractor = config.tokenExtractor ?? defaultTokenExtractor;

  return async function expressSSOAuth(
    req: unknown,
    res: { status: (code: number) => { json: (body: unknown) => void } },
    next: ExpressNextFunction
  ): Promise<void> {
    const request = req as SSORequest;

    try {
      const token = tokenExtractor(req);
      if (!token) {
        throw new SSOAuthError('No authorization token provided', 'NO_TOKEN');
      }

      const validatedToken = await ssoClient.validateToken(token);
      if (!validatedToken) {
        throw new SSOAuthError('Invalid or expired token', 'INVALID_TOKEN');
      }

      // Check required scopes
      if (config.requiredScopes?.length) {
        const hasScopes = ssoClient.hasAllScopes(validatedToken, config.requiredScopes);
        if (!hasScopes) {
          throw new SSOAuthError(
            `Missing required scopes: ${config.requiredScopes.join(', ')}`,
            'INSUFFICIENT_SCOPE',
            403
          );
        }
      }

      // Check required role
      if (config.requiredRole) {
        if (!ssoClient.hasRole(validatedToken, config.requiredRole)) {
          throw new SSOAuthError(
            `Required role: ${config.requiredRole}`,
            'INSUFFICIENT_ROLE',
            403
          );
        }
      }

      // Attach to request
      request.ssoUser = validatedToken;
      request.ssoToken = token;
      next();
    } catch (error) {
      if (config.onAuthError) {
        config.onAuthError(error as Error, req, res);
        return;
      }

      const authError = error instanceof SSOAuthError
        ? error
        : error instanceof SSOError
          ? new SSOAuthError(error.message, error.code, error.statusCode ?? 401)
          : new SSOAuthError('Authentication failed', 'AUTH_FAILED');

      res.status(authError.statusCode).json({
        error: authError.code,
        message: authError.message,
      });
    }
  };
}

/**
 * Create Express middleware that requires specific scopes.
 */
export function createExpressSSOScopes(client: SSOClient, requiredScopes: string[]) {
  return function expressSSOScopes(
    req: unknown,
    res: { status: (code: number) => { json: (body: unknown) => void } },
    next: ExpressNextFunction
  ): void {
    const request = req as SSORequest;
    const token = request.ssoUser;

    if (!token) {
      res.status(401).json({
        error: 'NO_USER',
        message: 'Authentication required before scope check',
      });
      return;
    }

    if (!client.hasAllScopes(token, requiredScopes)) {
      res.status(403).json({
        error: 'INSUFFICIENT_SCOPE',
        message: `Missing required scopes: ${requiredScopes.join(', ')}`,
      });
      return;
    }

    next();
  };
}

/**
 * Create Express middleware that requires specific roles.
 */
export function createExpressSSOScopes_Roles(client: SSOClient, allowedRoles: string[]) {
  return function expressSSOScopes(
    req: unknown,
    res: { status: (code: number) => { json: (body: unknown) => void } },
    next: ExpressNextFunction
  ): void {
    const request = req as SSORequest;
    const token = request.ssoUser;

    if (!token) {
      res.status(401).json({
        error: 'NO_USER',
        message: 'Authentication required before role check',
      });
      return;
    }

    if (!client.hasAnyRole(token, allowedRoles)) {
      res.status(403).json({
        error: 'INSUFFICIENT_ROLE',
        message: `Required role: ${allowedRoles.join(' or ')}`,
      });
      return;
    }

    next();
  };
}

// =============================================================================
// Generic Helpers
// =============================================================================

/**
 * Create a configured SSO client.
 * Convenience function for creating a client without importing the class.
 */
export function createSSOClient(config: SSOClientConfig): SSOClient {
  return new SSOClient(config);
}

/**
 * Require specific scopes on a token (for custom middleware).
 */
export function requireScopes(client: SSOClient, token: ValidatedToken, scopes: string[]): void {
  if (!client.hasAllScopes(token, scopes)) {
    throw new SSOAuthError(
      `Missing required scopes: ${scopes.join(', ')}`,
      'INSUFFICIENT_SCOPE',
      403
    );
  }
}

/**
 * Require specific roles on a token (for custom middleware).
 */
export function requireRole(client: SSOClient, token: ValidatedToken, roles: string[]): void {
  if (!client.hasAnyRole(token, roles)) {
    throw new SSOAuthError(
      `Required role: ${roles.join(' or ')}`,
      'INSUFFICIENT_ROLE',
      403
    );
  }
}
