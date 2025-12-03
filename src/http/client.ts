// Path: zn-vault-sdk-node/src/http/client.ts

import https from 'node:https';
import type { ZnVaultErrorResponse } from '../types/index.js';

export interface HttpClientConfig {
  baseUrl: string;
  apiKey?: string;
  timeout?: number;
  retries?: number;
  rejectUnauthorized?: boolean;
}

export type TokenRefreshCallback = () => Promise<string>;

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
  private accessToken?: string;
  private refreshToken?: string;
  private timeout: number;
  private retryAttempts: number;
  private retryDelay: number;
  private rejectUnauthorized: boolean;
  private tokenRefreshCallback?: TokenRefreshCallback;

  constructor(config: HttpClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.apiKey = config.apiKey;
    this.timeout = config.timeout ?? 30000;
    this.retryAttempts = config.retries ?? 3;
    this.retryDelay = 1000;
    this.rejectUnauthorized = config.rejectUnauthorized ?? true;
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

  async request<T>(options: RequestOptions): Promise<T> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.retryAttempts; attempt++) {
      try {
        return await this.executeRequest<T>(options);
      } catch (error) {
        lastError = error as Error;

        if (error instanceof AuthenticationError && this.tokenRefreshCallback && attempt === 0) {
          try {
            const newToken = await this.tokenRefreshCallback();
            this.accessToken = newToken;
            continue;
          } catch {
            throw error;
          }
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
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...options.headers,
      };

      if (this.apiKey) {
        headers['X-API-Key'] = this.apiKey;
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
