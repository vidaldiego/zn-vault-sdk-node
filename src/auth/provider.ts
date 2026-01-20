// Path: zn-vault-sdk-node/src/auth/provider.ts

import { readFileSync, existsSync, accessSync, constants } from 'node:fs';

/**
 * Auth provider interface for API key authentication.
 */
export interface AuthProvider {
  /** Get the API key value */
  getApiKey(): string;
}

/**
 * Auth provider that supports refresh on authentication errors.
 */
export interface RefreshableAuthProvider extends AuthProvider {
  /**
   * Called when authentication fails (401).
   * Returns true if the credential was refreshed and the request should be retried.
   */
  onAuthenticationError(): boolean;
}

/**
 * Simple API key authentication provider.
 * Use this for static API keys that don't change.
 */
export class ApiKeyAuth implements AuthProvider {
  constructor(private readonly apiKey: string) {}

  getApiKey(): string {
    return this.apiKey;
  }

  static of(apiKey: string): ApiKeyAuth {
    return new ApiKeyAuth(apiKey);
  }
}

/**
 * File-based API key authentication provider with automatic refresh.
 *
 * This provider reads the API key from a file and supports automatic
 * credential refresh when authentication fails. Use this when an external
 * process (like zn-vault-agent) manages and rotates the API key.
 *
 * ## Usage
 *
 * ```typescript
 * // The agent writes the current key to this file
 * const provider = new FileApiKeyAuth('/run/zn-vault-agent/secrets/VAULT_API_KEY');
 *
 * // Or auto-detect from environment
 * const provider = FileApiKeyAuth.fromEnv('VAULT_API_KEY');
 * ```
 *
 * ## How it works
 *
 * 1. On initialization, reads the API key from the file
 * 2. Caches the key in memory for subsequent requests
 * 3. When a 401 error occurs, re-reads the file and retries
 * 4. This handles key rotation by the agent transparently
 *
 * ## File format
 *
 * The file should contain only the API key value (whitespace is trimmed):
 * ```
 * znv_abc123...
 * ```
 */
export class FileApiKeyAuth implements RefreshableAuthProvider {
  private cachedKey: string;

  constructor(private readonly filePath: string) {
    this.cachedKey = this.readKeyFromFile();
  }

  getApiKey(): string {
    return this.cachedKey;
  }

  /**
   * Called when authentication fails (401).
   *
   * Re-reads the API key from the file. If the key has changed,
   * returns true to indicate the request should be retried.
   */
  onAuthenticationError(): boolean {
    const oldKey = this.cachedKey;

    try {
      const newKey = this.readKeyFromFile();

      if (newKey !== oldKey) {
        this.cachedKey = newKey;
        return true; // Key changed, retry the request
      }
      return false; // Key is the same, don't retry (it's a real auth error)
    } catch {
      return false; // Can't refresh, don't retry
    }
  }

  /**
   * Force a refresh of the cached API key from the file.
   * @returns The new API key value
   * @throws Error if the file cannot be read
   */
  refresh(): string {
    this.cachedKey = this.readKeyFromFile();
    return this.cachedKey;
  }

  /**
   * Get the file path being used.
   */
  getFilePath(): string {
    return this.filePath;
  }

  private readKeyFromFile(): string {
    if (!existsSync(this.filePath)) {
      throw new Error(`API key file not found: ${this.filePath}`);
    }

    try {
      accessSync(this.filePath, constants.R_OK);
    } catch {
      throw new Error(`Cannot read API key file: ${this.filePath}`);
    }

    const key = readFileSync(this.filePath, 'utf-8').trim();
    if (!key) {
      throw new Error(`API key file is empty: ${this.filePath}`);
    }

    return key;
  }

  /**
   * Create a FileApiKeyAuth from environment variable detection.
   *
   * Checks for the file path in `{envName}_FILE` environment variable.
   * For example, if envName is "VAULT_API_KEY", it checks for
   * "VAULT_API_KEY_FILE" to get the file path.
   *
   * Falls back to reading the direct value from `envName` if no file
   * is configured (returns a regular ApiKeyAuth in that case).
   *
   * @param envName Base environment variable name
   * @returns AuthProvider configured from environment
   * @throws Error if neither file nor value is configured
   */
  static fromEnv(envName: string): AuthProvider {
    const filePath = process.env[`${envName}_FILE`];
    const directValue = process.env[envName];

    if (filePath) {
      return new FileApiKeyAuth(filePath);
    }

    if (directValue) {
      return new ApiKeyAuth(directValue);
    }

    throw new Error(
      `No API key configured. Set either ${envName}_FILE (recommended) or ${envName} environment variable.`
    );
  }

  /**
   * Create from a file path.
   */
  static fromFile(filePath: string): FileApiKeyAuth {
    return new FileApiKeyAuth(filePath);
  }
}

/**
 * Check if an auth provider supports refresh.
 */
export function isRefreshableAuthProvider(provider: AuthProvider): provider is RefreshableAuthProvider {
  return 'onAuthenticationError' in provider && typeof provider.onAuthenticationError === 'function';
}
