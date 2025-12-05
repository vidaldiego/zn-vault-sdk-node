// Path: zn-vault-sdk-node/test/auth.test.ts

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ZnVaultClient } from '../src/index.js';

const BASE_URL = process.env.ZNVAULT_BASE_URL || process.env.ZN_VAULT_URL || 'https://localhost:8443';
// Note: Username must be in format "tenant/username" for non-superadmin users.
// Superadmin can omit tenant prefix. Email can also be used as username.
const ADMIN_USER = process.env.ZNVAULT_USERNAME || process.env.ZN_VAULT_USER || 'admin';
const ADMIN_PASS = process.env.ZNVAULT_PASSWORD || process.env.ZN_VAULT_PASS || 'Admin123456#';

describe('AuthClient', () => {
  let client: ZnVaultClient;

  beforeAll(() => {
    client = ZnVaultClient.builder()
      .baseUrl(BASE_URL)
      .rejectUnauthorized(false)
      .build();
  });

  describe('API Key Management', () => {
    it('should create an API key', async () => {
      await client.auth.login({ username: ADMIN_USER, password: ADMIN_PASS });

      const response = await client.auth.createApiKey({
        name: `test-key-${Date.now()}`,
        expiresIn: '1d',
      });

      expect(response.key).toBeDefined();
      expect(response.key).toMatch(/^znv_/);
      expect(response.apiKey).toBeDefined();
      expect(response.apiKey.id).toBeDefined();

      // Cleanup
      await client.auth.deleteApiKey(response.apiKey.id);
    });

    it('should list API keys', async () => {
      await client.auth.login({ username: ADMIN_USER, password: ADMIN_PASS });

      const response = await client.auth.listApiKeys();

      expect(response.keys).toBeDefined();
      expect(Array.isArray(response.keys)).toBe(true);
    });

    it('should rotate an API key by ID', async () => {
      await client.auth.login({ username: ADMIN_USER, password: ADMIN_PASS });

      // Create a key to rotate
      const original = await client.auth.createApiKey({
        name: `rotate-test-${Date.now()}`,
        expiresIn: '1d',
      });

      // Rotate the key
      const rotated = await client.auth.rotateApiKey(original.apiKey.id);

      expect(rotated.key).toBeDefined();
      expect(rotated.key).not.toBe(original.key);
      expect(rotated.apiKey.name).toBe(original.apiKey.name);

      // Cleanup
      await client.auth.deleteApiKey(rotated.apiKey.id);
    });

    it('should get current API key info when authenticated via API key', async () => {
      // First login and create an API key
      await client.auth.login({ username: ADMIN_USER, password: ADMIN_PASS });

      const keyResponse = await client.auth.createApiKey({
        name: `self-test-${Date.now()}`,
        expiresIn: '1d',
      });

      // Create a new client with the API key
      const apiKeyClient = ZnVaultClient.builder()
        .baseUrl(BASE_URL)
        .apiKey(keyResponse.key)
        .rejectUnauthorized(false)
        .build();

      // Get current API key info
      const currentKey = await apiKeyClient.auth.getCurrentApiKey();

      expect(currentKey).toBeDefined();
      expect(currentKey.name).toBe(keyResponse.apiKey.name);
      expect(currentKey.prefix).toBe(keyResponse.apiKey.prefix);

      // Cleanup
      await client.auth.deleteApiKey(keyResponse.apiKey.id);
    });

    it('should self-rotate the current API key', async () => {
      // First login and create an API key
      await client.auth.login({ username: ADMIN_USER, password: ADMIN_PASS });

      const originalKey = await client.auth.createApiKey({
        name: `self-rotate-test-${Date.now()}`,
        expiresIn: '1d',
      });

      // Create a new client with the API key
      const apiKeyClient = ZnVaultClient.builder()
        .baseUrl(BASE_URL)
        .apiKey(originalKey.key)
        .rejectUnauthorized(false)
        .build();

      // Self-rotate the key
      const rotatedKey = await apiKeyClient.auth.rotateCurrentApiKey();

      expect(rotatedKey.key).toBeDefined();
      expect(rotatedKey.key).not.toBe(originalKey.key);
      expect(rotatedKey.apiKey.name).toBe(originalKey.apiKey.name);

      // Cleanup - delete the new key using the original client
      await client.auth.deleteApiKey(rotatedKey.apiKey.id);
    });

    it('should delete an API key', async () => {
      await client.auth.login({ username: ADMIN_USER, password: ADMIN_PASS });

      // Create a key to delete
      const keyResponse = await client.auth.createApiKey({
        name: `delete-test-${Date.now()}`,
        expiresIn: '1d',
      });

      // Delete it
      await expect(client.auth.deleteApiKey(keyResponse.apiKey.id)).resolves.toBeUndefined();
    });
  });
});
