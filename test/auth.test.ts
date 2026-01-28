// Path: zn-vault-sdk-node/test/auth.test.ts

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ZnVaultClient } from '../src/index.js';
import { TestConfig } from './test-config.js';

// Skip all tests if integration environment not configured
const shouldRunIntegration = TestConfig.isIntegrationEnabled();

describe.skipIf(!shouldRunIntegration)('AuthClient', () => {
  describe('API Key Management', () => {
    let client: ZnVaultClient;
    const createdKeyIds: string[] = [];

    beforeAll(async () => {
      // Create and authenticate a client once for all tests
      client = await TestConfig.createTenantAdminClient();
    });

    afterAll(async () => {
      // Cleanup all created API keys
      for (const id of createdKeyIds) {
        try {
          await client.auth.deleteApiKey(id);
        } catch {
          // Ignore cleanup errors
        }
      }
    });

    it('should create an API key', async () => {
      const response = await client.auth.createApiKey({
        name: `test-key-${Date.now()}`,
        permissions: ['secret:read:metadata', 'secret:read:value'],
        expiresInDays: 1,
      });

      createdKeyIds.push(response.apiKey.id);

      expect(response.key).toBeDefined();
      expect(response.key).toMatch(/^znv_/);
      expect(response.apiKey).toBeDefined();
      expect(response.apiKey.id).toBeDefined();
      expect(response.apiKey.permissions).toContain('secret:read:metadata');
    });

    it('should create an API key with conditions', async () => {
      const response = await client.auth.createApiKey({
        name: `test-key-conditions-${Date.now()}`,
        permissions: ['secret:read:metadata'],
        expiresInDays: 1,
        conditions: {
          ip: ['10.0.0.0/8'],
          methods: ['GET'],
        },
      });

      createdKeyIds.push(response.apiKey.id);

      expect(response.key).toBeDefined();
      expect(response.apiKey.conditions).toBeDefined();
      expect(response.apiKey.conditions?.ip).toContain('10.0.0.0/8');
    });

    it('should list API keys', async () => {
      const response = await client.auth.listApiKeys();

      expect(response.keys).toBeDefined();
      expect(Array.isArray(response.keys)).toBe(true);
    });

    it('should rotate an API key by ID', async () => {
      // Create a key to rotate
      const original = await client.auth.createApiKey({
        name: `rotate-test-${Date.now()}`,
        permissions: ['secret:read:metadata'],
        expiresInDays: 1,
      });

      // Rotate the key
      const rotated = await client.auth.rotateApiKey(original.apiKey.id);

      createdKeyIds.push(rotated.apiKey.id);

      expect(rotated.key).toBeDefined();
      expect(rotated.key).not.toBe(original.key);
      expect(rotated.apiKey.name).toBe(original.apiKey.name);
    });

    it('should get current API key info when authenticated via API key', async () => {
      // Create an API key
      const keyResponse = await client.auth.createApiKey({
        name: `self-test-${Date.now()}`,
        permissions: ['secret:read:metadata'],
        expiresInDays: 1,
      });

      createdKeyIds.push(keyResponse.apiKey.id);

      // Create a new client with the API key
      const apiKeyClient = ZnVaultClient.builder()
        .baseUrl(TestConfig.BASE_URL)
        .apiKey(keyResponse.key)
        .rejectUnauthorized(false)
        .build();

      // Get current API key info (self endpoints don't require special permissions)
      const currentKey = await apiKeyClient.auth.getCurrentApiKey();

      expect(currentKey).toBeDefined();
      expect(currentKey.name).toBe(keyResponse.apiKey.name);
      expect(currentKey.prefix).toBe(keyResponse.apiKey.prefix);
    });

    it('should self-rotate the current API key', async () => {
      // Create an API key
      const originalKey = await client.auth.createApiKey({
        name: `self-rotate-test-${Date.now()}`,
        permissions: ['secret:read:metadata'],
        expiresInDays: 1,
      });

      // Create a new client with the API key
      const apiKeyClient = ZnVaultClient.builder()
        .baseUrl(TestConfig.BASE_URL)
        .apiKey(originalKey.key)
        .rejectUnauthorized(false)
        .build();

      // Self-rotate the key (self endpoints don't require special permissions)
      const rotatedKey = await apiKeyClient.auth.rotateCurrentApiKey();

      createdKeyIds.push(rotatedKey.apiKey.id);

      expect(rotatedKey.key).toBeDefined();
      expect(rotatedKey.key).not.toBe(originalKey.key);
      expect(rotatedKey.apiKey.name).toBe(originalKey.apiKey.name);
    });

    it('should delete an API key', async () => {
      // Create a key to delete
      const keyResponse = await client.auth.createApiKey({
        name: `delete-test-${Date.now()}`,
        permissions: ['secret:read:metadata'],
        expiresInDays: 1,
      });

      // Delete it (don't add to cleanup list since we're testing delete)
      await expect(client.auth.deleteApiKey(keyResponse.apiKey.id)).resolves.toBeUndefined();
    });
  });
});
