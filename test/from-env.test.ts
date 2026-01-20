// Path: zn-vault-sdk-node/test/from-env.test.ts

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { writeFileSync, unlinkSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  ZnVaultClient,
  FileApiKeyAuth,
  ApiKeyAuth,
  DEFAULT_URL_ENV,
  DEFAULT_API_KEY_ENV,
  DEFAULT_BASE_URL,
} from '../src/index.js';
import { TestConfig } from './test-config.js';

/**
 * E2E tests for fromEnv feature and file-based API key authentication.
 *
 * These tests verify:
 * - ZnVaultClient.fromEnv() with default environment variables
 * - ZnVaultClient.fromEnvCustom() with custom environment variables
 * - Builder .apiKeyFromEnv() method
 * - Builder .apiKeyFile() method
 * - FileApiKeyAuth auto-refresh on 401 (key rotation)
 */

const shouldRunIntegration = TestConfig.isIntegrationEnabled();

describe('fromEnv Feature', () => {
  // Store original env vars to restore after tests
  const originalEnv: Record<string, string | undefined> = {};
  const envVarsToRestore = [
    DEFAULT_URL_ENV,
    DEFAULT_API_KEY_ENV,
    `${DEFAULT_API_KEY_ENV}_FILE`,
    'CUSTOM_VAULT_URL',
    'CUSTOM_API_KEY',
    'CUSTOM_API_KEY_FILE',
  ];

  beforeEach(() => {
    // Save original values
    for (const key of envVarsToRestore) {
      originalEnv[key] = process.env[key];
    }
  });

  afterEach(() => {
    // Restore original values
    for (const key of envVarsToRestore) {
      if (originalEnv[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = originalEnv[key];
      }
    }
  });

  describe('Constants', () => {
    it('should export correct default constants', () => {
      expect(DEFAULT_URL_ENV).toBe('ZINC_CONFIG_VAULT_URL');
      expect(DEFAULT_API_KEY_ENV).toBe('ZINC_CONFIG_VAULT_API_KEY');
      expect(DEFAULT_BASE_URL).toBe('https://localhost:8443');
    });
  });

  describe('ApiKeyAuth', () => {
    it('should create ApiKeyAuth with static key', () => {
      const auth = new ApiKeyAuth('znv_test_key_123');
      expect(auth.getApiKey()).toBe('znv_test_key_123');
    });

    it('should create ApiKeyAuth using static factory', () => {
      const auth = ApiKeyAuth.of('znv_test_key_456');
      expect(auth.getApiKey()).toBe('znv_test_key_456');
    });
  });

  describe('FileApiKeyAuth', () => {
    const testDir = join(tmpdir(), 'znvault-sdk-test');
    const keyFilePath = join(testDir, 'api-key');

    beforeAll(() => {
      if (!existsSync(testDir)) {
        mkdirSync(testDir, { recursive: true });
      }
    });

    afterEach(() => {
      try {
        unlinkSync(keyFilePath);
      } catch {
        // Ignore if file doesn't exist
      }
    });

    it('should read API key from file', () => {
      writeFileSync(keyFilePath, 'znv_file_key_123');

      const auth = new FileApiKeyAuth(keyFilePath);
      expect(auth.getApiKey()).toBe('znv_file_key_123');
      expect(auth.getFilePath()).toBe(keyFilePath);
    });

    it('should trim whitespace from file content', () => {
      writeFileSync(keyFilePath, '  znv_whitespace_key  \n');

      const auth = new FileApiKeyAuth(keyFilePath);
      expect(auth.getApiKey()).toBe('znv_whitespace_key');
    });

    it('should throw if file does not exist', () => {
      expect(() => new FileApiKeyAuth('/nonexistent/path/api-key'))
        .toThrow('API key file not found');
    });

    it('should throw if file is empty', () => {
      writeFileSync(keyFilePath, '');

      expect(() => new FileApiKeyAuth(keyFilePath))
        .toThrow('API key file is empty');
    });

    it('should throw if file contains only whitespace', () => {
      writeFileSync(keyFilePath, '   \n\t  ');

      expect(() => new FileApiKeyAuth(keyFilePath))
        .toThrow('API key file is empty');
    });

    it('should refresh key from file manually', () => {
      writeFileSync(keyFilePath, 'znv_original_key');
      const auth = new FileApiKeyAuth(keyFilePath);
      expect(auth.getApiKey()).toBe('znv_original_key');

      // Update file
      writeFileSync(keyFilePath, 'znv_rotated_key');

      // Manual refresh
      const newKey = auth.refresh();
      expect(newKey).toBe('znv_rotated_key');
      expect(auth.getApiKey()).toBe('znv_rotated_key');
    });

    it('should return true from onAuthenticationError when key changed', () => {
      writeFileSync(keyFilePath, 'znv_original_key');
      const auth = new FileApiKeyAuth(keyFilePath);

      // Update file (simulating agent rotation)
      writeFileSync(keyFilePath, 'znv_rotated_key');

      // Should return true indicating retry is appropriate
      const shouldRetry = auth.onAuthenticationError();
      expect(shouldRetry).toBe(true);
      expect(auth.getApiKey()).toBe('znv_rotated_key');
    });

    it('should return false from onAuthenticationError when key unchanged', () => {
      writeFileSync(keyFilePath, 'znv_same_key');
      const auth = new FileApiKeyAuth(keyFilePath);

      // Key hasn't changed
      const shouldRetry = auth.onAuthenticationError();
      expect(shouldRetry).toBe(false);
      expect(auth.getApiKey()).toBe('znv_same_key');
    });

    describe('fromEnv factory', () => {
      const fileKeyPath = join(testDir, 'env-api-key');

      afterEach(() => {
        delete process.env['TEST_API_KEY'];
        delete process.env['TEST_API_KEY_FILE'];
        try {
          unlinkSync(fileKeyPath);
        } catch {
          // Ignore
        }
      });

      it('should prefer _FILE env var over direct value', () => {
        writeFileSync(fileKeyPath, 'znv_from_file');
        process.env['TEST_API_KEY'] = 'znv_direct_value';
        process.env['TEST_API_KEY_FILE'] = fileKeyPath;

        const auth = FileApiKeyAuth.fromEnv('TEST_API_KEY');

        expect(auth).toBeInstanceOf(FileApiKeyAuth);
        expect(auth.getApiKey()).toBe('znv_from_file');
      });

      it('should use direct value when _FILE not set', () => {
        process.env['TEST_API_KEY'] = 'znv_direct_value';

        const auth = FileApiKeyAuth.fromEnv('TEST_API_KEY');

        expect(auth).toBeInstanceOf(ApiKeyAuth);
        expect(auth.getApiKey()).toBe('znv_direct_value');
      });

      it('should throw when neither _FILE nor direct value set', () => {
        expect(() => FileApiKeyAuth.fromEnv('UNSET_API_KEY'))
          .toThrow('No API key configured. Set either UNSET_API_KEY_FILE (recommended) or UNSET_API_KEY environment variable.');
      });
    });
  });

  describe('ZnVaultClient.fromEnv()', () => {
    const testDir = join(tmpdir(), 'znvault-sdk-test');
    const keyFilePath = join(testDir, 'from-env-api-key');

    beforeAll(() => {
      if (!existsSync(testDir)) {
        mkdirSync(testDir, { recursive: true });
      }
    });

    afterEach(() => {
      try {
        unlinkSync(keyFilePath);
      } catch {
        // Ignore
      }
    });

    it('should use default URL when env var not set', () => {
      delete process.env[DEFAULT_URL_ENV];
      process.env[DEFAULT_API_KEY_ENV] = 'znv_test_key';

      const client = ZnVaultClient.fromEnv();

      // Client was created - we can't easily inspect baseUrl but we can verify it works
      expect(client).toBeInstanceOf(ZnVaultClient);
    });

    it('should use URL from environment', () => {
      process.env[DEFAULT_URL_ENV] = 'https://custom.vault.com:8443';
      process.env[DEFAULT_API_KEY_ENV] = 'znv_test_key';

      const client = ZnVaultClient.fromEnv();

      expect(client).toBeInstanceOf(ZnVaultClient);
    });

    it('should prefer _FILE env var for API key', () => {
      writeFileSync(keyFilePath, 'znv_file_based_key');
      process.env[DEFAULT_URL_ENV] = 'https://localhost:8443';
      process.env[`${DEFAULT_API_KEY_ENV}_FILE`] = keyFilePath;

      const client = ZnVaultClient.fromEnv();

      expect(client).toBeInstanceOf(ZnVaultClient);
      expect(client.getCurrentApiKey()).toBe('znv_file_based_key');
    });

    it('should throw when no API key configured', () => {
      delete process.env[DEFAULT_API_KEY_ENV];
      delete process.env[`${DEFAULT_API_KEY_ENV}_FILE`];
      process.env[DEFAULT_URL_ENV] = 'https://localhost:8443';

      expect(() => ZnVaultClient.fromEnv())
        .toThrow(`No API key configured. Set either ${DEFAULT_API_KEY_ENV}_FILE (recommended) or ${DEFAULT_API_KEY_ENV} environment variable.`);
    });
  });

  describe('ZnVaultClient.fromEnvCustom()', () => {
    const testDir = join(tmpdir(), 'znvault-sdk-test');
    const keyFilePath = join(testDir, 'custom-env-api-key');

    beforeAll(() => {
      if (!existsSync(testDir)) {
        mkdirSync(testDir, { recursive: true });
      }
    });

    afterEach(() => {
      delete process.env['CUSTOM_VAULT_URL'];
      delete process.env['CUSTOM_API_KEY'];
      delete process.env['CUSTOM_API_KEY_FILE'];
      try {
        unlinkSync(keyFilePath);
      } catch {
        // Ignore
      }
    });

    it('should use custom env var names', () => {
      process.env['CUSTOM_VAULT_URL'] = 'https://custom.vault.com:9443';
      process.env['CUSTOM_API_KEY'] = 'znv_custom_key';

      const client = ZnVaultClient.fromEnvCustom('CUSTOM_VAULT_URL', 'CUSTOM_API_KEY');

      expect(client).toBeInstanceOf(ZnVaultClient);
      expect(client.getCurrentApiKey()).toBe('znv_custom_key');
    });

    it('should prefer _FILE variant with custom names', () => {
      writeFileSync(keyFilePath, 'znv_custom_file_key');
      process.env['CUSTOM_VAULT_URL'] = 'https://custom.vault.com:9443';
      process.env['CUSTOM_API_KEY_FILE'] = keyFilePath;

      const client = ZnVaultClient.fromEnvCustom('CUSTOM_VAULT_URL', 'CUSTOM_API_KEY');

      expect(client).toBeInstanceOf(ZnVaultClient);
      expect(client.getCurrentApiKey()).toBe('znv_custom_file_key');
    });

    it('should throw when custom URL env var not set', () => {
      delete process.env['CUSTOM_VAULT_URL'];
      process.env['CUSTOM_API_KEY'] = 'znv_test';

      expect(() => ZnVaultClient.fromEnvCustom('CUSTOM_VAULT_URL', 'CUSTOM_API_KEY'))
        .toThrow('Environment variable CUSTOM_VAULT_URL not set');
    });

    it('should throw when custom API key env vars not set', () => {
      process.env['CUSTOM_VAULT_URL'] = 'https://localhost:8443';
      delete process.env['CUSTOM_API_KEY'];
      delete process.env['CUSTOM_API_KEY_FILE'];

      expect(() => ZnVaultClient.fromEnvCustom('CUSTOM_VAULT_URL', 'CUSTOM_API_KEY'))
        .toThrow('No API key configured. Set either CUSTOM_API_KEY_FILE (recommended) or CUSTOM_API_KEY environment variable.');
    });
  });

  describe('Builder apiKeyFromEnv()', () => {
    const testDir = join(tmpdir(), 'znvault-sdk-test');
    const keyFilePath = join(testDir, 'builder-env-api-key');

    beforeAll(() => {
      if (!existsSync(testDir)) {
        mkdirSync(testDir, { recursive: true });
      }
    });

    afterEach(() => {
      delete process.env['BUILDER_API_KEY'];
      delete process.env['BUILDER_API_KEY_FILE'];
      try {
        unlinkSync(keyFilePath);
      } catch {
        // Ignore
      }
    });

    it('should resolve direct API key from env', () => {
      process.env['BUILDER_API_KEY'] = 'znv_builder_direct_key';

      const client = ZnVaultClient.builder()
        .baseUrl('https://localhost:8443')
        .apiKeyFromEnv('BUILDER_API_KEY')
        .build();

      expect(client.getCurrentApiKey()).toBe('znv_builder_direct_key');
    });

    it('should resolve file-based API key from env', () => {
      writeFileSync(keyFilePath, 'znv_builder_file_key');
      process.env['BUILDER_API_KEY_FILE'] = keyFilePath;

      const client = ZnVaultClient.builder()
        .baseUrl('https://localhost:8443')
        .apiKeyFromEnv('BUILDER_API_KEY')
        .build();

      expect(client.getCurrentApiKey()).toBe('znv_builder_file_key');
    });

    it('should throw when env var not set', () => {
      expect(() =>
        ZnVaultClient.builder()
          .baseUrl('https://localhost:8443')
          .apiKeyFromEnv('MISSING_API_KEY')
          .build()
      ).toThrow('No API key configured');
    });

    it('should clear apiKey when apiKeyFromEnv is called', () => {
      process.env['OVERRIDE_API_KEY'] = 'znv_from_env';

      const client = ZnVaultClient.builder()
        .baseUrl('https://localhost:8443')
        .apiKey('znv_direct_key') // This should be overridden
        .apiKeyFromEnv('OVERRIDE_API_KEY')
        .build();

      expect(client.getCurrentApiKey()).toBe('znv_from_env');
    });
  });

  describe('Builder apiKeyFile()', () => {
    const testDir = join(tmpdir(), 'znvault-sdk-test');
    const keyFilePath = join(testDir, 'builder-file-api-key');

    beforeAll(() => {
      if (!existsSync(testDir)) {
        mkdirSync(testDir, { recursive: true });
      }
    });

    afterEach(() => {
      try {
        unlinkSync(keyFilePath);
      } catch {
        // Ignore
      }
    });

    it('should read API key from specified file', () => {
      writeFileSync(keyFilePath, 'znv_file_key_direct');

      const client = ZnVaultClient.builder()
        .baseUrl('https://localhost:8443')
        .apiKeyFile(keyFilePath)
        .build();

      expect(client.getCurrentApiKey()).toBe('znv_file_key_direct');
    });

    it('should throw if file does not exist', () => {
      expect(() =>
        ZnVaultClient.builder()
          .baseUrl('https://localhost:8443')
          .apiKeyFile('/nonexistent/path/key')
          .build()
      ).toThrow('API key file not found');
    });

    it('should clear apiKey when apiKeyFile is called', () => {
      writeFileSync(keyFilePath, 'znv_from_file');

      const client = ZnVaultClient.builder()
        .baseUrl('https://localhost:8443')
        .apiKey('znv_direct_key') // This should be overridden
        .apiKeyFile(keyFilePath)
        .build();

      expect(client.getCurrentApiKey()).toBe('znv_from_file');
    });
  });

  // Integration tests that require a running vault server
  describe.skipIf(!shouldRunIntegration)('Integration with Server', () => {
    const testDir = join(tmpdir(), 'znvault-sdk-test-integration');
    const keyFilePath = join(testDir, 'integration-api-key');
    let testApiKey: string;
    let testApiKeyId: string;
    let adminClient: ZnVaultClient;

    beforeAll(async () => {
      if (!existsSync(testDir)) {
        mkdirSync(testDir, { recursive: true });
      }

      // Create an API key for testing (use tenant admin to avoid superadmin lockout issues)
      adminClient = await TestConfig.createTenantAdminClient();

      const response = await adminClient.auth.createApiKey({
        name: `from-env-test-${Date.now()}`,
        permissions: ['secret:read:metadata', 'secret:list:metadata'],
        expiresInDays: 1,
      });

      testApiKey = response.key;
      testApiKeyId = response.apiKey.id;

      console.log('✓ Created test API key for fromEnv tests');
    });

    afterAll(async () => {
      // Cleanup API key
      try {
        await adminClient.auth.deleteApiKey(testApiKeyId);
        console.log('✓ Cleaned up test API key');
      } catch {
        // Ignore cleanup errors
      }

      try {
        unlinkSync(keyFilePath);
      } catch {
        // Ignore
      }
    });

    // Note: fromEnv() uses default TLS settings (rejectUnauthorized: true).
    // For self-signed certs, NODE_TLS_REJECT_UNAUTHORIZED=0 must be set BEFORE
    // starting Node.js. These tests verify the env configuration works; the
    // TLS behavior is the same as using the builder without rejectUnauthorized(false).
    //
    // To run these tests against a self-signed cert server:
    //   NODE_TLS_REJECT_UNAUTHORIZED=0 npm test -- test/from-env.test.ts

    const tlsVerificationDisabled = process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0';
    const isSelfSignedEnv = TestConfig.BASE_URL.includes('localhost') && !tlsVerificationDisabled;

    it.skipIf(isSelfSignedEnv)(
      'should connect using fromEnv() with direct API key',
      async () => {
        process.env[DEFAULT_URL_ENV] = TestConfig.BASE_URL;
        process.env[DEFAULT_API_KEY_ENV] = testApiKey;

        const client = ZnVaultClient.fromEnv();

        // Verify we can make authenticated requests
        const health = await client.health.check();
        expect(health.status).toBe('ok');

        console.log('✓ Successfully connected using fromEnv() with direct API key');
      }
    );

    it.skipIf(isSelfSignedEnv)(
      'should connect using fromEnv() with file-based API key',
      async () => {
        writeFileSync(keyFilePath, testApiKey);
        process.env[DEFAULT_URL_ENV] = TestConfig.BASE_URL;
        delete process.env[DEFAULT_API_KEY_ENV];
        process.env[`${DEFAULT_API_KEY_ENV}_FILE`] = keyFilePath;

        const client = ZnVaultClient.fromEnv();

        // Verify we can make authenticated requests
        const health = await client.health.check();
        expect(health.status).toBe('ok');

        console.log('✓ Successfully connected using fromEnv() with file-based API key');
      }
    );

    it.skipIf(isSelfSignedEnv)('should connect using fromEnvCustom()', async () => {
      process.env['MY_VAULT_URL'] = TestConfig.BASE_URL;
      process.env['MY_API_KEY'] = testApiKey;

      try {
        const client = ZnVaultClient.fromEnvCustom('MY_VAULT_URL', 'MY_API_KEY');

        const health = await client.health.check();
        expect(health.status).toBe('ok');

        console.log('✓ Successfully connected using fromEnvCustom()');
      } finally {
        // Cleanup
        delete process.env['MY_VAULT_URL'];
        delete process.env['MY_API_KEY'];
      }
    });

    it('should connect using builder with apiKeyFromEnv()', async () => {
      process.env['TEST_VAULT_API_KEY'] = testApiKey;

      const client = ZnVaultClient.builder()
        .baseUrl(TestConfig.BASE_URL)
        .apiKeyFromEnv('TEST_VAULT_API_KEY')
        .rejectUnauthorized(false)
        .build();

      const health = await client.health.check();
      expect(health.status).toBe('ok');

      // Cleanup
      delete process.env['TEST_VAULT_API_KEY'];

      console.log('✓ Successfully connected using builder.apiKeyFromEnv()');
    });

    it('should connect using builder with apiKeyFile()', async () => {
      writeFileSync(keyFilePath, testApiKey);

      const client = ZnVaultClient.builder()
        .baseUrl(TestConfig.BASE_URL)
        .apiKeyFile(keyFilePath)
        .rejectUnauthorized(false)
        .build();

      const health = await client.health.check();
      expect(health.status).toBe('ok');

      console.log('✓ Successfully connected using builder.apiKeyFile()');
    });

    it('should auto-refresh on key rotation (401 handling)', async () => {
      // Create TWO keys for rotation testing - we'll invalidate the first one
      const key1Response = await adminClient.auth.createApiKey({
        name: `rotate-test-key1-${Date.now()}`,
        permissions: ['secret:read:metadata', 'secret:list:metadata'],
        expiresInDays: 1,
      });

      const key2Response = await adminClient.auth.createApiKey({
        name: `rotate-test-key2-${Date.now()}`,
        permissions: ['secret:read:metadata', 'secret:list:metadata'],
        expiresInDays: 1,
      });

      const key1 = key1Response.key;
      const key1Id = key1Response.apiKey.id;
      const key2 = key2Response.key;
      const key2Id = key2Response.apiKey.id;

      // Write first key to file
      writeFileSync(keyFilePath, key1);

      // Create client with file-based auth
      const client = ZnVaultClient.builder()
        .baseUrl(TestConfig.BASE_URL)
        .apiKeyFile(keyFilePath)
        .rejectUnauthorized(false)
        .build();

      // Verify initial connection works with an authenticated endpoint
      const secrets = await client.secrets.list({ tenantId: TestConfig.DEFAULT_TENANT });
      expect(secrets).toBeDefined();
      expect(Array.isArray(secrets.items)).toBe(true);
      console.log('✓ Initial connection successful with key1');

      // Now simulate key rotation:
      // 1. Delete key1 (invalidates it immediately - no grace period)
      // 2. Write key2 to file (simulating agent update)
      await adminClient.auth.deleteApiKey(key1Id);
      writeFileSync(keyFilePath, key2);

      // The client still has key1 in memory (now invalid)
      // The file now has key2 (valid)
      // Next authenticated request should:
      // 1. Try with key1 -> get 401
      // 2. FileApiKeyAuth.onAuthenticationError() re-reads file -> finds key2
      // 3. Retry with key2 -> succeeds
      const secrets2 = await client.secrets.list({ tenantId: TestConfig.DEFAULT_TENANT });
      expect(secrets2).toBeDefined();
      expect(Array.isArray(secrets2.items)).toBe(true);

      // Verify the client is now using key2
      expect(client.getCurrentApiKey()).toBe(key2);
      console.log('✓ Auto-refresh worked after key invalidation');

      // Cleanup
      await adminClient.auth.deleteApiKey(key2Id);
    });
  });
});
