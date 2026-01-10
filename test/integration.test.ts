// Path: zn-vault-sdk-node/test/integration.test.ts

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import type { SecretType } from '../src/index.js';
import { ZnVaultClient } from '../src/index.js';
import { TestConfig } from './test-config.js';

/**
 * Integration tests that run against a real ZnVault server.
 *
 * These tests require:
 * - A running ZnVault server
 * - Environment variable: ZNVAULT_BASE_URL (e.g., "https://localhost:8443")
 *
 * Run with: ZNVAULT_BASE_URL=https://localhost:8443 npm test
 */

const shouldRunIntegration = TestConfig.isIntegrationEnabled();

// Skip all integration tests if environment not configured
describe.skipIf(!shouldRunIntegration)('Integration Tests', () => {
  // ===================
  // Health Tests
  // ===================
  describe('Health', () => {
    let client: ZnVaultClient;

    beforeAll(() => {
      client = TestConfig.createTestClient();
    });

    it('should return healthy status', async () => {
      const health = await client.health.check();
      expect(health.status).toBe('ok');
      console.log(`✓ Health status: ${health.status}`);
    });

    it('should report live status', async () => {
      const result = await client.health.live();
      expect(result.status).toBe('ok');
      console.log('✓ Live check successful');
    });
  });

  // ===================
  // Authentication Tests
  // ===================
  describe('Authentication', () => {
    let client: ZnVaultClient;

    beforeEach(() => {
      client = TestConfig.createTestClient();
    });

    it('should login with valid superadmin credentials', async () => {
      const response = await client.login(
        TestConfig.Users.SUPERADMIN_USERNAME,
        TestConfig.Users.SUPERADMIN_PASSWORD
      );

      expect(response.accessToken).toBeDefined();
      expect(response.refreshToken).toBeDefined();
      expect(response.expiresIn).toBeGreaterThan(0);

      console.log(`✓ Logged in as superadmin, token expires in ${response.expiresIn}s`);
    });

    it('should login with valid reader user credentials', async () => {
      const response = await client.login(
        TestConfig.Users.READER_USERNAME,
        TestConfig.Users.READER_PASSWORD
      );

      expect(response.accessToken).toBeDefined();
      console.log('✓ Logged in as reader user');
    });

    it('should fail login with invalid credentials', async () => {
      await expect(
        client.login('invalid_user', 'wrong_password')
      ).rejects.toThrow();

      console.log('✓ Invalid credentials correctly rejected');
    });

    it('should get current user info after login', async () => {
      await client.login(
        TestConfig.Users.SUPERADMIN_USERNAME,
        TestConfig.Users.SUPERADMIN_PASSWORD
      );

      const user = await client.auth.me();

      expect(user.username).toBe(TestConfig.Users.SUPERADMIN_USERNAME);
      expect(user.id).toBeDefined();

      console.log(`✓ Current user: ${user.username} (${user.role})`);
    });
  });

  // ===================
  // Secrets Tests
  // ===================
  describe('Secrets', () => {
    let client: ZnVaultClient;
    let createdSecretIds: string[] = [];

    beforeAll(async () => {
      // Use tenant admin - has full tenant permissions including secret:read:value
      // Tenant has allow_admin_secret_access=true so admin can decrypt secrets
      client = await TestConfig.createTenantAdminClient();
    });

    afterEach(async () => {
      // Cleanup created secrets
      for (const id of createdSecretIds) {
        try {
          await client.secrets.delete(id);
          console.log(`  Cleaned up secret: ${id}`);
        } catch {
          // Ignore cleanup errors
        }
      }
      createdSecretIds = [];
    });

    it('should create a credential secret', async () => {
      const alias = TestConfig.uniqueAlias('creds');

      const secret = await client.secrets.create({
        alias,
        tenant: TestConfig.DEFAULT_TENANT,
        type: 'credential',
        data: {
          username: 'testuser',
          password: 'testpass123',
        },
        tags: ['test', 'credential'],
      });

      createdSecretIds.push(secret.id);

      expect(secret.id).toBeDefined();
      expect(secret.alias).toBe(alias);
      expect(secret.tenant).toBe(TestConfig.DEFAULT_TENANT);
      expect(secret.type).toBe('credential');
      expect(secret.version).toBe(1);

      console.log(`✓ Created credential secret: ${secret.id}`);
      console.log(`  Alias: ${secret.alias}`);
      console.log(`  Version: ${secret.version}`);
    });

    it('should create an opaque secret', async () => {
      const alias = TestConfig.uniqueAlias('opaque');

      const secret = await client.secrets.create({
        alias,
        tenant: TestConfig.DEFAULT_TENANT,
        type: 'opaque',
        data: {
          api_key: 'sk_live_abc123',
          api_secret: 'secret_xyz789',
        },
      });

      createdSecretIds.push(secret.id);

      expect(secret.id).toBeDefined();
      expect(secret.type).toBe('opaque');

      console.log(`✓ Created opaque secret: ${secret.id}`);
    });

    it('should decrypt secret value', async () => {
      const alias = TestConfig.uniqueAlias('decrypt');

      const created = await client.secrets.create({
        alias,
        tenant: TestConfig.DEFAULT_TENANT,
        type: 'credential',
        data: {
          username: 'decryptuser',
          password: 'decryptpass',
        },
      });

      createdSecretIds.push(created.id);

      // Decrypt it
      const data = await client.secrets.decrypt(created.id);

      expect(data.data.username).toBe('decryptuser');
      expect(data.data.password).toBe('decryptpass');

      console.log('✓ Decrypted secret successfully');
      console.log(`  Username: ${data.data.username}`);
    });

    it('should update secret and create new version', async () => {
      const alias = TestConfig.uniqueAlias('update');

      const created = await client.secrets.create({
        alias,
        tenant: TestConfig.DEFAULT_TENANT,
        type: 'opaque',
        data: { key: 'original_value' },
      });

      createdSecretIds.push(created.id);
      expect(created.version).toBe(1);

      // Update it
      const updated = await client.secrets.update(created.id, {
        data: { key: 'updated_value' },
      });

      expect(updated.version).toBe(2);

      // Verify the value changed
      const data = await client.secrets.decrypt(updated.id);
      expect(data.data.key).toBe('updated_value');

      console.log(`✓ Updated secret, version: ${created.version} -> ${updated.version}`);
    });

    it('should rotate secret', async () => {
      const alias = TestConfig.uniqueAlias('rotate');

      const created = await client.secrets.create({
        alias,
        tenant: TestConfig.DEFAULT_TENANT,
        type: 'credential',
        data: {
          username: 'user',
          password: 'oldpass',
        },
      });

      createdSecretIds.push(created.id);

      // Rotate it
      const rotated = await client.secrets.rotate(created.id, {
        username: 'user',
        password: 'newpass',
      });

      expect(rotated.version).toBe(2);

      // Verify new value
      const data = await client.secrets.decrypt(rotated.id);
      expect(data.data.password).toBe('newpass');

      console.log(`✓ Rotated secret, version: ${created.version} -> ${rotated.version}`);
    });

    it('should list secrets', async () => {
      // Create some secrets
      for (let i = 0; i < 3; i++) {
        const secret = await client.secrets.create({
          alias: TestConfig.uniqueAlias(`list-${i}`),
          tenant: TestConfig.DEFAULT_TENANT,
          type: 'opaque',
          data: { index: i },
        });
        createdSecretIds.push(secret.id);
      }

      // List secrets
      const secrets = await client.secrets.list({ tenantId: TestConfig.DEFAULT_TENANT });

      expect(secrets.length).toBeGreaterThanOrEqual(3);
      console.log(`✓ Listed ${secrets.length} secrets`);
    });

    it('should delete a secret', async () => {
      const alias = TestConfig.uniqueAlias('delete');

      const created = await client.secrets.create({
        alias,
        tenant: TestConfig.DEFAULT_TENANT,
        type: 'opaque',
        data: { key: 'value' },
      });

      // Delete it (don't add to cleanup list)
      await client.secrets.delete(created.id);

      // Verify it's gone
      await expect(client.secrets.get(created.id)).rejects.toThrow();

      console.log(`✓ Deleted secret: ${created.id}`);
    });
  });

  // ===================
  // User Management Tests
  // ===================
  describe('User Management', () => {
    let client: ZnVaultClient;
    let createdUserIds: string[] = [];

    beforeAll(async () => {
      client = await TestConfig.createSuperadminClient();
    });

    afterEach(async () => {
      // Cleanup created users
      for (const id of createdUserIds) {
        try {
          await client.users.delete(id);
          console.log(`  Cleaned up user: ${id}`);
        } catch {
          // Ignore cleanup errors
        }
      }
      createdUserIds = [];
    });

    it('should list users', async () => {
      const users = await client.users.list();
      expect(users).toBeDefined();
      console.log(`✓ Listed ${users.length} users`);
    });

    it('should create a new user', async () => {
      const username = TestConfig.uniqueId('testuser');

      const user = await client.users.create({
        username,
        password: 'TestPassword123#',
        email: `${username}@example.com`,
        tenantId: TestConfig.DEFAULT_TENANT,
        role: 'user',
      });

      createdUserIds.push(user.id);

      expect(user.id).toBeDefined();
      // Server returns username with tenant prefix for tenant users
      expect(user.username).toBe(`${TestConfig.DEFAULT_TENANT}/${username}`);

      console.log(`✓ Created user: ${user.username}`);
      console.log(`  ID: ${user.id}`);
    });

    it('should delete a user', async () => {
      const username = TestConfig.uniqueId('deleteuser');

      const user = await client.users.create({
        username,
        password: 'TestPassword123#',
        tenantId: TestConfig.DEFAULT_TENANT,
      });

      // Delete it (don't add to cleanup list)
      await client.users.delete(user.id);

      console.log(`✓ Deleted user: ${user.username}`);
    });
  });

  // ===================
  // Tenant Management Tests
  // ===================
  describe('Tenant Management', () => {
    let client: ZnVaultClient;

    beforeAll(async () => {
      client = await TestConfig.createSuperadminClient();
    });

    it('should list tenants', async () => {
      const tenants = await client.tenants.list();
      expect(tenants).toBeDefined();
      console.log(`✓ Listed ${tenants.length} tenants`);
    });

    it('should get tenant by ID', async () => {
      const tenant = await client.tenants.get(TestConfig.DEFAULT_TENANT);
      expect(tenant.id).toBe(TestConfig.DEFAULT_TENANT);
      console.log(`✓ Retrieved tenant: ${tenant.id}`);
    });
  });

  // ===================
  // Role Management Tests
  // ===================
  describe('Role Management', () => {
    let client: ZnVaultClient;

    beforeAll(async () => {
      client = await TestConfig.createSuperadminClient();
    });

    it('should list roles', async () => {
      const roles = await client.roles.list();
      expect(roles).toBeDefined();
      console.log(`✓ Listed ${roles.length} roles`);
    });
  });

  // ===================
  // Audit Tests
  // ===================
  describe('Audit', () => {
    let client: ZnVaultClient;

    beforeAll(async () => {
      client = await TestConfig.createSuperadminClient();
    });

    it('should list audit logs', async () => {
      const logs = await client.audit.list();
      expect(logs).toBeDefined();
      console.log(`✓ Listed ${logs.length} audit entries`);
    });
  });
});
