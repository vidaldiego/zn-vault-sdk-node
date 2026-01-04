// Path: zn-vault-sdk-node/test/test-config.ts

import { ZnVaultClient } from '../src/index.js';

/**
 * Test configuration for integration tests.
 *
 * All test users use the standard password: SdkTest123456#
 *
 * Environment variables:
 * - ZNVAULT_BASE_URL: Server URL (default: https://localhost:9443 for SDK test env)
 * - ZNVAULT_USERNAME: Superadmin username (default: "admin")
 * - ZNVAULT_PASSWORD: Superadmin password (default: "Admin123456#")
 * - ZNVAULT_TENANT: Test tenant (default: "sdk-test")
 *
 * Usage:
 *   # Start the SDK test environment first:
 *   npm run test:sdk:start   # from zn-vault root
 *
 *   # Run tests:
 *   npm test                 # uses local SDK test environment
 *
 *   # Or run against production (not recommended):
 *   ZNVAULT_BASE_URL=https://vault.example.com npm test
 */

// Standard password for all test users (matches sdk-test-init.js)
const STANDARD_PASSWORD = 'SdkTest123456#';

export const TestConfig = {
  // Test server - defaults to SDK test environment (port 9443)
  BASE_URL: process.env.ZNVAULT_BASE_URL ?? 'https://localhost:9443',

  // Default tenant for tests
  DEFAULT_TENANT: process.env.ZNVAULT_TENANT ?? 'sdk-test',

  // Secondary tenant for isolation tests
  TENANT_2: 'sdk-test-2',

  // Test users - can be overridden with environment variables
  // Note: Username must be in format "tenant/username" for non-superadmin users.
  // Superadmin can omit tenant prefix. Email can also be used as username.
  Users: {
    // Superadmin - full access (no tenant prefix required)
    SUPERADMIN_USERNAME: process.env.ZNVAULT_USERNAME ?? 'admin',
    SUPERADMIN_PASSWORD: process.env.ZNVAULT_PASSWORD ?? 'Admin123456#',

    // Tenant admin - manages tenant resources with admin-crypto (requires tenant/username format)
    get TENANT_ADMIN_USERNAME(): string {
      return process.env.ZNVAULT_TENANT_ADMIN_USERNAME ?? `${TestConfig.DEFAULT_TENANT}/sdk-admin`;
    },
    get TENANT_ADMIN_PASSWORD(): string {
      return process.env.ZNVAULT_TENANT_ADMIN_PASSWORD ?? STANDARD_PASSWORD;
    },

    // Read-only user - can only read secrets (requires tenant/username format)
    get READER_USERNAME(): string {
      return process.env.ZNVAULT_READER_USERNAME ?? `${TestConfig.DEFAULT_TENANT}/sdk-reader`;
    },
    get READER_PASSWORD(): string {
      return process.env.ZNVAULT_READER_PASSWORD ?? STANDARD_PASSWORD;
    },

    // Read-write user - can read and write secrets (requires tenant/username format)
    get WRITER_USERNAME(): string {
      return process.env.ZNVAULT_WRITER_USERNAME ?? `${TestConfig.DEFAULT_TENANT}/sdk-writer`;
    },
    get WRITER_PASSWORD(): string {
      return process.env.ZNVAULT_WRITER_PASSWORD ?? STANDARD_PASSWORD;
    },

    // KMS user - can only use KMS operations (requires tenant/username format)
    get KMS_USER_USERNAME(): string {
      return process.env.ZNVAULT_KMS_USER_USERNAME ?? `${TestConfig.DEFAULT_TENANT}/sdk-kms-user`;
    },
    get KMS_USER_PASSWORD(): string {
      return process.env.ZNVAULT_KMS_USER_PASSWORD ?? STANDARD_PASSWORD;
    },

    // Certificate user - can manage certificates (requires tenant/username format)
    get CERT_USER_USERNAME(): string {
      return process.env.ZNVAULT_CERT_USER_USERNAME ?? `${TestConfig.DEFAULT_TENANT}/sdk-cert-user`;
    },
    get CERT_USER_PASSWORD(): string {
      return process.env.ZNVAULT_CERT_USER_PASSWORD ?? STANDARD_PASSWORD;
    },

    // Second tenant admin (for isolation testing)
    get TENANT2_ADMIN_USERNAME(): string {
      return process.env.ZNVAULT_TENANT2_ADMIN_USERNAME ?? `${TestConfig.TENANT_2}/sdk-admin`;
    },
    get TENANT2_ADMIN_PASSWORD(): string {
      return process.env.ZNVAULT_TENANT2_ADMIN_PASSWORD ?? STANDARD_PASSWORD;
    },
  },

  // Pre-created API keys (created by sdk-test-init.js)
  ApiKeys: {
    FULL_ACCESS: process.env.ZNVAULT_API_KEY_FULL,
    READ_ONLY: process.env.ZNVAULT_API_KEY_READONLY,
    KMS_ONLY: process.env.ZNVAULT_API_KEY_KMS,
    WITH_IP_RESTRICTION: process.env.ZNVAULT_API_KEY_WITH_IP,
    PROD_ONLY: process.env.ZNVAULT_API_KEY_PROD_ONLY,
  },

  // Test resources
  Resources: {
    get TEST_SECRET_ALIAS(): string {
      return process.env.ZNVAULT_TEST_SECRET_ALIAS ?? 'sdk-test/database/credentials';
    },
  },

  /**
   * Create a client for testing (insecure TLS for localhost).
   */
  createTestClient(): ZnVaultClient {
    return ZnVaultClient.builder()
      .baseUrl(this.BASE_URL)
      .rejectUnauthorized(false)
      .build();
  },

  /**
   * Create an authenticated client as superadmin.
   */
  async createSuperadminClient(): Promise<ZnVaultClient> {
    const client = this.createTestClient();
    await client.login(this.Users.SUPERADMIN_USERNAME, this.Users.SUPERADMIN_PASSWORD);
    return client;
  },

  /**
   * Create an authenticated client as tenant admin.
   */
  async createTenantAdminClient(): Promise<ZnVaultClient> {
    const client = this.createTestClient();
    await client.login(this.Users.TENANT_ADMIN_USERNAME, this.Users.TENANT_ADMIN_PASSWORD);
    return client;
  },

  /**
   * Create an authenticated client as read-only user.
   */
  async createReaderClient(): Promise<ZnVaultClient> {
    const client = this.createTestClient();
    await client.login(this.Users.READER_USERNAME, this.Users.READER_PASSWORD);
    return client;
  },

  /**
   * Create an authenticated client as read-write user.
   */
  async createWriterClient(): Promise<ZnVaultClient> {
    const client = this.createTestClient();
    await client.login(this.Users.WRITER_USERNAME, this.Users.WRITER_PASSWORD);
    return client;
  },

  /**
   * Create an authenticated client as KMS user.
   */
  async createKmsUserClient(): Promise<ZnVaultClient> {
    const client = this.createTestClient();
    await client.login(this.Users.KMS_USER_USERNAME, this.Users.KMS_USER_PASSWORD);
    return client;
  },

  /**
   * Create an authenticated client as certificate user.
   */
  async createCertUserClient(): Promise<ZnVaultClient> {
    const client = this.createTestClient();
    await client.login(this.Users.CERT_USER_USERNAME, this.Users.CERT_USER_PASSWORD);
    return client;
  },

  /**
   * Create an authenticated client as second tenant admin.
   */
  async createTenant2AdminClient(): Promise<ZnVaultClient> {
    const client = this.createTestClient();
    await client.login(this.Users.TENANT2_ADMIN_USERNAME, this.Users.TENANT2_ADMIN_PASSWORD);
    return client;
  },

  /**
   * Generate a unique ID for testing.
   */
  uniqueId(prefix: string = 'test'): string {
    const uuid = crypto.randomUUID().slice(0, 8);
    return `${prefix}-${uuid}`;
  },

  /**
   * Generate a unique alias for testing.
   */
  uniqueAlias(prefix: string = 'test'): string {
    const uuid = crypto.randomUUID().slice(0, 8);
    return `${prefix}/sdk-test/${uuid}`;
  },

  /**
   * Check if integration tests should run.
   */
  isIntegrationEnabled(): boolean {
    return process.env.ZNVAULT_BASE_URL !== undefined;
  },
};
