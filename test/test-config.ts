// Path: zn-vault-sdk-node/test/test-config.ts

import { ZnVaultClient } from '../src/index.js';

/**
 * Test configuration for integration tests.
 */
export const TestConfig = {
  // Test server
  BASE_URL: process.env.ZNVAULT_BASE_URL ?? 'https://localhost:8443',

  // Test users
  Users: {
    // Superadmin - full access
    SUPERADMIN_USERNAME: 'admin',
    SUPERADMIN_PASSWORD: 'Admin123456#',

    // Tenant admin - manages tenant resources
    TENANT_ADMIN_USERNAME: 'zincadmin',
    TENANT_ADMIN_PASSWORD: 'Admin123456#',

    // Regular user - limited access
    REGULAR_USER_USERNAME: 'zincuser',
    REGULAR_USER_PASSWORD: 'Admin123456#',
  },

  // Default tenant for tests
  DEFAULT_TENANT: 'zincapp',

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
   * Create an authenticated client as regular user.
   */
  async createRegularUserClient(): Promise<ZnVaultClient> {
    const client = this.createTestClient();
    await client.login(this.Users.REGULAR_USER_USERNAME, this.Users.REGULAR_USER_PASSWORD);
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
