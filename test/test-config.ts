// Path: zn-vault-sdk-node/test/test-config.ts

import { ZnVaultClient } from '../src/index.js';

/**
 * Test configuration for integration tests.
 *
 * Environment variables:
 * - ZNVAULT_BASE_URL: Server URL (e.g., "https://vault.zincapp.com")
 * - ZNVAULT_USERNAME: Superadmin username (default: "admin")
 * - ZNVAULT_PASSWORD: Superadmin password (default: "Admin123456#")
 */
export const TestConfig = {
  // Test server
  BASE_URL: process.env.ZNVAULT_BASE_URL ?? 'https://localhost:8443',

  // Test users
  // Note: Username must be in format "tenant/username" for non-superadmin users.
  // Superadmin can omit tenant prefix. Email can also be used as username.
  Users: {
    // Superadmin - full access (no tenant prefix required)
    SUPERADMIN_USERNAME: process.env.ZNVAULT_USERNAME ?? 'admin',
    SUPERADMIN_PASSWORD: process.env.ZNVAULT_PASSWORD ?? 'Admin123456#',

    // Tenant admin - manages tenant resources (requires tenant/username format)
    TENANT_ADMIN_USERNAME: 'zincapp/zincadmin',
    TENANT_ADMIN_PASSWORD: process.env.ZNVAULT_PASSWORD ?? 'Admin123456#',

    // Regular user - limited access (requires tenant/username format)
    REGULAR_USER_USERNAME: 'zincapp/zincuser',
    REGULAR_USER_PASSWORD: process.env.ZNVAULT_PASSWORD ?? 'Admin123456#',
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
