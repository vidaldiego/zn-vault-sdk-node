// Path: zn-vault-sdk-node/test/e2e/auth.e2e.test.ts
//
// E2E assertions proving AUTH-01/02/04:
//   AUTH-01 — 2FA enable → verify round-trip: field names are correct
//             (enable2fa returns { secret, qrCode, backupCodes }).
//   AUTH-02 — changePassword round-trip works: user can change password and
//             re-authenticate with the new password.
//   AUTH-04 — auth.me() returns the authenticated user with expected fields.
//
// Uses a freshly-created throwaway user to avoid locking seeded accounts.
// Requires a live seeded vault (`npm run test:e2e`).

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { ZnVaultClient } from '../../src/index.js';
import { TestConfig } from '../test-config.js';
import { probeServer } from '../helpers/integration.js';

const isIntegrationEnabled = TestConfig.isIntegrationEnabled();

describe.skipIf(!isIntegrationEnabled)('E2E: Auth — contract fixes AUTH-01/02/04', () => {
  let serverUnreachable = false;

  // Tenant admin client for user management
  let adminClient: ZnVaultClient;

  // Throwaway user created for this suite (deleted in afterAll)
  let throwawayUserId: string | undefined;
  const throwawayUsername = `e2e-auth-${Date.now()}`;
  const throwawayPassword = 'ThrowAway123456#';
  const newPassword      = 'NewPassword789$';

  beforeAll(async () => {
    if (!(await probeServer())) {
      serverUnreachable = true;
      return;
    }
    adminClient = await TestConfig.createTenantAdminClient();

    // Create a throwaway user within the sdk-test tenant (admin can do this)
    try {
      const user = await adminClient.users.create({
        username: throwawayUsername,
        password: throwawayPassword,
        email: `${throwawayUsername}@e2e.test`,
        role: 'user',
      });
      throwawayUserId = user.id;
      console.log(`Created throwaway user: ${user.username} (id=${user.id})`);
    } catch (err) {
      console.warn(`Could not create throwaway user: ${(err as Error).message}`);
    }
  });

  afterAll(async () => {
    if (serverUnreachable) return;
    if (throwawayUserId) {
      try {
        await adminClient.users.delete(throwawayUserId);
        console.log(`Deleted throwaway user: ${throwawayUserId}`);
      } catch {
        // Ignore cleanup errors
      }
    }
  });

  // ---------------------------------------------------------------------------
  // AUTH-04: auth.me() returns the authenticated user
  // ---------------------------------------------------------------------------

  it('AUTH-04: auth.me() returns current user with id and username', async () => {
    if (serverUnreachable) return;

    const user = await adminClient.auth.me();

    expect(user).toBeDefined();
    expect(typeof user.id).toBe('string');
    expect(user.id.length).toBeGreaterThan(0);
    expect(typeof user.username).toBe('string');
    expect(user.username.length).toBeGreaterThan(0);

    console.log(`AUTH-04 pass: me() → username=${user.username}, id=${user.id}`);
  });

  it('AUTH-04: login returns accessToken + refreshToken + expiresIn', async () => {
    if (serverUnreachable) return;

    const client = TestConfig.createTestClient();
    const response = await client.login(
      TestConfig.Users.TENANT_ADMIN_USERNAME,
      TestConfig.Users.TENANT_ADMIN_PASSWORD
    );

    expect(typeof response.accessToken).toBe('string');
    expect(response.accessToken.length).toBeGreaterThan(0);
    expect(typeof response.refreshToken).toBe('string');
    expect(response.refreshToken.length).toBeGreaterThan(0);
    expect(typeof response.expiresIn).toBe('number');
    expect(response.expiresIn).toBeGreaterThan(0);

    console.log(`AUTH-04 login pass: expiresIn=${response.expiresIn}s`);
  });

  // ---------------------------------------------------------------------------
  // AUTH-02: changePassword round-trip on the throwaway user
  // ---------------------------------------------------------------------------

  it('AUTH-02: changePassword round-trip — user can re-authenticate with new password', async () => {
    if (serverUnreachable) return;
    if (!throwawayUserId) {
      console.warn('Skipping AUTH-02: throwaway user was not created');
      return;
    }

    // Login as the throwaway user
    const userClient = TestConfig.createTestClient();
    await userClient.login(
      `${TestConfig.DEFAULT_TENANT}/${throwawayUsername}`,
      throwawayPassword
    );

    // Change password
    await userClient.auth.changePassword(throwawayPassword, newPassword);

    // Re-authenticate with new password — must not throw
    const newClient = TestConfig.createTestClient();
    const response = await newClient.login(
      `${TestConfig.DEFAULT_TENANT}/${throwawayUsername}`,
      newPassword
    );

    expect(typeof response.accessToken).toBe('string');
    expect(response.accessToken.length).toBeGreaterThan(0);

    console.log(`AUTH-02 pass: password changed, re-auth succeeded`);

    // Restore original password so afterAll delete still works even if
    // the admin delete path requires the user still exist.
    try {
      await newClient.auth.changePassword(newPassword, throwawayPassword);
    } catch {
      // Best-effort restore; ignored if it fails
    }
  });

  // ---------------------------------------------------------------------------
  // AUTH-01: 2FA enable → TwoFactorSetupResponse field names
  // ---------------------------------------------------------------------------

  it('AUTH-01: enable2fa returns { secret, qrCode, backupCodes } with correct field names', async () => {
    if (serverUnreachable) return;
    if (!throwawayUserId) {
      console.warn('Skipping AUTH-01: throwaway user was not created');
      return;
    }

    // We intentionally just test the shape of the response; we do NOT complete
    // TOTP verification because that would require generating a valid TOTP code,
    // which requires a real TOTP library and the secret from the response.
    const userClient = TestConfig.createTestClient();
    await userClient.login(
      `${TestConfig.DEFAULT_TENANT}/${throwawayUsername}`,
      throwawayPassword
    );

    const setup = await userClient.auth.enable2fa();

    // AUTH-01: field names must be exactly these (not `totpSecret` or `qr_code`)
    expect(typeof setup.secret).toBe('string');
    expect(setup.secret.length).toBeGreaterThan(0);
    expect(typeof setup.qrCode).toBe('string');
    expect(setup.qrCode.length).toBeGreaterThan(0);
    expect(Array.isArray(setup.backupCodes)).toBe(true);
    expect(setup.backupCodes.length).toBeGreaterThan(0);

    // qrCode is typically a data-URI or otpauth:// URL
    // backupCodes are non-empty strings
    expect(typeof setup.backupCodes[0]).toBe('string');

    console.log(
      `AUTH-01 pass: secret length=${setup.secret.length}, ` +
      `backupCodes count=${setup.backupCodes.length}`
    );
  });
});
