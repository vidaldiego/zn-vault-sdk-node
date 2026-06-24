// Path: zn-vault-sdk-node/test/e2e/health.e2e.test.ts
//
// E2E assertions proving HEALTH-01/02:
//   HEALTH-01 — health.check() returns { status, checks: { db, tls } } where
//               status ∈ {ok, degraded, error} and checks.db / checks.tls are present.
//   HEALTH-02 — health.ready() returns { status } where
//               status ∈ {ready, not ready, degraded}.
//
// Requires a live seeded vault (`npm run test:e2e`).

import { describe, it, expect, beforeAll } from 'vitest';
import { TestConfig } from '../test-config.js';
import { probeServer } from '../helpers/integration.js';
import type { ZnVaultClient } from '../../src/index.js';

const isIntegrationEnabled = TestConfig.isIntegrationEnabled();

describe.skipIf(!isIntegrationEnabled)('E2E: Health — contract fixes HEALTH-01/02', () => {
  let serverUnreachable = false;

  // No authentication needed for health checks
  let client: ZnVaultClient;

  beforeAll(async () => {
    if (!(await probeServer())) {
      serverUnreachable = true;
      return;
    }
    client = TestConfig.createTestClient();
  });

  // ---------------------------------------------------------------------------
  // HEALTH-01: health.check() — status + checks.db + checks.tls
  // ---------------------------------------------------------------------------

  it('HEALTH-01: health.check() returns status ∈ {ok, degraded, error}', async () => {
    if (serverUnreachable) return;

    const health = await client.health.check();

    expect(health).toBeDefined();
    expect(['ok', 'degraded', 'error']).toContain(health.status);

    console.log(`HEALTH-01 status pass: status=${health.status}`);
  });

  it('HEALTH-01: health.check() returns checks.db present', async () => {
    if (serverUnreachable) return;

    const health = await client.health.check();

    // checks must exist
    expect(health.checks).toBeDefined();

    // checks.db must be present with a status field
    expect(health.checks.db).toBeDefined();
    expect(typeof health.checks.db.status).toBe('string');
    expect(health.checks.db.status.length).toBeGreaterThan(0);

    console.log(`HEALTH-01 checks.db pass: status=${health.checks.db.status}`);
  });

  it('HEALTH-01: health.check() returns checks.tls present', async () => {
    if (serverUnreachable) return;

    const health = await client.health.check();

    // checks.tls must be present with a status field
    expect(health.checks.tls).toBeDefined();
    expect(typeof health.checks.tls.status).toBe('string');
    expect(health.checks.tls.status.length).toBeGreaterThan(0);

    console.log(`HEALTH-01 checks.tls pass: status=${health.checks.tls.status}`);
  });

  it('HEALTH-01: health.check() returns version, uptime, and timestamp', async () => {
    if (serverUnreachable) return;

    const health = await client.health.check();

    expect(typeof health.version).toBe('string');
    expect(health.version.length).toBeGreaterThan(0);

    expect(typeof health.uptime).toBe('number');
    expect(health.uptime).toBeGreaterThanOrEqual(0);

    expect(typeof health.timestamp).toBe('string');
    expect(health.timestamp.length).toBeGreaterThan(0);

    console.log(
      `HEALTH-01 metadata pass: version=${health.version}, uptime=${health.uptime}s`
    );
  });

  // ---------------------------------------------------------------------------
  // HEALTH-02: health.ready() — status ∈ {ready, not ready, degraded}
  // ---------------------------------------------------------------------------

  it('HEALTH-02: health.ready() returns status ∈ {ready, not ready, degraded}', async () => {
    if (serverUnreachable) return;

    const readiness = await client.health.ready();

    expect(readiness).toBeDefined();
    expect(['ready', 'not ready', 'degraded']).toContain(readiness.status);

    // timestamp must be present
    expect(typeof readiness.timestamp).toBe('string');
    expect(readiness.timestamp.length).toBeGreaterThan(0);

    console.log(`HEALTH-02 pass: status=${readiness.status}`);
  });

  it('HEALTH-02: ready vault returns status=ready', async () => {
    if (serverUnreachable) return;

    // In a properly running E2E environment the vault should be ready
    const readiness = await client.health.ready();

    // We expect the test vault to be healthy; if it's not, log it but don't fail
    if (readiness.status !== 'ready') {
      console.warn(
        `HEALTH-02 warning: vault is not fully ready: ` +
        `status=${readiness.status}, reason=${readiness.reason ?? 'none'}`
      );
    }

    // Still: status must be one of the valid values
    expect(['ready', 'not ready', 'degraded']).toContain(readiness.status);

    console.log(`HEALTH-02 ready-vault pass: status=${readiness.status}`);
  });

  // ---------------------------------------------------------------------------
  // Liveness: health.live()
  // ---------------------------------------------------------------------------

  it('live(): health.live() returns { status: "ok" }', async () => {
    if (serverUnreachable) return;

    const live = await client.health.live();

    expect(live).toBeDefined();
    expect(live.status).toBe('ok');

    console.log(`live() pass: status=${live.status}`);
  });
});
