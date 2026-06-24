// Path: zn-vault-sdk-node/test/helpers/integration.ts

import { ZnVaultClient } from '../../src/index.js';
import { TestConfig } from '../test-config.js';

/**
 * Probe the configured vault server for reachability.
 *
 * Attempts a lightweight health request against `TestConfig.BASE_URL`.
 * Returns `true` if the server responds (even with an error status that isn't
 * a network-level connection failure), or `false` when the request fails with
 * a `CONNECTION_ERROR` or `TIMEOUT` error code — meaning no server is up at
 * that address.
 *
 * Usage in integration `beforeAll`:
 * ```ts
 * let serverUnreachable = false;
 * beforeAll(async () => {
 *   if (!(await probeServer())) { serverUnreachable = true; return; }
 *   // ... existing setup ...
 * });
 * it('...', async () => {
 *   if (serverUnreachable) return;
 *   // ... test body ...
 * });
 * ```
 */
export async function probeServer(): Promise<boolean> {
  try {
    const client = ZnVaultClient.builder()
      .baseUrl(TestConfig.BASE_URL)
      .rejectUnauthorized(false)
      .build();
    await client.health.check();
    return true;
  } catch (err) {
    const code = (err as { errorCode?: string }).errorCode;
    if (code === 'CONNECTION_ERROR' || code === 'TIMEOUT') {
      return false;
    }
    // Any other error (e.g. 401, 500) means the server IS reachable.
    return true;
  }
}
