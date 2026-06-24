// Path: zn-vault-sdk-node/test/e2e/secrets.e2e.test.ts
//
// E2E assertions proving SECRET-01/02:
//   SECRET-01 — getHistory(id) returns { items, pagination } after create+update.
//   SECRET-02 — updateMetadata(id, { tags }) hits /metadata and returns the
//               updated secret without creating a new version.
//
// Requires a live seeded vault (`npm run test:e2e`).

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { ZnVaultClient } from '../../src/index.js';
import { TestConfig } from '../test-config.js';
import { probeServer } from '../helpers/integration.js';

const isIntegrationEnabled = TestConfig.isIntegrationEnabled();

describe.skipIf(!isIntegrationEnabled)('E2E: Secrets — contract fixes SECRET-01/02', () => {
  let serverUnreachable = false;

  // Tenant admin has full secret permissions
  let client: ZnVaultClient;

  // IDs of secrets created by this suite — cleaned up in afterAll
  const createdSecretIds: string[] = [];

  beforeAll(async () => {
    if (!(await probeServer())) {
      serverUnreachable = true;
      return;
    }
    client = await TestConfig.createTenantAdminClient();
  });

  afterAll(async () => {
    if (serverUnreachable) return;
    for (const id of createdSecretIds) {
      try {
        await client.secrets.delete(id);
        console.log(`Cleaned up secret: ${id}`);
      } catch {
        // Ignore cleanup errors
      }
    }
  });

  // ---------------------------------------------------------------------------
  // SECRET-01: getHistory returns { items, pagination }
  // ---------------------------------------------------------------------------

  it('SECRET-01: getHistory returns { items, pagination } after create+update', async () => {
    if (serverUnreachable) return;

    const alias = TestConfig.uniqueAlias('secret-01-history');

    // Step 1: create the secret (v1)
    const created = await client.secrets.create({
      alias,
      type: 'opaque',
      data: { value: 'initial-value' },
      tags: ['e2e', 'test'],
    });
    createdSecretIds.push(created.id);
    expect(created.version).toBe(1);

    // Step 2: update the secret (v2)
    const updated = await client.secrets.update(created.id, {
      data: { value: 'updated-value' },
    });
    expect(updated.version).toBe(2);

    // Step 3: fetch history — must return { items, pagination }
    const history = await client.secrets.getHistory(created.id);

    // Shape assertions
    expect(history).toBeDefined();
    expect(Array.isArray(history.items)).toBe(true);
    expect(history.pagination).toBeDefined();
    expect(typeof history.pagination.total).toBe('number');
    expect(typeof history.pagination.limit).toBe('number');
    expect(typeof history.pagination.offset).toBe('number');
    expect(typeof history.pagination.hasMore).toBe('boolean');

    // Content assertions: history contains at least one entry.
    // Note: the server records superseded (old) versions — after one update
    // the history list has 1 entry (v1, the superseded version). The current
    // live version (v2) is accessible via GET /secrets/:id but is not in the
    // history list itself, matching the vault server's contract.
    expect(history.items.length).toBeGreaterThanOrEqual(1);

    // Each history entry has a version number
    for (const entry of history.items) {
      expect(typeof entry.version).toBe('number');
    }

    console.log(
      `SECRET-01 pass: history.items.length=${history.items.length}, ` +
      `pagination.total=${history.pagination.total}`
    );
  });

  it('SECRET-01: getHistory pagination params are forwarded correctly', async () => {
    if (serverUnreachable) return;

    const alias = TestConfig.uniqueAlias('secret-01-paginate');

    // Create then update 3 times to have 4 versions
    const created = await client.secrets.create({
      alias,
      type: 'opaque',
      data: { v: 1 },
    });
    createdSecretIds.push(created.id);

    for (let i = 2; i <= 4; i++) {
      await client.secrets.update(created.id, { data: { v: i } });
    }

    // Fetch first page of 2
    const page1 = await client.secrets.getHistory(created.id, { limit: 2, offset: 0 });
    expect(page1.items.length).toBeLessThanOrEqual(2);
    expect(page1.pagination.limit).toBe(2);
    expect(page1.pagination.offset).toBe(0);

    // Fetch second page
    const page2 = await client.secrets.getHistory(created.id, { limit: 2, offset: 2 });
    expect(page2.pagination.offset).toBe(2);

    console.log(
      `SECRET-01 pagination pass: page1.length=${page1.items.length}, ` +
      `page2.length=${page2.items.length}`
    );
  });

  // ---------------------------------------------------------------------------
  // SECRET-02: updateMetadata hits /metadata endpoint and returns updated secret
  // ---------------------------------------------------------------------------

  it('SECRET-02: updateMetadata({ tags }) succeeds and returns updated secret', async () => {
    if (serverUnreachable) return;

    const alias = TestConfig.uniqueAlias('secret-02-metadata');

    const created = await client.secrets.create({
      alias,
      type: 'opaque',
      data: { value: 'metadata-test' },
      tags: ['original-tag'],
    });
    createdSecretIds.push(created.id);

    const originalVersion = created.version;

    // Update only the metadata (tags) — should NOT bump the version
    const updated = await client.secrets.updateMetadata(created.id, {
      tags: ['updated-tag', 'e2e', 'test'],
    });

    expect(updated).toBeDefined();
    expect(updated.id).toBe(created.id);

    // tags should be updated
    if (updated.tags !== undefined) {
      // Tags may be returned as an array or object; verify the value changed
      const tagsStr = JSON.stringify(updated.tags);
      expect(tagsStr).toContain('updated-tag');
    }

    // Version should NOT have changed (metadata update does not create new version)
    expect(updated.version).toBe(originalVersion);

    console.log(
      `SECRET-02 pass: metadata updated, version unchanged at ${updated.version}`
    );
  });

  it('SECRET-02: updateMetadata with empty tags array succeeds', async () => {
    if (serverUnreachable) return;

    const alias = TestConfig.uniqueAlias('secret-02-empty-tags');

    const created = await client.secrets.create({
      alias,
      type: 'opaque',
      data: { value: 'empty-tags-test' },
      tags: ['some-tag'],
    });
    createdSecretIds.push(created.id);

    // Clear all tags
    const updated = await client.secrets.updateMetadata(created.id, {
      tags: [],
    });

    expect(updated).toBeDefined();
    expect(updated.id).toBe(created.id);

    console.log(`SECRET-02 empty-tags pass: id=${updated.id}`);
  });

  // ---------------------------------------------------------------------------
  // Combined: create → update → history → updateMetadata flow
  // ---------------------------------------------------------------------------

  it('SECRET-01/02: full flow — create, update, getHistory, updateMetadata', async () => {
    if (serverUnreachable) return;

    const alias = TestConfig.uniqueAlias('secret-full-flow');

    // 1. Create
    const secret = await client.secrets.create({
      alias,
      type: 'credential',
      data: { username: 'flowuser', password: 'flowpass' },
      tags: ['flow-start'],
    });
    createdSecretIds.push(secret.id);
    expect(secret.version).toBe(1);

    // 2. Update (new version)
    const v2 = await client.secrets.update(secret.id, {
      data: { username: 'flowuser', password: 'updated-pass' },
    });
    expect(v2.version).toBe(2);

    // 3. getHistory — SECRET-01
    // History records superseded (old) versions. After one update there is
    // 1 history entry (v1, now superseded by v2). v2 is the current live
    // version returned by GET /secrets/:id, not in the history list.
    const history = await client.secrets.getHistory(secret.id);
    expect(Array.isArray(history.items)).toBe(true);
    expect(history.pagination).toBeDefined();
    expect(history.items.length).toBeGreaterThanOrEqual(1);

    // 4. updateMetadata — SECRET-02
    const meta = await client.secrets.updateMetadata(secret.id, {
      tags: ['flow-end', 'e2e'],
    });
    expect(meta.id).toBe(secret.id);
    expect(meta.version).toBe(v2.version); // still v2

    console.log(
      `SECRET full-flow pass: id=${secret.id}, ` +
      `historyEntries=${history.items.length}, finalVersion=${meta.version}`
    );
  });
});
