// Path: zn-vault-sdk-node/test/e2e/kms.e2e.test.ts
//
// E2E assertions proving KMS-01/03/04:
//   KMS-01 — encryptString/decryptString round-trip returns the original plaintext.
//   KMS-03 — getKeyByAlias resolves the pre-seeded `alias/sdk-test-aes` key.
//   KMS-04 — getKey/getKeyByAlias unwrap keyMetadata and normalize the raw
//             server fields (id→keyId, usage→keyUsage, createdAt→createdDate),
//             so callers always see the canonical SDK names.
//
// Requires a live seeded vault (`npm run test:e2e`). Skipped when
// ZNVAULT_BASE_URL is not set or the server is unreachable.

import { describe, it, expect, beforeAll } from 'vitest';
import type { ZnVaultClient } from '../../src/index.js';
import { TestConfig } from '../test-config.js';
import { probeServer } from '../helpers/integration.js';

const isIntegrationEnabled = TestConfig.isIntegrationEnabled();

describe.skipIf(!isIntegrationEnabled)('E2E: KMS — contract fixes KMS-01/03/04', () => {
  let serverUnreachable = false;

  // Pre-seeded by sdk-entrypoint.js → TEST_DATA.kmsKeys
  const SEEDED_ALIAS = 'alias/sdk-test-aes';

  // Use tenant admin for all KMS operations — kms-user has no effective
  // permissions in the e2e environment (permissions require role assignment
  // via the vault RBAC system, not direct user-create params).
  let adminClient: ZnVaultClient;

  beforeAll(async () => {
    if (!(await probeServer())) {
      serverUnreachable = true;
      return;
    }
    adminClient = await TestConfig.createTenantAdminClient();
  });

  // ---------------------------------------------------------------------------
  // KMS-03/04: key lookup by alias — keyMetadata is unwrapped, keyState present
  // ---------------------------------------------------------------------------

  it('KMS-03: getKeyByAlias resolves the pre-seeded alias without error', async () => {
    if (serverUnreachable) return;

    const key = await adminClient.kms.getKeyByAlias(SEEDED_ALIAS);

    // KMS-03: alias resolves without error
    expect(key).toBeDefined();
    // Alias field should match (server returns it in keyMetadata)
    expect(key.alias).toBe(SEEDED_ALIAS);

    console.log(`KMS-03 pass: alias resolved, alias=${key.alias}`);
  });

  it('KMS-04: getKeyByAlias returns keyState ∈ {ENABLED, DISABLED, PENDING_DELETION}', async () => {
    if (serverUnreachable) return;

    const key = await adminClient.kms.getKeyByAlias(SEEDED_ALIAS);

    // KMS-04: keyState is present and is one of the valid states
    expect(['ENABLED', 'DISABLED', 'PENDING_DELETION']).toContain(key.keyState);

    console.log(`KMS-04 pass: keyState=${key.keyState}`);
  });

  it('KMS-04: getKeyByAlias exposes a non-empty createdDate (canonical SDK name)', async () => {
    if (serverUnreachable) return;

    // The SDK normalizes the raw server field `createdAt` → `createdDate`.
    // After the fix, the canonical name must be populated and the raw field must not leak.
    const key = await adminClient.kms.getKeyByAlias(SEEDED_ALIAS);

    expect(typeof key.createdDate).toBe('string');
    expect(key.createdDate.length).toBeGreaterThan(0);
    // Raw field must not be present on the returned object
    expect((key as unknown as Record<string, unknown>).createdAt).toBeUndefined();

    console.log(`KMS-04 date pass: createdDate=${key.createdDate}`);
  });

  it('KMS-04: getKeyByAlias exposes keyId (canonical SDK name, not raw id)', async () => {
    if (serverUnreachable) return;

    // The SDK normalizes the raw server field `id` → `keyId`.
    // After the fix, keyId must be populated and the stray `id` field must not leak.
    const key = await adminClient.kms.getKeyByAlias(SEEDED_ALIAS);

    expect(typeof key.keyId).toBe('string');
    expect(key.keyId.length).toBeGreaterThan(0);
    // Raw `id` field must not be present on the returned object
    expect((key as unknown as Record<string, unknown>).id).toBeUndefined();

    console.log(`KMS-04 id pass: keyId=${key.keyId}`);
  });

  it('KMS-04: getKeyByAlias exposes keyUsage (canonical SDK name, not raw usage)', async () => {
    if (serverUnreachable) return;

    const key = await adminClient.kms.getKeyByAlias(SEEDED_ALIAS);

    expect(typeof key.keyUsage).toBe('string');
    expect((key as unknown as Record<string, unknown>).usage).toBeUndefined();

    console.log(`KMS-04 usage pass: keyUsage=${key.keyUsage}`);
  });

  it('KMS-04: listKeys normalizes items — canonical keyId, keyState, and createdDate are populated', async () => {
    if (serverUnreachable) return;

    const response = await adminClient.kms.listKeys();

    expect(Array.isArray(response.items)).toBe(true);
    expect(response.items.length).toBeGreaterThan(0);

    const firstKey = response.items[0];
    // keyState must be a valid state (present in both raw and canonical shapes)
    expect(['ENABLED', 'DISABLED', 'PENDING_DELETION']).toContain(firstKey.keyState);
    // keyId must be canonical and non-empty (normalizeKmsKey maps raw `id` → `keyId`)
    expect(typeof firstKey.keyId).toBe('string');
    expect(firstKey.keyId.length).toBeGreaterThan(0);
    // createdDate must be canonical and non-empty (normalizeKmsKey maps raw `createdAt` → `createdDate`)
    expect(typeof firstKey.createdDate).toBe('string');
    expect(firstKey.createdDate.length).toBeGreaterThan(0);

    console.log(`KMS-04 listKeys pass: count=${response.items.length}, firstKeyId=${firstKey.keyId}, firstKeyState=${firstKey.keyState}, createdDate=${firstKey.createdDate}`);
  });

  // ---------------------------------------------------------------------------
  // KMS-01: encrypt→decrypt round-trip via alias (admin client)
  // ---------------------------------------------------------------------------

  it('KMS-01: encryptString(alias, plaintext) → decryptString(...) returns original plaintext', async () => {
    if (serverUnreachable) return;

    const plaintext = 'hello-e2e';

    const ciphertext = await adminClient.kms.encryptString(SEEDED_ALIAS, plaintext);

    expect(typeof ciphertext).toBe('string');
    expect(ciphertext.length).toBeGreaterThan(0);

    const recovered = await adminClient.kms.decryptString(SEEDED_ALIAS, ciphertext);

    expect(recovered).toBe(plaintext);

    console.log(`KMS-01 pass: round-trip via alias, ciphertext length=${ciphertext.length}`);
  });

  it('KMS-01: encryptString/decryptString preserves multi-byte UTF-8 strings', async () => {
    if (serverUnreachable) return;

    const plaintext = 'héllo-wörld-🔐';

    const ciphertext = await adminClient.kms.encryptString(SEEDED_ALIAS, plaintext);
    const recovered = await adminClient.kms.decryptString(SEEDED_ALIAS, ciphertext);

    expect(recovered).toBe(plaintext);

    console.log(`KMS-01 utf8 pass: round-trip preserved multi-byte string`);
  });

  it('KMS-01: encrypt/decrypt using low-level method with explicit context', async () => {
    if (serverUnreachable) return;

    const plaintext = 'context-test';
    const base64 = Buffer.from(plaintext).toString('base64');
    const ctx = { purpose: 'e2e-test' };

    const encResult = await adminClient.kms.encrypt({
      keyId: SEEDED_ALIAS,
      plaintext: base64,
      context: ctx,
    });

    expect(typeof encResult.ciphertext).toBe('string');
    expect(encResult.ciphertext.length).toBeGreaterThan(0);

    const decResult = await adminClient.kms.decrypt({
      keyId: SEEDED_ALIAS,
      ciphertext: encResult.ciphertext,
      context: ctx,
    });

    const decoded = Buffer.from(decResult.plaintext, 'base64').toString('utf-8');
    expect(decoded).toBe(plaintext);

    console.log(`KMS-01 low-level pass: encrypt+decrypt with context`);
  });

  it('KMS-01: getKey resolves via keyId obtained from getKeyByAlias (canonical keyId)', async () => {
    if (serverUnreachable) return;

    // Resolve key via alias — keyId is now normalized by the SDK
    const byAlias = await adminClient.kms.getKeyByAlias(SEEDED_ALIAS);

    // keyId must be populated (normalized from raw `id`)
    expect(typeof byAlias.keyId).toBe('string');
    expect(byAlias.keyId.length).toBeGreaterThan(0);

    // Now get by ID using the canonical keyId
    const byId = await adminClient.kms.getKey(byAlias.keyId);
    expect(byId).toBeDefined();
    expect(['ENABLED', 'DISABLED', 'PENDING_DELETION']).toContain(byId.keyState);
    // getKey also normalizes — keyId and createdDate must be present
    expect(typeof byId.keyId).toBe('string');
    expect(typeof byId.createdDate).toBe('string');

    console.log(`KMS-01 getKey via id pass: keyId=${byAlias.keyId}, keyState=${byId.keyState}`);
  });
});
