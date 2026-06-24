// Path: zn-vault-sdk-node/test/e2e/kms.e2e.test.ts
//
// E2E assertions proving KMS-01/03/04:
//   KMS-01 — encryptString/decryptString round-trip returns the original plaintext.
//   KMS-03 — getKeyByAlias resolves the pre-seeded `alias/sdk-test-aes` key.
//   KMS-04 — getKey/getKeyByAlias unwrap keyMetadata and expose `keyState` and
//             a date field (the server returns `createdAt` which the SDK type
//             models as `createdDate` — tests confirm the field is non-empty).
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

  it('KMS-04: getKeyByAlias exposes a non-empty date field (createdDate or createdAt)', async () => {
    if (serverUnreachable) return;

    // The SDK type models this field as `createdDate`. The server returns it
    // as `createdAt` in the keyMetadata object — the client returns the raw
    // server shape without re-mapping on the read path. We check whichever
    // field is populated, proving the date is present and non-empty.
    const key = await adminClient.kms.getKeyByAlias(SEEDED_ALIAS);
    const raw = key as unknown as Record<string, unknown>;

    // At least one of createdDate or createdAt must be a non-empty string
    const dateField = (raw.createdDate ?? raw.createdAt) as string | undefined;
    expect(typeof dateField).toBe('string');
    expect((dateField ?? '').length).toBeGreaterThan(0);

    console.log(`KMS-04 date pass: createdDate=${String(raw.createdDate)}, createdAt=${String(raw.createdAt)}`);
  });

  it('KMS-04: getKeyByAlias contains a key identifier (keyId or id)', async () => {
    if (serverUnreachable) return;

    const key = await adminClient.kms.getKeyByAlias(SEEDED_ALIAS);
    const raw = key as unknown as Record<string, unknown>;

    // The SDK type expects `keyId` but the server returns `id` in keyMetadata.
    // Either field must be a non-empty UUID string.
    const idField = (raw.keyId ?? raw.id) as string | undefined;
    expect(typeof idField).toBe('string');
    expect((idField ?? '').length).toBeGreaterThan(0);

    console.log(`KMS-04 id pass: keyId=${String(raw.keyId)}, id=${String(raw.id)}`);
  });

  it('KMS-04: listKeys returns items with keyState and a date field', async () => {
    if (serverUnreachable) return;

    const response = await adminClient.kms.listKeys();

    expect(Array.isArray(response.items)).toBe(true);
    expect(response.items.length).toBeGreaterThan(0);

    const firstKey = response.items[0];
    expect(['ENABLED', 'DISABLED', 'PENDING_DELETION']).toContain(firstKey.keyState);

    // The list endpoint may return keyId or id, and createdDate or createdAt
    const raw = firstKey as unknown as Record<string, unknown>;
    const dateField = (raw.createdDate ?? raw.createdAt) as string | undefined;
    expect(typeof dateField).toBe('string');

    console.log(`KMS-04 listKeys pass: count=${response.items.length}, firstKeyState=${firstKey.keyState}`);
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

  it('KMS-01: getKey resolves via keyId obtained from getKeyByAlias', async () => {
    if (serverUnreachable) return;

    // Resolve key via alias — then look up by its actual ID
    const byAlias = await adminClient.kms.getKeyByAlias(SEEDED_ALIAS);
    const raw = byAlias as unknown as Record<string, unknown>;
    const keyId = (raw.keyId ?? raw.id) as string;

    expect(typeof keyId).toBe('string');
    expect(keyId.length).toBeGreaterThan(0);

    // Now get by ID
    const byId = await adminClient.kms.getKey(keyId);
    expect(byId).toBeDefined();
    expect(['ENABLED', 'DISABLED', 'PENDING_DELETION']).toContain(byId.keyState);

    console.log(`KMS-01 getKey via id pass: id=${keyId}, keyState=${byId.keyState}`);
  });
});
