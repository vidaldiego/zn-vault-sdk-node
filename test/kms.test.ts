// Path: zn-vault-sdk-node/test/kms.test.ts

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { KmsClient } from '../src/kms/client.js';
import type { HttpClient } from '../src/http/client.js';

function makeClient() {
  const http = { post: vi.fn(), get: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() };
  return { client: new KmsClient(http as unknown as HttpClient), http };
}

describe('KmsClient crypto (mocked HTTP)', () => {
  let client: KmsClient; let http: ReturnType<typeof makeClient>['http'];
  beforeEach(() => ({ client, http } = makeClient()));

  it('encrypt sends keyId/plaintext/context and reads response.ciphertext', async () => {
    http.post.mockResolvedValue({ keyId: 'k1', ciphertext: 'CT', encryptionContext: {} });
    const res = await client.encrypt({ keyId: 'k1', plaintext: 'cGxhaW4=', context: { a: 'b' } });
    expect(http.post).toHaveBeenCalledWith('/v1/kms/encrypt', { keyId: 'k1', plaintext: 'cGxhaW4=', context: { a: 'b' } });
    expect(res.ciphertext).toBe('CT');
  });

  it('decrypt sends ciphertext (not ciphertextBlob) + required context', async () => {
    http.post.mockResolvedValue({ keyId: 'k1', plaintext: 'cGxhaW4=' });
    await client.decrypt({ keyId: 'k1', ciphertext: 'CT', context: {} });
    expect(http.post).toHaveBeenCalledWith('/v1/kms/decrypt', { keyId: 'k1', ciphertext: 'CT', context: {} });
  });

  it('encryptString round-trips via response.ciphertext', async () => {
    http.post.mockResolvedValue({ keyId: 'k1', ciphertext: 'CTBLOB' });
    const out = await client.encryptString('k1', 'hello');
    expect(out).toBe('CTBLOB');
  });

  it('reEncrypt sends ciphertext/sourceKeyId/sourceContext/destinationKeyId/destinationContext (not ciphertextBlob/keyId) and reads response.ciphertext', async () => {
    const mockResponse = { sourceKeyId: 'src-key', destinationKeyId: 'dst-key', ciphertext: 'NEWCT' };
    http.post.mockResolvedValue(mockResponse);
    const res = await client.reEncrypt({
      ciphertext: 'OLDCT',
      sourceKeyId: 'src-key',
      sourceContext: { env: 'prod' },
      destinationKeyId: 'dst-key',
      destinationContext: { env: 'staging' },
    });
    expect(http.post).toHaveBeenCalledWith('/v1/kms/re-encrypt', {
      ciphertext: 'OLDCT',
      sourceKeyId: 'src-key',
      sourceContext: { env: 'prod' },
      destinationKeyId: 'dst-key',
      destinationContext: { env: 'staging' },
    });
    expect(res.ciphertext).toBe('NEWCT');
    expect(res.sourceKeyId).toBe('src-key');
    expect(res.destinationKeyId).toBe('dst-key');
  });
});

// KMS-04/05/09, URL-01: keyMetadata unwrap, keyState/createdDate field names,
// alias URL-encoding, phantom rotation fields removed from createKey body.
describe('KmsClient key metadata contract (mocked HTTP)', () => {
  let client: KmsClient; let http: ReturnType<typeof makeClient>['http'];
  beforeEach(() => ({ client, http } = makeClient()));

  // Raw shape as emitted by the live server's getKey/getKeyByAlias handlers
  // (id/usage/createdAt instead of keyId/keyUsage/createdDate — schema/handler drift).
  const wrappedKey = {
    keyMetadata: {
      id: 'key-uuid-1',
      alias: 'my/prod/key',
      arn: 'arn:zn-vault:kms:us-east-1:acme:key/key-uuid-1',
      createdAt: '2026-01-01T00:00:00.000Z',
      description: 'Production key',
      keyState: 'ENABLED',
      usage: 'ENCRYPT_DECRYPT',
      keySpec: 'AES_256',
      multiRegion: false,
      origin: 'ZN_VAULT',
    },
  };

  it('getKey unwraps keyMetadata, normalizes id→keyId, usage→keyUsage, createdAt→createdDate (KMS-04/05)', async () => {
    http.get.mockResolvedValue(wrappedKey);
    const key = await client.getKey('key-uuid-1');
    expect(http.get).toHaveBeenCalledWith('/v1/kms/keys/key-uuid-1');
    // Must unwrap keyMetadata AND normalize raw field names
    expect(key.keyId).toBe('key-uuid-1');
    expect(key.keyState).toBe('ENABLED');
    expect(key.createdDate).toBe('2026-01-01T00:00:00.000Z');
    expect(key.keyUsage).toBe('ENCRYPT_DECRYPT');
    // Must NOT have phantom rotation fields
    expect((key as Record<string, unknown>).rotationEnabled).toBeUndefined();
    expect((key as Record<string, unknown>).rotationPeriodDays).toBeUndefined();
    // Must NOT expose raw field aliases — they must be mapped to canonical names
    expect((key as Record<string, unknown>).state).toBeUndefined();
    expect((key as Record<string, unknown>).createdAt).toBeUndefined();
    expect((key as Record<string, unknown>).id).toBeUndefined();
    expect((key as Record<string, unknown>).usage).toBeUndefined();
  });

  it('getKeyByAlias URL-encodes the alias and normalizes raw keyMetadata (KMS-09, URL-01)', async () => {
    http.get.mockResolvedValue(wrappedKey);
    const key = await client.getKeyByAlias('my/prod/key');
    // Slash in alias must be percent-encoded
    expect(http.get).toHaveBeenCalledWith('/v1/kms/keys/alias/my%2Fprod%2Fkey');
    // Normalized canonical names are present
    expect(key.keyId).toBe('key-uuid-1');
    expect(key.keyState).toBe('ENABLED');
    expect(key.createdDate).toBe('2026-01-01T00:00:00.000Z');
    expect(key.keyUsage).toBe('ENCRYPT_DECRYPT');
    // Raw names must not leak through
    expect((key as Record<string, unknown>).id).toBeUndefined();
    expect((key as Record<string, unknown>).usage).toBeUndefined();
    expect((key as Record<string, unknown>).createdAt).toBeUndefined();
  });

  it('createKey omits rotationEnabled/rotationPeriodDays from request body', async () => {
    const createResponse = {
      keyId: 'new-key-id',
      alias: 'billing/key',
      arn: 'arn:zn-vault:kms:us-east-1:acme:key/new-key-id',
      createdDate: '2026-06-24T00:00:00.000Z',
      keyState: 'ENABLED',
      keyUsage: 'ENCRYPT_DECRYPT',
      keySpec: 'AES_256',
    };
    http.post.mockResolvedValue(createResponse);
    const result = await client.createKey({
      alias: 'billing/key',
      description: 'Billing key',
    });
    const body = http.post.mock.calls[0][1] as Record<string, unknown>;
    expect(body).not.toHaveProperty('rotationEnabled');
    expect(body).not.toHaveProperty('rotationPeriodDays');
    expect(body.alias).toBe('billing/key');
    expect(body.usage).toBe('ENCRYPT_DECRYPT');
    expect(body.keySpec).toBe('AES_256');
    // createKey response is not wrapped in keyMetadata
    expect(result.keyId).toBe('new-key-id');
    expect(result.keyState).toBe('ENABLED');
    expect(result.createdDate).toBe('2026-06-24T00:00:00.000Z');
  });

  it('listKeys normalizes raw item shape (id→keyId, createdAt→createdDate)', async () => {
    // Mock the raw item shape that the list endpoint might emit (mirrors the
    // schema drift seen on single-key read endpoints). normalizeKmsKey must
    // convert id→keyId and createdAt→createdDate on each item.
    const rawListResponse = {
      items: [
        { id: 'k1', alias: 'prod/key', keyState: 'ENABLED', createdAt: '2026-01-01T00:00:00.000Z' },
        { id: 'k2', keyState: 'DISABLED', createdAt: '2026-02-01T00:00:00.000Z' },
      ],
      pagination: { total: 2, limit: 50, offset: 0, hasMore: false },
    };
    http.get.mockResolvedValue(rawListResponse);
    const result = await client.listKeys({ state: 'ENABLED', limit: 10 });
    expect(http.get).toHaveBeenCalledWith('/v1/kms/keys?state=ENABLED&limit=10');
    // Items must be normalized: raw `id` → canonical `keyId`
    expect(result.items[0].keyId).toBe('k1');
    expect(result.items[1].keyId).toBe('k2');
    // Items must be normalized: raw `createdAt` → canonical `createdDate`
    expect(result.items[0].createdDate).toBe('2026-01-01T00:00:00.000Z');
    expect(result.items[1].createdDate).toBe('2026-02-01T00:00:00.000Z');
    // keyState passthrough (not renamed)
    expect(result.items[0].keyState).toBe('ENABLED');
    expect(result.items[1].keyState).toBe('DISABLED');
    // Raw field names must not leak through
    expect((result.items[0] as Record<string, unknown>).id).toBeUndefined();
    expect((result.items[0] as Record<string, unknown>).createdAt).toBeUndefined();
  });
});

// KMS-06/07/08: rotation status/history field names + scheduleKeyDeletion body field
describe('KmsClient rotation status/history + scheduleKeyDeletion (KMS-06/07/08)', () => {
  let client: KmsClient; let http: ReturnType<typeof makeClient>['http'];
  beforeEach(() => ({ client, http } = makeClient()));

  it('setRotationStatus PUT body uses { enabled, intervalDays } not { rotationEnabled, rotationPeriodDays }', async () => {
    http.put.mockResolvedValue({
      keyId: 'key-1',
      rotationEnabled: true,
      intervalDays: 90,
      rotationCount: 0,
    });
    await client.setRotationStatus('key-1', true, 90);
    const body = http.put.mock.calls[0][1] as Record<string, unknown>;
    expect(body).toHaveProperty('enabled', true);
    expect(body).toHaveProperty('intervalDays', 90);
    expect(body).not.toHaveProperty('rotationEnabled');
    expect(body).not.toHaveProperty('rotationPeriodDays');
  });

  it('setRotationStatus returns RotationStatus shape with rotationEnabled/rotationCount', async () => {
    const serverResponse = {
      keyId: 'key-1',
      rotationEnabled: true,
      intervalDays: 90,
      lastRotationDate: '2026-01-01T00:00:00.000Z',
      nextRotationDate: '2026-04-01T00:00:00.000Z',
      rotationCount: 3,
    };
    http.put.mockResolvedValue(serverResponse);
    const result = await client.setRotationStatus('key-1', true, 90);
    expect(result.keyId).toBe('key-1');
    expect(result.rotationEnabled).toBe(true);
    expect(result.intervalDays).toBe(90);
    expect(result.rotationCount).toBe(3);
    expect(result.lastRotationDate).toBe('2026-01-01T00:00:00.000Z');
    expect(result.nextRotationDate).toBe('2026-04-01T00:00:00.000Z');
  });

  it('getRotationStatus returns RotationStatus shape (not rotationPeriodDays)', async () => {
    const serverResponse = {
      keyId: 'key-2',
      rotationEnabled: false,
      intervalDays: undefined,
      rotationCount: 0,
    };
    http.get.mockResolvedValue(serverResponse);
    const result = await client.getRotationStatus('key-2');
    expect(http.get).toHaveBeenCalledWith('/v1/kms/keys/key-2/rotation-status');
    expect(result.keyId).toBe('key-2');
    expect(result.rotationEnabled).toBe(false);
    expect(result.rotationCount).toBe(0);
    // Old field name must not appear
    expect((result as Record<string, unknown>).rotationPeriodDays).toBeUndefined();
  });

  it('getRotationHistory reads response.history (not response.versions)', async () => {
    const serverResponse = {
      history: [
        {
          id: 'hist-1',
          keyId: 'key-3',
          oldVersion: 1,
          newVersion: 2,
          rotationType: 'MANUAL',
          rotationDate: '2026-03-01T00:00:00.000Z',
          initiatedBy: 'admin',
          success: true,
        },
      ],
    };
    http.get.mockResolvedValue(serverResponse);
    const result = await client.getRotationHistory('key-3');
    expect(http.get).toHaveBeenCalledWith('/v1/kms/keys/key-3/rotation-history');
    expect(result.history).toHaveLength(1);
    const entry = result.history[0];
    expect(entry.id).toBe('hist-1');
    expect(entry.keyId).toBe('key-3');
    expect(entry.oldVersion).toBe(1);
    expect(entry.newVersion).toBe(2);
    expect(entry.rotationType).toBe('MANUAL');
    expect(entry.initiatedBy).toBe('admin');
    expect(entry.success).toBe(true);
    // Must not expose old shape
    expect((result as Record<string, unknown>).versions).toBeUndefined();
  });

  it('getRotationHistory passes limit as query param when provided', async () => {
    http.get.mockResolvedValue({ history: [] });
    await client.getRotationHistory('key-4', 5);
    expect(http.get).toHaveBeenCalledWith('/v1/kms/keys/key-4/rotation-history?limit=5');
  });

  it('scheduleKeyDeletion body uses pendingWindowInDays not pendingWindowDays', async () => {
    const serverResponse = {
      keyId: 'key-5',
      keyState: 'PENDING_DELETION',
      deletionDate: '2026-07-21T00:00:00.000Z',
    };
    http.post.mockResolvedValue(serverResponse);
    const result = await client.scheduleKeyDeletion('key-5', 21);
    const body = http.post.mock.calls[0][1] as Record<string, unknown>;
    expect(body).toHaveProperty('pendingWindowInDays', 21);
    expect(body).not.toHaveProperty('pendingWindowDays');
    // Return type is ScheduleDeletionResponse, not KmsKey
    expect(result.keyId).toBe('key-5');
    expect(result.keyState).toBe('PENDING_DELETION');
    expect(result.deletionDate).toBe('2026-07-21T00:00:00.000Z');
    // Must not expose KmsKey-specific fields
    expect((result as Record<string, unknown>).keySpec).toBeUndefined();
    expect((result as Record<string, unknown>).keyUsage).toBeUndefined();
  });
});

// Task-6 review fix: mutation endpoints emit createdAt (legacy) instead of createdDate.
// The SDK must normalize createdAt → createdDate so callers always see createdDate.
describe('KmsClient mutation endpoints createdAt normalization (Task-6 review)', () => {
  let client: KmsClient; let http: ReturnType<typeof makeClient>['http'];
  beforeEach(() => ({ client, http } = makeClient()));

  it('enableKey: server response with createdAt (no createdDate) is normalized to createdDate', async () => {
    // Simulate the legacy server shape returned by mutation endpoints.
    const legacyServerResponse = {
      keyId: 'key-uuid-42',
      alias: 'billing/key',
      arn: 'arn:zn-vault:kms:us-east-1:acme:key/key-uuid-42',
      // Server emits `createdAt`, NOT `createdDate`
      createdAt: '2026-06-24T10:00:00.000Z',
      keyState: 'ENABLED',
      keyUsage: 'ENCRYPT_DECRYPT',
      keySpec: 'AES_256',
      multiRegion: false,
      origin: 'ZN_VAULT',
    };
    http.post.mockResolvedValue(legacyServerResponse);

    const key = await client.enableKey('key-uuid-42');

    // The normalized result must expose createdDate populated from createdAt
    expect(key.createdDate).toBe('2026-06-24T10:00:00.000Z');
    // The stray createdAt field must not leak through to the caller
    expect((key as Record<string, unknown>).createdAt).toBeUndefined();
    // Other fields are preserved
    expect(key.keyId).toBe('key-uuid-42');
    expect(key.keyState).toBe('ENABLED');
  });
});
