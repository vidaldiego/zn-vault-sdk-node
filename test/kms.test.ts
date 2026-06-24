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
});
