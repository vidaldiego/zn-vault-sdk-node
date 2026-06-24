// Path: zn-vault-sdk-node/src/kms/client.ts

import type { HttpClient } from '../http/client.js';
import type {
  KmsKey,
  KeyUsage,
  CreateKeyRequest,
  EncryptRequest,
  EncryptResponse,
  DecryptRequest,
  DecryptResponse,
  GenerateDataKeyRequest,
  GenerateDataKeyResponse,
  ReEncryptRequest,
  ReEncryptResponse,
  KeyFilter,
  PaginatedResponse,
  RotationStatus,
  RotationHistoryEntry,
  ScheduleDeletionResponse,
} from '../types/index.js';

/**
 * Raw shape as returned by the server. Read endpoints (`getKey`, `getKeyByAlias`)
 * emit `id`/`usage`/`createdAt` while mutation endpoints and some other paths
 * emit the canonical `keyId`/`keyUsage`/`createdDate`. All three pairs may be
 * present simultaneously during a transition period — normalizeKmsKey handles
 * both by preferring the canonical name and falling back to the raw name.
 */
type RawKmsKey = Omit<KmsKey, 'keyId' | 'keyUsage' | 'createdDate'> & {
  /** Canonical name (mutation endpoints / createKey) */
  keyId?: string;
  /** Raw name emitted by read endpoints (getKey, getKeyByAlias) */
  id?: string;
  /** Canonical name */
  keyUsage?: KeyUsage;
  /** Raw name emitted by read endpoints */
  usage?: KeyUsage;
  /** Canonical name */
  createdDate?: string;
  /** Raw name emitted by read endpoints and mutation endpoints */
  createdAt?: string;
};

/**
 * Normalizes the raw server key shape into the canonical SDK `KmsKey` type.
 *
 * The server has a schema/handler drift on the read endpoints where the live
 * handler emits `id`/`usage`/`createdAt` while the type contract and mutation
 * endpoints use `keyId`/`keyUsage`/`createdDate`. This function is idempotent:
 * if the canonical name is already present it is used as-is; the raw name is
 * only a fallback.
 */
function normalizeKmsKey(raw: RawKmsKey): KmsKey {
  const { id, keyId, usage, keyUsage, createdAt, createdDate, ...rest } = raw;
  return {
    ...rest,
    keyId: keyId ?? id ?? '',
    keyUsage: (keyUsage ?? usage) as KeyUsage,
    createdDate: createdDate ?? createdAt ?? '',
  };
}

export class KmsClient {
  constructor(private http: HttpClient) {}

  async createKey(request: CreateKeyRequest): Promise<KmsKey> {
    const raw = await this.http.post<RawKmsKey>('/v1/kms/keys', {
      alias: request.alias,
      description: request.description,
      usage: request.usage ?? 'ENCRYPT_DECRYPT',
      keySpec: request.keySpec ?? 'AES_256',
      origin: request.origin,
      multiRegion: request.multiRegion,
      tags: request.tags,
    });
    return normalizeKmsKey(raw);
  }

  async getKey(keyId: string): Promise<KmsKey> {
    const r = await this.http.get<{ keyMetadata: RawKmsKey }>(`/v1/kms/keys/${keyId}`);
    return normalizeKmsKey(r.keyMetadata);
  }

  async getKeyByAlias(alias: string): Promise<KmsKey> {
    const r = await this.http.get<{ keyMetadata: RawKmsKey }>(`/v1/kms/keys/alias/${encodeURIComponent(alias)}`);
    return normalizeKmsKey(r.keyMetadata);
  }

  async listKeys(filter?: KeyFilter): Promise<PaginatedResponse<KmsKey>> {
    const params = new URLSearchParams();
    if (filter?.state) params.set('state', filter.state);
    if (filter?.limit) params.set('limit', filter.limit.toString());
    if (filter?.offset) params.set('offset', filter.offset.toString());

    const query = params.toString();
    const path = query ? `/v1/kms/keys?${query}` : '/v1/kms/keys';
    // Normalize each item defensively: the list endpoint currently emits canonical
    // names (keyId/keyUsage/createdDate), but single-key read endpoints (getKey,
    // getKeyByAlias) emit raw names (id/usage/createdAt) due to server schema drift.
    // Normalizing here keeps listKeys correct if the list endpoint ever drifts the
    // same way. normalizeKmsKey is idempotent for already-canonical input.
    const page = await this.http.get<PaginatedResponse<RawKmsKey>>(path);
    return { ...page, items: page.items.map(normalizeKmsKey) };
  }

  async updateKeyDescription(keyId: string, description: string): Promise<KmsKey> {
    const raw = await this.http.put<RawKmsKey>(`/v1/kms/keys/${keyId}/description`, { description });
    return normalizeKmsKey(raw);
  }

  async updateKeyAlias(keyId: string, alias: string): Promise<KmsKey> {
    const raw = await this.http.put<RawKmsKey>(`/v1/kms/keys/${keyId}/alias`, { alias });
    return normalizeKmsKey(raw);
  }

  async enableKey(keyId: string): Promise<KmsKey> {
    const raw = await this.http.post<RawKmsKey>(`/v1/kms/keys/${keyId}/enable`);
    return normalizeKmsKey(raw);
  }

  async disableKey(keyId: string): Promise<KmsKey> {
    const raw = await this.http.post<RawKmsKey>(`/v1/kms/keys/${keyId}/disable`);
    return normalizeKmsKey(raw);
  }

  async scheduleKeyDeletion(keyId: string, pendingWindowInDays?: number): Promise<ScheduleDeletionResponse> {
    return this.http.post<ScheduleDeletionResponse>(`/v1/kms/keys/${keyId}/schedule-deletion`, {
      pendingWindowInDays,
    });
  }

  async cancelKeyDeletion(keyId: string): Promise<KmsKey> {
    const raw = await this.http.post<RawKmsKey>(`/v1/kms/keys/${keyId}/cancel-deletion`);
    return normalizeKmsKey(raw);
  }

  async rotateKey(keyId: string): Promise<KmsKey> {
    const raw = await this.http.post<RawKmsKey>(`/v1/kms/keys/${keyId}/rotate`);
    return normalizeKmsKey(raw);
  }

  async setRotationStatus(
    keyId: string,
    enabled: boolean,
    intervalDays?: number
  ): Promise<RotationStatus> {
    return this.http.put<RotationStatus>(`/v1/kms/keys/${keyId}/rotation-status`, {
      enabled,
      intervalDays,
    });
  }

  async getRotationStatus(keyId: string): Promise<RotationStatus> {
    return this.http.get<RotationStatus>(`/v1/kms/keys/${keyId}/rotation-status`);
  }

  async getRotationHistory(
    keyId: string,
    limit?: number
  ): Promise<{ history: RotationHistoryEntry[] }> {
    const path = limit !== undefined
      ? `/v1/kms/keys/${keyId}/rotation-history?limit=${limit}`
      : `/v1/kms/keys/${keyId}/rotation-history`;
    return this.http.get<{ history: RotationHistoryEntry[] }>(path);
  }

  // Encryption operations
  async encrypt(request: EncryptRequest): Promise<EncryptResponse> {
    return this.http.post<EncryptResponse>('/v1/kms/encrypt', {
      keyId: request.keyId,
      plaintext: request.plaintext,
      context: request.context,
    });
  }

  async decrypt(request: DecryptRequest): Promise<DecryptResponse> {
    return this.http.post<DecryptResponse>('/v1/kms/decrypt', {
      keyId: request.keyId,
      ciphertext: request.ciphertext,
      context: request.context,
    });
  }

  async reEncrypt(request: ReEncryptRequest): Promise<ReEncryptResponse> {
    return this.http.post<ReEncryptResponse>('/v1/kms/re-encrypt', {
      ciphertext: request.ciphertext,
      sourceKeyId: request.sourceKeyId,
      sourceContext: request.sourceContext,
      destinationKeyId: request.destinationKeyId,
      destinationContext: request.destinationContext,
    });
  }

  async generateDataKey(request: GenerateDataKeyRequest): Promise<GenerateDataKeyResponse> {
    return this.http.post<GenerateDataKeyResponse>('/v1/kms/generate-data-key', {
      keyId: request.keyId,
      keySpec: request.keySpec ?? 'AES_256',
      numberOfBytes: request.numberOfBytes,
      context: request.context,
    });
  }

  async generateDataKeyWithoutPlaintext(
    request: GenerateDataKeyRequest
  ): Promise<{ ciphertext: string; keyId: string }> {
    return this.http.post('/v1/kms/generate-data-key-without-plaintext', {
      keyId: request.keyId,
      keySpec: request.keySpec ?? 'AES_256',
      numberOfBytes: request.numberOfBytes,
      context: request.context,
    });
  }

  // Convenience methods for string encryption
  async encryptString(keyId: string, plaintext: string, context?: Record<string, string>): Promise<string> {
    const base64 = Buffer.from(plaintext).toString('base64');
    const response = await this.encrypt({ keyId, plaintext: base64, context: context ?? {} });
    return response.ciphertext;
  }

  async decryptString(keyId: string, ciphertext: string, context?: Record<string, string>): Promise<string> {
    const response = await this.decrypt({ keyId, ciphertext, context: context ?? {} });
    return Buffer.from(response.plaintext, 'base64').toString('utf-8');
  }

  // Convenience methods for buffer encryption
  async encryptBuffer(keyId: string, data: Buffer, context?: Record<string, string>): Promise<Buffer> {
    const response = await this.encrypt({
      keyId,
      plaintext: data.toString('base64'),
      context: context ?? {},
    });
    return Buffer.from(response.ciphertext, 'base64');
  }

  async decryptBuffer(keyId: string, ciphertext: Buffer, context?: Record<string, string>): Promise<Buffer> {
    const response = await this.decrypt({
      keyId,
      ciphertext: ciphertext.toString('base64'),
      context: context ?? {},
    });
    return Buffer.from(response.plaintext, 'base64');
  }
}
