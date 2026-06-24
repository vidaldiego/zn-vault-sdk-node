// Path: zn-vault-sdk-node/src/kms/client.ts

import type { HttpClient } from '../http/client.js';
import type {
  KmsKey,
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
} from '../types/index.js';

export class KmsClient {
  constructor(private http: HttpClient) {}

  async createKey(request: CreateKeyRequest): Promise<KmsKey> {
    return this.http.post<KmsKey>('/v1/kms/keys', {
      alias: request.alias,
      description: request.description,
      usage: request.usage ?? 'ENCRYPT_DECRYPT',
      keySpec: request.keySpec ?? 'AES_256',
      origin: request.origin,
      multiRegion: request.multiRegion,
      tags: request.tags,
    });
  }

  async getKey(keyId: string): Promise<KmsKey> {
    const r = await this.http.get<{ keyMetadata: KmsKey }>(`/v1/kms/keys/${keyId}`);
    return r.keyMetadata;
  }

  async getKeyByAlias(alias: string): Promise<KmsKey> {
    const r = await this.http.get<{ keyMetadata: KmsKey }>(`/v1/kms/keys/alias/${encodeURIComponent(alias)}`);
    return r.keyMetadata;
  }

  async listKeys(filter?: KeyFilter): Promise<PaginatedResponse<KmsKey>> {
    const params = new URLSearchParams();
    if (filter?.state) params.set('state', filter.state);
    if (filter?.limit) params.set('limit', filter.limit.toString());
    if (filter?.offset) params.set('offset', filter.offset.toString());

    const query = params.toString();
    const path = query ? `/v1/kms/keys?${query}` : '/v1/kms/keys';
    return this.http.get<PaginatedResponse<KmsKey>>(path);
  }

  async updateKeyDescription(keyId: string, description: string): Promise<KmsKey> {
    return this.http.put<KmsKey>(`/v1/kms/keys/${keyId}/description`, { description });
  }

  async updateKeyAlias(keyId: string, alias: string): Promise<KmsKey> {
    return this.http.put<KmsKey>(`/v1/kms/keys/${keyId}/alias`, { alias });
  }

  async enableKey(keyId: string): Promise<KmsKey> {
    return this.http.post<KmsKey>(`/v1/kms/keys/${keyId}/enable`);
  }

  async disableKey(keyId: string): Promise<KmsKey> {
    return this.http.post<KmsKey>(`/v1/kms/keys/${keyId}/disable`);
  }

  async scheduleKeyDeletion(keyId: string, pendingWindowDays: number = 7): Promise<KmsKey> {
    return this.http.post<KmsKey>(`/v1/kms/keys/${keyId}/schedule-deletion`, {
      pendingWindowDays,
    });
  }

  async cancelKeyDeletion(keyId: string): Promise<KmsKey> {
    return this.http.post<KmsKey>(`/v1/kms/keys/${keyId}/cancel-deletion`);
  }

  async rotateKey(keyId: string): Promise<KmsKey> {
    return this.http.post<KmsKey>(`/v1/kms/keys/${keyId}/rotate`);
  }

  async setRotationStatus(
    keyId: string,
    enabled: boolean,
    periodDays?: number
  ): Promise<KmsKey> {
    return this.http.put<KmsKey>(`/v1/kms/keys/${keyId}/rotation-status`, {
      rotationEnabled: enabled,
      rotationPeriodDays: periodDays,
    });
  }

  async getRotationStatus(keyId: string): Promise<{
    rotationEnabled: boolean;
    rotationPeriodDays?: number;
    nextRotationDate?: string;
  }> {
    return this.http.get(`/v1/kms/keys/${keyId}/rotation-status`);
  }

  async getRotationHistory(
    keyId: string
  ): Promise<{ versions: { versionId: string; createdAt: string }[] }> {
    return this.http.get(`/v1/kms/keys/${keyId}/rotation-history`);
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
