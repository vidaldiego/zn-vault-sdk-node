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
      tenantId: request.tenantId,
      rotationEnabled: request.rotationEnabled,
      rotationPeriodDays: request.rotationPeriodDays,
    });
  }

  async getKey(keyId: string): Promise<KmsKey> {
    return this.http.get<KmsKey>(`/v1/kms/keys/${keyId}`);
  }

  async getKeyByAlias(alias: string): Promise<KmsKey> {
    return this.http.get<KmsKey>(`/v1/kms/keys/alias/${alias}`);
  }

  async listKeys(filter?: KeyFilter): Promise<PaginatedResponse<KmsKey>> {
    const params = new URLSearchParams();
    if (filter?.tenantId) params.set('tenantId', filter.tenantId);
    if (filter?.state) params.set('state', filter.state);
    if (filter?.page) params.set('page', filter.page.toString());
    if (filter?.pageSize) params.set('pageSize', filter.pageSize.toString());

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
      ciphertextBlob: request.ciphertextBlob,
      context: request.context,
    });
  }

  async reEncrypt(
    keyId: string,
    ciphertextBlob: string,
    destinationKeyId: string,
    sourceContext?: Record<string, string>,
    destinationContext?: Record<string, string>
  ): Promise<EncryptResponse> {
    return this.http.post<EncryptResponse>('/v1/kms/re-encrypt', {
      keyId,
      ciphertextBlob,
      destinationKeyId,
      sourceContext,
      destinationContext,
    });
  }

  async generateDataKey(request: GenerateDataKeyRequest): Promise<GenerateDataKeyResponse> {
    return this.http.post<GenerateDataKeyResponse>('/v1/kms/generate-data-key', {
      keyId: request.keyId,
      keySpec: request.keySpec ?? 'AES_256',
      context: request.context,
    });
  }

  async generateDataKeyWithoutPlaintext(
    request: GenerateDataKeyRequest
  ): Promise<{ ciphertextBlob: string; keyId: string }> {
    return this.http.post('/v1/kms/generate-data-key-without-plaintext', {
      keyId: request.keyId,
      keySpec: request.keySpec ?? 'AES_256',
      context: request.context,
    });
  }

  // Convenience methods for string encryption
  async encryptString(keyId: string, plaintext: string, context?: Record<string, string>): Promise<string> {
    const base64 = Buffer.from(plaintext).toString('base64');
    const response = await this.encrypt({ keyId, plaintext: base64, context });
    return response.ciphertextBlob;
  }

  async decryptString(keyId: string, ciphertextBlob: string, context?: Record<string, string>): Promise<string> {
    const response = await this.decrypt({ keyId, ciphertextBlob, context });
    return Buffer.from(response.plaintext, 'base64').toString('utf-8');
  }

  // Convenience methods for buffer encryption
  async encryptBuffer(keyId: string, data: Buffer, context?: Record<string, string>): Promise<Buffer> {
    const response = await this.encrypt({
      keyId,
      plaintext: data.toString('base64'),
      context,
    });
    return Buffer.from(response.ciphertextBlob, 'base64');
  }

  async decryptBuffer(keyId: string, ciphertextBlob: Buffer, context?: Record<string, string>): Promise<Buffer> {
    const response = await this.decrypt({
      keyId,
      ciphertextBlob: ciphertextBlob.toString('base64'),
      context,
    });
    return Buffer.from(response.plaintext, 'base64');
  }
}
