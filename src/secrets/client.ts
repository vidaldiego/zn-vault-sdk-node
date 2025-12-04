// Path: zn-vault-sdk-node/src/secrets/client.ts

import type { HttpClient } from '../http/client.js';
import type {
  Secret,
  SecretWithData,
  CreateSecretRequest,
  UpdateSecretRequest,
  SecretFilter,
  SecretVersion,
  PaginatedResponse,
} from '../types/index.js';

export class SecretsClient {
  constructor(private http: HttpClient) {}

  async create(request: CreateSecretRequest): Promise<Secret> {
    return this.http.post<Secret>('/v1/secrets', {
      alias: request.alias,
      type: request.type,
      data: request.data,
      tags: request.tags,
      ttl_until: request.ttlUntil,
    });
  }

  async get(id: string): Promise<Secret> {
    return this.http.get<Secret>(`/v1/secrets/${id}/meta`);
  }

  async getByAlias(alias: string): Promise<Secret> {
    const encodedAlias = encodeURIComponent(alias);
    return this.http.get<Secret>(`/v1/secrets/alias/${encodedAlias}`);
  }

  async decrypt(id: string): Promise<SecretWithData> {
    return this.http.post<SecretWithData>(`/v1/secrets/${id}/decrypt`);
  }

  async update(id: string, request: UpdateSecretRequest): Promise<Secret> {
    return this.http.put<Secret>(`/v1/secrets/${id}`, {
      data: request.data,
      tags: request.tags,
    });
  }

  async updateMetadata(
    id: string,
    metadata: { tags?: string[]; ttlUntil?: string }
  ): Promise<Secret> {
    return this.http.patch<Secret>(`/v1/secrets/${id}/meta/data`, {
      tags: metadata.tags,
      ttl_until: metadata.ttlUntil,
    });
  }

  async rotate(id: string, newData: Record<string, unknown>): Promise<Secret> {
    return this.http.post<Secret>(`/v1/secrets/${id}/rotate`, { data: newData });
  }

  async delete(id: string): Promise<void> {
    await this.http.delete(`/v1/secrets/${id}`);
  }

  async list(filter?: SecretFilter): Promise<PaginatedResponse<Secret>> {
    const params = new URLSearchParams();
    if (filter?.type) params.set('type', filter.type);
    if (filter?.tags) params.set('tags', filter.tags.join(','));
    if (filter?.page) params.set('page', filter.page.toString());
    if (filter?.pageSize) params.set('pageSize', filter.pageSize.toString());

    const query = params.toString();
    const path = query ? `/v1/secrets?${query}` : '/v1/secrets';
    return this.http.get<PaginatedResponse<Secret>>(path);
  }

  async getHistory(id: string): Promise<SecretVersion[]> {
    const response = await this.http.get<{ history: SecretVersion[] }>(
      `/v1/secrets/${id}/history`
    );
    return response.history;
  }

  async decryptVersion(id: string, version: number): Promise<SecretWithData> {
    return this.http.post<SecretWithData>(`/v1/secrets/${id}/history/${version}/decrypt`);
  }

  // File upload helper
  async uploadFile(
    alias: string,
    filename: string,
    content: Buffer | string,
    options?: {
      contentType?: string;
      tags?: string[];
    }
  ): Promise<Secret> {
    const base64Content = Buffer.isBuffer(content)
      ? content.toString('base64')
      : Buffer.from(content).toString('base64');

    return this.create({
      alias,
      type: 'opaque',
      data: {
        filename,
        content: base64Content,
        contentType: options?.contentType,
      },
      tags: options?.tags,
    });
  }

  // Download file helper
  async downloadFile(id: string): Promise<{ filename: string; content: Buffer; contentType?: string }> {
    const secret = await this.decrypt(id);
    const data = secret.data as { filename: string; content: string; contentType?: string };

    return {
      filename: data.filename,
      content: Buffer.from(data.content, 'base64'),
      contentType: data.contentType,
    };
  }
}
