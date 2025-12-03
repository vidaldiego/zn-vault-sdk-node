// Path: zn-vault-sdk-node/src/admin/tenants.ts

import type { HttpClient } from '../http/client.js';
import type {
  Tenant,
  CreateTenantRequest,
  UpdateTenantRequest,
  TenantFilter,
  TenantUsage,
  TenantStatus,
  PaginatedResponse,
} from '../types/index.js';

export class TenantsClient {
  constructor(private http: HttpClient) {}

  async create(request: CreateTenantRequest): Promise<Tenant> {
    return this.http.post<Tenant>('/v1/tenants', {
      id: request.id,
      name: request.name,
      max_secrets: request.maxSecrets,
      max_kms_keys: request.maxKmsKeys,
      max_storage_mb: request.maxStorageMb,
      plan_tier: request.planTier,
      contact_email: request.contactEmail,
      contact_name: request.contactName,
    });
  }

  async get(id: string): Promise<Tenant> {
    const response = await this.http.get<{ success: boolean; data: Tenant } | Tenant>(`/v1/tenants/${id}`);
    // API returns {success: true, data: {...}}
    if (response && typeof response === 'object' && 'data' in response && 'success' in response) {
      return response.data;
    }
    return response as Tenant;
  }

  async update(id: string, request: UpdateTenantRequest): Promise<Tenant> {
    return this.http.patch<Tenant>(`/v1/tenants/${id}`, {
      name: request.name,
      max_secrets: request.maxSecrets,
      max_kms_keys: request.maxKmsKeys,
      max_storage_mb: request.maxStorageMb,
      contact_email: request.contactEmail,
      contact_name: request.contactName,
    });
  }

  async delete(id: string): Promise<void> {
    await this.http.delete(`/v1/tenants/${id}`);
  }

  async list(filter?: TenantFilter): Promise<PaginatedResponse<Tenant>> {
    const params = new URLSearchParams();
    if (filter?.status) params.set('status', filter.status);
    if (filter?.includeUsage !== undefined) {
      params.set('includeUsage', filter.includeUsage.toString());
    }
    if (filter?.page) params.set('page', filter.page.toString());
    if (filter?.pageSize) params.set('pageSize', filter.pageSize.toString());

    const query = params.toString();
    const path = query ? `/v1/tenants?${query}` : '/v1/tenants';
    return this.http.get<PaginatedResponse<Tenant>>(path);
  }

  async setStatus(id: string, status: TenantStatus): Promise<Tenant> {
    return this.http.put<Tenant>(`/v1/tenants/${id}/status`, { status });
  }

  async getUsage(id: string): Promise<TenantUsage> {
    return this.http.get<TenantUsage>(`/v1/tenants/${id}/usage`);
  }

  async checkQuota(
    id: string,
    resourceType: 'secrets' | 'kms_keys' | 'users' | 'api_keys'
  ): Promise<{ resourceType: string; current: number; limit: number | null; allowed: boolean }> {
    return this.http.get(`/v1/tenants/${id}/quota/${resourceType}`);
  }

  async suspend(id: string): Promise<Tenant> {
    return this.setStatus(id, 'suspended');
  }

  async activate(id: string): Promise<Tenant> {
    return this.setStatus(id, 'active');
  }

  async archive(id: string): Promise<Tenant> {
    return this.setStatus(id, 'archived');
  }
}
