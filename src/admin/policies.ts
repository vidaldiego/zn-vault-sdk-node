// Path: zn-vault-sdk-node/src/admin/policies.ts

import type { HttpClient } from '../http/client.js';
import type {
  Policy,
  CreatePolicyRequest,
  UpdatePolicyRequest,
  PolicyFilter,
  PaginatedResponse,
} from '../types/index.js';

export class PoliciesClient {
  constructor(private http: HttpClient) {}

  async create(request: CreatePolicyRequest): Promise<Policy> {
    return this.http.post<Policy>('/v1/policies', {
      name: request.name,
      description: request.description,
      effect: request.effect,
      actions: request.actions,
      resources: request.resources,
      conditions: request.conditions,
      priority: request.priority,
      tenantId: request.tenantId,
    });
  }

  async get(id: string): Promise<Policy> {
    return this.http.get<Policy>(`/v1/policies/${id}`);
  }

  async update(id: string, request: UpdatePolicyRequest): Promise<Policy> {
    return this.http.patch<Policy>(`/v1/policies/${id}`, {
      name: request.name,
      description: request.description,
      effect: request.effect,
      actions: request.actions,
      resources: request.resources,
      conditions: request.conditions,
      priority: request.priority,
    });
  }

  async delete(id: string): Promise<void> {
    await this.http.delete(`/v1/policies/${id}`);
  }

  async list(filter?: PolicyFilter): Promise<PaginatedResponse<Policy>> {
    const params = new URLSearchParams();
    if (filter?.tenantId) params.set('tenantId', filter.tenantId);
    if (filter?.enabled !== undefined) params.set('enabled', filter.enabled.toString());
    if (filter?.page) params.set('page', filter.page.toString());
    if (filter?.pageSize) params.set('pageSize', filter.pageSize.toString());

    const query = params.toString();
    const path = query ? `/v1/policies?${query}` : '/v1/policies';
    return this.http.get<PaginatedResponse<Policy>>(path);
  }

  async toggle(id: string, enabled: boolean): Promise<Policy> {
    return this.http.post<Policy>(`/v1/policies/${id}/toggle`, { enabled });
  }

  async enable(id: string): Promise<Policy> {
    return this.toggle(id, true);
  }

  async disable(id: string): Promise<Policy> {
    return this.toggle(id, false);
  }

  async validate(policy: Omit<CreatePolicyRequest, 'tenantId'>): Promise<{ valid: boolean; errors?: string[] }> {
    return this.http.post('/v1/policies/validate', policy);
  }

  async getAttachments(id: string): Promise<{ users: string[]; roles: string[] }> {
    return this.http.get(`/v1/policies/${id}/attachments`);
  }

  async attachToUser(policyId: string, userId: string): Promise<void> {
    await this.http.post(`/v1/policies/${policyId}/attach/user`, { userId });
  }

  async detachFromUser(policyId: string, userId: string): Promise<void> {
    await this.http.delete(`/v1/policies/${policyId}/attach/user/${userId}`);
  }

  async attachToRole(policyId: string, roleId: string): Promise<void> {
    await this.http.post(`/v1/policies/${policyId}/attach/role`, { roleId });
  }

  async detachFromRole(policyId: string, roleId: string): Promise<void> {
    await this.http.delete(`/v1/policies/${policyId}/attach/role/${roleId}`);
  }
}
