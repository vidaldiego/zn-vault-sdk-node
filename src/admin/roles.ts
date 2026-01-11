// Path: zn-vault-sdk-node/src/admin/roles.ts

import type { HttpClient } from '../http/client.js';
import type {
  Role,
  CreateRoleRequest,
  UpdateRoleRequest,
  RoleFilter,
  Permission,
  PaginatedResponse,
} from '../types/index.js';

export class RolesClient {
  constructor(private http: HttpClient) {}

  async create(request: CreateRoleRequest): Promise<Role> {
    return this.http.post<Role>('/v1/roles', {
      name: request.name,
      description: request.description,
      permissions: request.permissions,
      tenantId: request.tenantId,
    });
  }

  async get(id: string): Promise<Role> {
    return this.http.get<Role>(`/v1/roles/${id}`);
  }

  async update(id: string, request: UpdateRoleRequest): Promise<Role> {
    return this.http.patch<Role>(`/v1/roles/${id}`, {
      name: request.name,
      description: request.description,
      permissions: request.permissions,
    });
  }

  async delete(id: string): Promise<void> {
    await this.http.delete(`/v1/roles/${id}`);
  }

  async list(filter?: RoleFilter): Promise<PaginatedResponse<Role>> {
    const params = new URLSearchParams();
    if (filter?.tenantId) params.set('tenantId', filter.tenantId);
    if (filter?.includeSystem !== undefined) {
      params.set('includeSystem', filter.includeSystem.toString());
    }
    if (filter?.limit) params.set('limit', filter.limit.toString());
    if (filter?.offset) params.set('offset', filter.offset.toString());

    const query = params.toString();
    const path = query ? `/v1/roles?${query}` : '/v1/roles';
    return this.http.get<PaginatedResponse<Role>>(path);
  }

  async listPermissions(): Promise<Permission[]> {
    const response = await this.http.get<{ permissions: Permission[] }>('/v1/permissions');
    return response.permissions;
  }

  async getRolePolicies(roleId: string): Promise<{ policies: { id: string; name: string }[] }> {
    return this.http.get(`/v1/roles/${roleId}/policies`);
  }
}
