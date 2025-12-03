// Path: zn-vault-sdk-node/src/admin/users.ts

import type { HttpClient } from '../http/client.js';
import type {
  User,
  CreateUserRequest,
  UpdateUserRequest,
  UserFilter,
  PaginatedResponse,
} from '../types/index.js';

export class UsersClient {
  constructor(private http: HttpClient) {}

  async create(request: CreateUserRequest): Promise<User> {
    return this.http.post<User>('/v1/users', {
      username: request.username,
      password: request.password,
      email: request.email,
      role: request.role,
      tenantId: request.tenantId,
      roles: request.roles,
    });
  }

  async get(id: string): Promise<User> {
    return this.http.get<User>(`/v1/users/${id}`);
  }

  async update(id: string, request: UpdateUserRequest): Promise<User> {
    return this.http.put<User>(`/v1/users/${id}`, {
      email: request.email,
      role: request.role,
      tenantId: request.tenantId,
      status: request.status,
      roles: request.roles,
    });
  }

  async delete(id: string): Promise<void> {
    await this.http.delete(`/v1/users/${id}`);
  }

  async list(filter?: UserFilter): Promise<PaginatedResponse<User>> {
    const params = new URLSearchParams();
    if (filter?.tenantId) params.set('tenantId', filter.tenantId);
    if (filter?.role) params.set('role', filter.role);
    if (filter?.status) params.set('status', filter.status);
    if (filter?.page) params.set('page', filter.page.toString());
    if (filter?.pageSize) params.set('pageSize', filter.pageSize.toString());

    const query = params.toString();
    const path = query ? `/v1/users?${query}` : '/v1/users';
    return this.http.get<PaginatedResponse<User>>(path);
  }

  async resetPassword(id: string, newPassword: string): Promise<void> {
    await this.http.post(`/v1/users/${id}/reset-password`, { password: newPassword });
  }

  async getPermissions(id: string): Promise<string[]> {
    const response = await this.http.get<{ permissions: string[] }>(`/v1/users/${id}/permissions`);
    return response.permissions;
  }

  // Role assignment
  async assignRole(userId: string, roleId: string): Promise<void> {
    await this.http.post(`/v1/users/${userId}/roles`, { roleId });
  }

  async removeRole(userId: string, roleId: string): Promise<void> {
    await this.http.delete(`/v1/users/${userId}/roles/${roleId}`);
  }

  async getUserRoles(userId: string): Promise<{ id: string; name: string }[]> {
    const response = await this.http.get<{ roles: { id: string; name: string }[] }>(
      `/v1/users/${userId}/roles`
    );
    return response.roles;
  }

  // TOTP management
  async setupTotp(userId: string): Promise<{ secret: string; qrCode: string }> {
    return this.http.post(`/v1/users/${userId}/totp/setup`);
  }

  async enableTotp(userId: string, code: string): Promise<void> {
    await this.http.post(`/v1/users/${userId}/totp/enable`, { code });
  }

  async disableTotp(userId: string): Promise<void> {
    await this.http.post(`/v1/users/${userId}/totp/disable`);
  }

  async resetTotp(userId: string): Promise<{ secret: string; qrCode: string; backupCodes: string[] }> {
    return this.http.post(`/v1/users/${userId}/totp/reset`);
  }
}
