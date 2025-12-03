// Path: zn-vault-sdk-node/src/auth/client.ts

import type { HttpClient } from '../http/client.js';
import type {
  LoginRequest,
  LoginResponse,
  RefreshResponse,
  MeResponse,
  User,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  ApiKey,
  TwoFactorSetupResponse,
  TwoFactorStatus,
} from '../types/index.js';

export class AuthClient {
  constructor(private http: HttpClient) {}

  async login(request: LoginRequest): Promise<LoginResponse> {
    const response = await this.http.post<LoginResponse>('/auth/login', {
      username: request.username,
      password: request.password,
      totp_code: request.totpCode,
    });

    if (response.accessToken) {
      this.http.setTokens(response.accessToken, response.refreshToken);
    }

    return response;
  }

  async refresh(refreshToken?: string): Promise<RefreshResponse> {
    const token = refreshToken ?? this.http.getRefreshToken();
    if (!token) {
      throw new Error('No refresh token available');
    }

    const response = await this.http.post<RefreshResponse>('/auth/refresh', {
      refreshToken: token,
    });

    if (response.accessToken) {
      this.http.setTokens(response.accessToken, response.refreshToken);
    }

    return response;
  }

  async me(): Promise<User> {
    const response = await this.http.get<MeResponse>('/auth/me');
    return response.user;
  }

  async updateProfile(email?: string): Promise<User> {
    const response = await this.http.put<MeResponse>('/auth/me', { email });
    return response.user;
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.http.post('/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    });
  }

  async forceChangePassword(
    username: string,
    currentPassword: string,
    newPassword: string
  ): Promise<LoginResponse> {
    return this.http.post<LoginResponse>('/auth/force-change-password', {
      username,
      current_password: currentPassword,
      new_password: newPassword,
    });
  }

  logout(): void {
    this.http.clearTokens();
  }

  // API Keys
  async createApiKey(request: CreateApiKeyRequest): Promise<CreateApiKeyResponse> {
    return this.http.post<CreateApiKeyResponse>('/auth/api-keys', {
      name: request.name,
      expires_in: request.expiresIn,
      permissions: request.permissions,
    });
  }

  async listApiKeys(): Promise<{ keys: ApiKey[]; expiringSoon: ApiKey[] }> {
    return this.http.get('/auth/api-keys');
  }

  async deleteApiKey(id: string): Promise<void> {
    await this.http.delete(`/auth/api-keys/${id}`);
  }

  async rotateApiKey(id: string): Promise<CreateApiKeyResponse> {
    return this.http.post<CreateApiKeyResponse>(`/auth/api-keys/${id}/rotate`);
  }

  async getCurrentApiKey(): Promise<ApiKey> {
    return this.http.get<ApiKey>('/auth/api-keys/self');
  }

  async rotateCurrentApiKey(): Promise<CreateApiKeyResponse> {
    return this.http.post<CreateApiKeyResponse>('/auth/api-keys/self/rotate');
  }

  // 2FA
  async enable2fa(): Promise<TwoFactorSetupResponse> {
    return this.http.post<TwoFactorSetupResponse>('/auth/2fa/enable');
  }

  async verify2fa(code: string): Promise<void> {
    await this.http.post('/auth/2fa/verify', { code });
  }

  async disable2fa(password: string, totpCode?: string): Promise<void> {
    await this.http.post('/auth/2fa/disable', {
      password,
      totp_code: totpCode,
    });
  }

  async get2faStatus(): Promise<TwoFactorStatus> {
    return this.http.get<TwoFactorStatus>('/auth/2fa/status');
  }
}
