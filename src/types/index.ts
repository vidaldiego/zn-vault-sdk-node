// Path: zn-vault-sdk-node/src/types/index.ts

// ============================================================================
// Configuration
// ============================================================================

export interface ZnVaultConfig {
  baseUrl: string;
  apiKey?: string;
  timeout?: number;
  retryAttempts?: number;
  retryDelay?: number;
  rejectUnauthorized?: boolean;
}

// ============================================================================
// Authentication
// ============================================================================

export interface LoginRequest {
  username: string;
  password: string;
  totpCode?: string;
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
  requires2fa?: boolean;
  user?: User;
}

export interface RefreshResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  user?: User;
}

export interface MeResponse {
  user: User;
  authMethod?: string;
}

export interface CreateApiKeyRequest {
  name: string;
  expiresIn?: string;
  permissions?: string[];
}

export interface ApiKey {
  id: string;
  name: string;
  prefix?: string;
  userId?: string;
  createdAt?: string;
  expiresAt?: string;
  lastUsed?: string;
  scope?: string;
}

export interface CreateApiKeyResponse {
  key: string;
  apiKey: ApiKey;
  message?: string;
}

export interface TwoFactorSetupResponse {
  secret: string;
  qrCode: string;
  backupCodes: string[];
}

export interface TwoFactorStatus {
  enabled: boolean;
  backupCodesRemaining?: number;
}

// ============================================================================
// Users
// ============================================================================

export type UserRole = 'superadmin' | 'admin' | 'user' | 'service';
export type UserStatus = 'active' | 'disabled' | 'locked';

export interface RoleAssignment {
  id: string;
  name: string;
  tenantId?: string;
}

export interface User {
  id: string;
  username: string;
  email?: string;
  role?: UserRole;
  tenantId?: string;
  totpEnabled: boolean;
  status?: UserStatus;
  createdAt?: string;
  updatedAt?: string;
  lastLogin?: string;
  permissions?: string[];
  roles?: RoleAssignment[];
  passwordMustChange?: boolean;
}

export interface CreateUserRequest {
  username: string;
  password: string;
  email?: string;
  role?: UserRole;
  tenantId?: string;
  roles?: string[];
}

export interface UpdateUserRequest {
  email?: string;
  role?: UserRole;
  tenantId?: string;
  status?: UserStatus;
  roles?: string[];
}

export interface UserFilter {
  tenantId?: string;
  role?: UserRole;
  status?: UserStatus;
  page?: number;
  pageSize?: number;
}

// ============================================================================
// Secrets
// ============================================================================

export type SecretType = 'opaque' | 'credential' | 'setting';

export interface Secret {
  id: string;
  alias: string;
  tenant: string;
  env?: string;
  service?: string;
  type: SecretType;
  version: number;
  tags?: string[];
  createdAt: string;
  updatedAt: string;
  expiresAt?: string;
  createdBy: string;
  checksum?: string;
}

export interface SecretWithData extends Secret {
  data: Record<string, unknown>;
}

export interface CreateSecretRequest {
  alias: string;
  tenant: string;
  env?: string;
  service?: string;
  type: SecretType;
  data: Record<string, unknown>;
  tags?: string[];
  ttlUntil?: string;
}

export interface UpdateSecretRequest {
  data: Record<string, unknown>;
  tags?: string[];
}

export interface SecretFilter {
  tenant?: string;
  env?: string;
  service?: string;
  type?: SecretType;
  tags?: string[];
  page?: number;
  pageSize?: number;
}

export interface SecretVersion {
  version: number;
  createdAt: string;
  createdBy: string;
}

// ============================================================================
// KMS
// ============================================================================

export type KeyUsage = 'ENCRYPT_DECRYPT' | 'SIGN_VERIFY';
export type KeySpec = 'AES_256' | 'RSA_2048' | 'RSA_4096' | 'ECC_P256' | 'ECC_P384';
export type KeyState = 'Enabled' | 'Disabled' | 'PendingDeletion' | 'Deleted';

export interface KmsKey {
  keyId: string;
  alias?: string;
  description?: string;
  usage: KeyUsage;
  keySpec: KeySpec;
  state: KeyState;
  tenantId?: string;
  rotationEnabled: boolean;
  rotationPeriodDays?: number;
  nextRotationDate?: string;
  createdAt: string;
  deletionDate?: string;
}

export interface CreateKeyRequest {
  alias?: string;
  description?: string;
  usage?: KeyUsage;
  keySpec?: KeySpec;
  tenantId?: string;
  rotationEnabled?: boolean;
  rotationPeriodDays?: number;
}

export interface EncryptRequest {
  keyId: string;
  plaintext: string;
  context?: Record<string, string>;
}

export interface EncryptResponse {
  ciphertextBlob: string;
  keyId: string;
  keyVersionId?: string;
}

export interface DecryptRequest {
  keyId: string;
  ciphertextBlob: string;
  context?: Record<string, string>;
}

export interface DecryptResponse {
  plaintext: string;
  keyId: string;
}

export interface GenerateDataKeyRequest {
  keyId: string;
  keySpec?: 'AES_256' | 'AES_128';
  context?: Record<string, string>;
}

export interface GenerateDataKeyResponse {
  plaintext: string;
  ciphertextBlob: string;
  keyId: string;
}

export interface KeyFilter {
  tenantId?: string;
  state?: KeyState;
  page?: number;
  pageSize?: number;
}

// ============================================================================
// Tenants
// ============================================================================

export type TenantStatus = 'active' | 'suspended' | 'archived';

export interface Tenant {
  id: string;
  name: string;
  status: TenantStatus;
  maxSecrets?: number;
  maxKmsKeys?: number;
  maxStorageMb?: number;
  planTier?: string;
  auditLogVisible?: boolean;
  auditLogRetentionDays?: number;
  contactEmail?: string;
  contactName?: string;
  metadata?: string;
  createdAt?: string;
  createdBy?: string;
  updatedAt?: string;
  lastActivity?: string;
}

export interface CreateTenantRequest {
  id: string;
  name: string;
  maxSecrets?: number;
  maxKmsKeys?: number;
  maxStorageMb?: number;
  planTier?: string;
  contactEmail?: string;
  contactName?: string;
}

export interface UpdateTenantRequest {
  name?: string;
  maxSecrets?: number;
  maxKmsKeys?: number;
  maxStorageMb?: number;
  contactEmail?: string;
  contactName?: string;
}

export interface TenantUsage {
  secretsCount: number;
  kmsKeysCount: number;
  usersCount: number;
  apiKeysCount: number;
  storageBytes: number;
}

export interface TenantFilter {
  status?: TenantStatus;
  includeUsage?: boolean;
  page?: number;
  pageSize?: number;
}

// ============================================================================
// Roles
// ============================================================================

export interface Role {
  id: string;
  name: string;
  description?: string;
  permissions: string[];
  isSystem: boolean;
  tenantId?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface CreateRoleRequest {
  name: string;
  description?: string;
  permissions: string[];
  tenantId?: string;
}

export interface UpdateRoleRequest {
  name?: string;
  description?: string;
  permissions?: string[];
}

export interface RoleFilter {
  tenantId?: string;
  includeSystem?: boolean;
  page?: number;
  pageSize?: number;
}

export interface Permission {
  id: string;
  name: string;
  description?: string;
  category?: string;
}

// ============================================================================
// Policies (ABAC)
// ============================================================================

export interface Policy {
  id: string;
  name: string;
  description?: string;
  effect: 'allow' | 'deny';
  actions: string[];
  resources: string[];
  conditions?: Record<string, unknown>;
  priority: number;
  enabled: boolean;
  tenantId?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface CreatePolicyRequest {
  name: string;
  description?: string;
  effect: 'allow' | 'deny';
  actions: string[];
  resources: string[];
  conditions?: Record<string, unknown>;
  priority?: number;
  tenantId?: string;
}

export interface UpdatePolicyRequest {
  name?: string;
  description?: string;
  effect?: 'allow' | 'deny';
  actions?: string[];
  resources?: string[];
  conditions?: Record<string, unknown>;
  priority?: number;
}

export interface PolicyFilter {
  tenantId?: string;
  enabled?: boolean;
  page?: number;
  pageSize?: number;
}

// ============================================================================
// Audit
// ============================================================================

export interface AuditEntry {
  id: number;
  timestamp: string;
  action: string;
  userId?: string;
  username?: string;
  tenantId?: string;
  resourceType?: string;
  resourceId?: string;
  ipAddress?: string;
  userAgent?: string;
  requestId?: string;
  success: boolean;
  errorMessage?: string;
  details?: Record<string, unknown>;
}

export interface AuditFilter {
  startDate?: string;
  endDate?: string;
  action?: string;
  userId?: string;
  tenantId?: string;
  resourceType?: string;
  success?: boolean;
  page?: number;
  pageSize?: number;
}

export interface AuditStats {
  totalEntries: number;
  entriesByAction: Record<string, number>;
  entriesByUser: Record<string, number>;
  successRate: number;
}

export interface AuditVerifyResult {
  valid: boolean;
  entriesChecked: number;
  brokenAt?: number;
}

// ============================================================================
// Health
// ============================================================================

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  uptime: number;
  checks?: Record<string, HealthCheck>;
}

export interface HealthCheck {
  status: 'pass' | 'warn' | 'fail';
  message?: string;
  time?: number;
}

// ============================================================================
// Pagination
// ============================================================================

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

// ============================================================================
// Errors
// ============================================================================

export interface ZnVaultErrorResponse {
  error: string;
  message: string;
  statusCode: number;
  details?: Record<string, unknown>;
}
