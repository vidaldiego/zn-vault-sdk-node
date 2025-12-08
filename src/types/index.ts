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

/**
 * Login request parameters.
 *
 * The username must include the tenant prefix in the format `tenant/username`
 * (e.g., "acme/admin"). This allows multiple tenants to have users with the
 * same username. Email addresses can also be used as username.
 *
 * Alternatively, you can provide `tenant` and `username` separately, and the
 * SDK will format them automatically.
 */
export interface LoginRequest {
  /** Username in format "tenant/username" or email address */
  username: string;
  /** User password */
  password: string;
  /** Optional TOTP code if 2FA is enabled */
  totpCode?: string;
  /** Optional tenant (if provided, will be prefixed to username as "tenant/username") */
  tenant?: string;
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

/**
 * Semantic sub-types for secrets.
 * These provide more granular classification beyond the base type.
 */
export type SecretSubType =
  // Credential sub-types
  | 'password'
  | 'api_key'
  // Opaque sub-types
  | 'file'
  | 'certificate'
  | 'private_key'
  | 'keypair'
  | 'ssh_key'
  | 'token'
  | 'generic'
  // Public key sub-types
  | 'ed25519_public_key'
  | 'rsa_public_key'
  | 'ecdsa_public_key'
  // Setting sub-types
  | 'json'
  | 'yaml'
  | 'env'
  | 'properties'
  | 'toml';

/**
 * Secret metadata (without decrypted data).
 */
export interface Secret {
  id: string;
  alias: string;
  tenant: string;
  type: SecretType;
  subType?: SecretSubType | null;
  version: number;
  /** File metadata (queryable without decryption) */
  fileName?: string | null;
  fileSize?: number | null;
  fileMime?: string | null;
  fileChecksum?: string | null;
  /** Natural expiration (for certs/tokens) */
  expiresAt?: string | null;
  /** User-defined expiration */
  ttlUntil?: string | null;
  tags?: string[];
  contentType?: string | null;
  createdBy?: string | null;
  createdAt: string;
  updatedAt: string;
}

/**
 * Secret with decrypted data.
 */
export interface SecretWithData extends Secret {
  data: Record<string, unknown>;
}

/**
 * Request to create a new secret.
 */
export interface CreateSecretRequest {
  alias: string;
  type: SecretType;
  /** Semantic sub-type (auto-inferred if not provided) */
  subType?: SecretSubType;
  data: Record<string, unknown>;
  /** Original filename for file-based secrets */
  fileName?: string;
  /** Natural expiration (ISO 8601) for certs/tokens */
  expiresAt?: string;
  /** User-defined expiration (ISO 8601) */
  ttlUntil?: string;
  tags?: string[];
  /** MIME type for settings/files */
  contentType?: string;
}

/**
 * Request to update an existing secret.
 */
export interface UpdateSecretRequest {
  data: Record<string, unknown>;
  subType?: SecretSubType;
  fileName?: string;
  expiresAt?: string;
  ttlUntil?: string;
  tags?: string[];
  contentType?: string;
}

/**
 * Filter options for listing secrets.
 */
export interface SecretFilter {
  type?: SecretType;
  /** Filter by semantic sub-type */
  subType?: SecretSubType;
  /** Filter by file MIME type */
  fileMime?: string;
  /** Find secrets expiring before this date (ISO 8601) */
  expiringBefore?: string;
  tags?: string[];
  /** Filter by alias prefix (e.g., "web/*") */
  aliasPrefix?: string;
  page?: number;
  pageSize?: number;
}

/**
 * Secret version history entry.
 */
export interface SecretVersion {
  id: number;
  tenant: string;
  alias: string;
  type: string;
  subType?: SecretSubType | null;
  version: number;
  fileName?: string | null;
  fileSize?: number | null;
  fileMime?: string | null;
  expiresAt?: string | null;
  tags?: string[];
  createdAt?: string;
  createdBy?: string;
  supersededAt?: string;
  supersededBy?: string;
}

/**
 * Algorithm for keypair generation.
 */
export type KeypairAlgorithm = 'RSA' | 'Ed25519' | 'ECDSA';

/**
 * RSA key size options.
 */
export type RsaBits = 2048 | 4096;

/**
 * ECDSA curve options.
 */
export type EcdsaCurve = 'P-256' | 'P-384';

/**
 * Request to generate a keypair.
 */
export interface GenerateKeypairRequest {
  /** Algorithm for keypair generation */
  algorithm: KeypairAlgorithm;
  /** Alias for the private key (e.g., "keys/prod/api-private") */
  alias: string;
  /** Tenant ID */
  tenant: string;
  /** RSA key size (only for RSA) */
  rsaBits?: RsaBits;
  /** ECDSA curve (only for ECDSA) */
  ecdsaCurve?: EcdsaCurve;
  /** Optional comment/description */
  comment?: string;
  /** Whether to auto-publish the public key */
  publishPublicKey?: boolean;
  /** Tags for both keys */
  tags?: string[];
}

/**
 * Public key information.
 */
export interface PublicKeyInfo {
  id: string;
  alias: string;
  tenant: string;
  subType: SecretSubType;
  publicKey: string;
  fingerprint: string;
  algorithm: string;
  bits?: number;
}

/**
 * Generated keypair result.
 */
export interface GeneratedKeypair {
  privateKey: {
    id: string;
    alias: string;
  };
  publicKey: PublicKeyInfo & {
    isPublic: boolean;
    publicKeyPem: string;
    publicKeyOpenSSH: string;
  };
}

/**
 * Result of publishing a public key.
 */
export interface PublishResult {
  message: string;
  publicUrl: string;
  fingerprint: string;
  algorithm: string;
}

/**
 * List of published public keys for a tenant.
 */
export interface PublicKeyList {
  tenant: string;
  keys: PublicKeyInfo[];
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
