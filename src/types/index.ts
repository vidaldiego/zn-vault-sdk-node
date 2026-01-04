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

/**
 * Time range condition for API key access.
 */
export interface ApiKeyTimeRangeCondition {
  /** Start time in HH:MM format */
  start: string;
  /** End time in HH:MM format */
  end: string;
  /** IANA timezone (default: UTC) */
  timezone?: string;
}

/**
 * Resource restrictions for API key access.
 */
export interface ApiKeyResourceConditions {
  /** Specific secret IDs */
  secrets?: string[];
  /** Specific certificate IDs */
  certificates?: string[];
  /** Specific KMS key IDs */
  kms_keys?: string[];
}

/**
 * Inline ABAC conditions for API keys.
 * These provide fine-grained access control without creating separate policies.
 */
export interface ApiKeyConditions {
  /** IP addresses or CIDR ranges allowed to use this key */
  ip?: string[];
  /** Time-of-day restriction */
  timeRange?: ApiKeyTimeRangeCondition;
  /** Allowed HTTP methods (GET, POST, PUT, PATCH, DELETE) */
  methods?: string[];
  /** Specific resource IDs by type */
  resources?: ApiKeyResourceConditions;
  /** Glob patterns for secret/certificate aliases (e.g., "api/prod/*") */
  aliases?: string[];
  /** Required resource tags (key-value pairs) */
  resourceTags?: Record<string, string>;
}

/**
 * Request to create an API key.
 *
 * API keys provide programmatic access to the vault. They are independent
 * (not bound to any user) and managed at the tenant level.
 */
export interface CreateApiKeyRequest {
  /** Descriptive name for the API key */
  name: string;
  /** Direct RBAC permissions. Supports wildcards: ["secret:*", "certificate:read:*"] */
  permissions: string[];
  /** Optional description of the API key purpose */
  description?: string;
  /** Days until expiration (1-3650, default: 90) */
  expiresInDays?: number;
  /** IP addresses or CIDR ranges allowed (legacy, prefer conditions.ip) */
  ipAllowlist?: string[];
  /** Inline ABAC conditions for fine-grained access control */
  conditions?: ApiKeyConditions;
  /** Target tenant ID (required for superadmin, optional for tenant users) */
  tenantId?: string;
}

/**
 * API key metadata.
 */
export interface ApiKey {
  id: string;
  name: string;
  description?: string;
  prefix?: string;
  tenantId?: string;
  createdBy?: string;
  createdAt?: string;
  expiresAt?: string;
  lastUsed?: string;
  permissions?: string[];
  ipAllowlist?: string[];
  conditions?: ApiKeyConditions;
  enabled?: boolean;
  rotationCount?: number;
  lastRotation?: string;
}

/**
 * Response from creating an API key.
 */
export interface CreateApiKeyResponse {
  /** The full API key - shown only once! Save it immediately. */
  key: string;
  /** API key metadata */
  apiKey: ApiKey;
  message?: string;
}

/**
 * Request to rotate an API key.
 */
export interface RotateApiKeyRequest {
  /** New expiration in days (optional, keeps current if not specified) */
  expiresInDays?: number;
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
  /** Tenant ID (required for superadmin, optional for tenant-scoped users) */
  tenant?: string;
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
  /** Tenant ID (required for superadmin, optional for tenant-scoped users) */
  tenantId?: string;
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

// ============================================================================
// Certificates
// ============================================================================

/**
 * Certificate format types.
 */
export type CertificateType = 'P12' | 'PEM' | 'DER';

/**
 * Certificate purpose/usage.
 */
export type CertificatePurpose = 'TLS' | 'mTLS' | 'SIGNING' | 'ENCRYPTION' | 'AUTHENTICATION';

/**
 * Certificate lifecycle status.
 */
export type CertificateStatus = 'ACTIVE' | 'EXPIRED' | 'REVOKED' | 'SUSPENDED' | 'PENDING_DELETION';

/**
 * Certificate kind/category.
 */
export type CertificateKind = 'AEAT' | 'FNMT' | 'CAMERFIRMA' | 'CUSTOM' | string;

/**
 * Certificate metadata (without encrypted data).
 */
export interface Certificate {
  id: string;
  tenantId: string;
  clientId: string;
  kind: string;
  alias: string;
  certificateType: CertificateType;
  purpose: CertificatePurpose;
  fingerprintSha256: string;
  subjectCn: string;
  issuerCn: string;
  notBefore: string;
  notAfter: string;
  clientName: string;
  organizationId?: string;
  contactEmail?: string;
  status: CertificateStatus;
  version: number;
  createdAt: string;
  createdBy: string;
  updatedAt: string;
  lastAccessedAt?: string;
  accessCount: number;
  tags: string[];
  daysUntilExpiry: number;
  isExpired: boolean;
}

/**
 * Decrypted certificate response.
 */
export interface DecryptedCertificate {
  id: string;
  certificateData: string;
  certificateType: CertificateType;
  fingerprintSha256: string;
}

/**
 * Request to store a new certificate.
 */
export interface StoreCertificateRequest {
  /** External customer identifier (e.g., NIF/CIF) */
  clientId: string;
  /** Certificate kind (AEAT, FNMT, CUSTOM, etc.) */
  kind: CertificateKind;
  /** Human-readable identifier */
  alias: string;
  /** Base64-encoded certificate data */
  certificateData: string;
  /** Certificate format */
  certificateType: CertificateType;
  /** Passphrase for P12 certificates */
  passphrase?: string;
  /** Certificate purpose */
  purpose: CertificatePurpose;
  /** Customer display name (defaults to certificate CN) */
  clientName?: string;
  /** Organization identifier */
  organizationId?: string;
  /** Contact for notifications */
  contactEmail?: string;
  /** Tags for organization */
  tags?: string[];
  /** Custom metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Request to update certificate metadata.
 */
export interface UpdateCertificateRequest {
  alias?: string;
  clientName?: string;
  contactEmail?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

/**
 * Request to rotate a certificate.
 */
export interface RotateCertificateRequest {
  /** Base64-encoded new certificate data */
  certificateData: string;
  /** Certificate format */
  certificateType: CertificateType;
  /** Passphrase for P12 certificates */
  passphrase?: string;
  /** Reason for rotation */
  reason?: string;
}

/**
 * Filter options for listing certificates.
 */
export interface CertificateFilter {
  clientId?: string;
  kind?: string;
  status?: CertificateStatus;
  expiringBefore?: string;
  tags?: string[];
  page?: number;
  pageSize?: number;
}

/**
 * Certificate statistics.
 */
export interface CertificateStats {
  total: number;
  byStatus: Record<string, number>;
  byKind: Record<string, number>;
  expiringIn30Days: number;
  expiringIn7Days: number;
}

/**
 * Certificate access log entry.
 */
export interface CertificateAccessLogEntry {
  id: number;
  certificateId: string;
  tenantId: string;
  userId?: string;
  apiKeyId?: string;
  purpose: string;
  operation: string;
  ipAddress?: string;
  userAgent?: string;
  accessedAt: string;
  success: boolean;
  errorMessage?: string;
}

/**
 * Certificate access log response.
 */
export interface CertificateAccessLog {
  entries: CertificateAccessLogEntry[];
}
