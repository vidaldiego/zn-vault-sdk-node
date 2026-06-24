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
}

/**
 * API key metadata.
 * Fields use snake_case to match the server's toPublic() output exactly.
 */
export interface ApiKey {
  id: string;
  name: string;
  description?: string | null;
  prefix?: string;
  tenant_id?: string;
  created_by?: string | null;
  /** Username of the user who created the key (present on list and get-by-id responses). */
  created_by_username?: string | null;
  created_at?: string;
  expires_at?: string;
  last_used?: string | null;
  permissions?: string[];
  ip_allowlist?: string[];
  conditions?: ApiKeyConditions;
  enabled?: boolean;
  rotation_count?: number;
  last_rotation?: string | null;
  // Managed key fields
  is_managed?: boolean;
  rotation_mode?: string | null;
  rotation_interval_seconds?: number | null;
  grace_period_seconds?: number;
  /** When the key was first used (for on-use rotation mode). */
  first_used_at?: string | null;
  /** When the grace period expires after a rotation. */
  grace_expires_at?: string | null;
  next_rotation_at?: string | null;
  /** URL that receives rotation event webhook notifications. */
  rotation_webhook_url?: string | null;
  rotation_paused?: boolean | null;
  // Late pickup fields
  late_pickup_enabled?: boolean | null;
  late_pickup_window_seconds?: number | null;
  late_pickup_max_attempts?: number | null;
  late_pickup_require_same_ip?: boolean | null;
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
 * The server only accepts an optional new name; expiration is not configurable at rotation time.
 */
export interface RotateApiKeyRequest {
  /** Optional new name for the rotated key */
  name?: string;
}

// ============================================================================
// Managed API Keys
// ============================================================================

/**
 * Rotation mode for managed API keys.
 *
 * - `scheduled`: Key rotates at fixed intervals (e.g., every 24 hours)
 * - `on-use`: Key rotates after being used (TTL resets on each use)
 * - `on-bind`: Key rotates each time bind is called
 */
export type RotationMode = 'scheduled' | 'on-use' | 'on-bind';

/**
 * Managed API key metadata.
 * Managed keys support automatic rotation with configurable modes.
 */
export interface ManagedApiKey {
  id: string;
  name: string;
  tenantId: string;
  permissions: string[];
  description?: string;
  rotationMode: RotationMode;
  /** Duration between rotations (e.g., "24h", "7d") - required for scheduled mode */
  rotationInterval?: string;
  /** Grace period during which both old and new keys are valid (e.g., "5m", "1h") */
  gracePeriod: string;
  /** When the key was last rotated */
  lastRotatedAt?: string;
  /** When the next rotation will occur (for scheduled mode) */
  nextRotationAt?: string;
  enabled: boolean;
  createdAt: string;
  createdBy?: string;
  updatedAt?: string;
}

/**
 * Request to create a managed API key.
 */
export interface CreateManagedApiKeyRequest {
  /** Unique name for the managed key */
  name: string;
  /** Permissions for the key */
  permissions: string[];
  /** Rotation mode */
  rotationMode: RotationMode;
  /** Rotation interval (required for scheduled mode, e.g., "24h", "7d") */
  rotationInterval?: string;
  /** Grace period for smooth key transitions (e.g., "5m") */
  gracePeriod?: string;
  /** Send notification before rotation (e.g., "1h") */
  notifyBefore?: string;
  /** URL to POST rotation event notifications */
  webhookUrl?: string;
  /** Optional description */
  description?: string;
  /** Expiration in days (optional) */
  expiresInDays?: number;
}

/**
 * Response from creating a managed API key.
 * The server returns toPublic() output (snake_case ApiKey shape), not the
 * camelCase ManagedApiKey shape.
 */
export interface CreateManagedApiKeyResponse {
  /** The managed key metadata (snake_case ApiKey from toPublic()) */
  apiKey: ApiKey;
  message?: string;
}

/**
 * Response from binding to a managed API key.
 * This is what agents use to get the current key value.
 */
export interface ManagedKeyBindResponse {
  /** The API key ID */
  id: string;
  /** The current API key value - use this for authentication */
  key: string;
  /** Key prefix for identification */
  prefix: string;
  /** Managed key name */
  name: string;
  /** When this key expires */
  expiresAt: string;
  /** Grace period duration */
  gracePeriod: string;
  /** Rotation mode */
  rotationMode: RotationMode;
  /** Permissions on the key */
  permissions: string[];
  /** When the next rotation will occur (helps SDK know when to re-bind) */
  nextRotationAt?: string;
  /** When the grace period expires (after this, old key stops working) */
  graceExpiresAt?: string;
}

/**
 * Response from rotating a managed API key.
 */
export interface ManagedKeyRotateResponse {
  /** The new API key value */
  key: string;
  /** Managed key metadata */
  apiKey: ManagedApiKey;
  /** When the old key expires (grace period end) */
  graceExpiresAt: string;
  message?: string;
}

/**
 * Request to update managed key configuration.
 */
export interface UpdateManagedApiKeyConfigRequest {
  /** New rotation interval */
  rotationInterval?: string;
  /** New grace period */
  gracePeriod?: string;
  /** Enable/disable the key */
  enabled?: boolean;
}

/**
 * Configuration for managed key auto-rotation in the SDK.
 */
export interface ManagedKeyConfig {
  /** The managed key name to bind to */
  name: string;
  /** How early before expiration to refresh (default: 30 seconds) */
  refreshBeforeExpiryMs?: number;
  /** Callback when key is rotated */
  onKeyRotated?: (newKey: string, oldKey: string) => void;
  /** Callback on rotation error */
  onRotationError?: (error: Error) => void;
}

// ============================================================================
// Registration Tokens (Agent Bootstrap)
// ============================================================================

/**
 * Registration token status.
 */
export type RegistrationTokenStatus = 'active' | 'used' | 'expired' | 'revoked';

/**
 * Registration token metadata.
 * Tokens are used for one-time agent bootstrapping.
 */
export interface RegistrationToken {
  id: string;
  prefix: string;
  managedKeyName: string;
  tenantId: string;
  createdBy: string;
  createdByUsername?: string;
  createdAt: string;
  expiresAt: string;
  usedAt?: string | null;
  usedByIp?: string | null;
  revokedAt?: string | null;
  description?: string | null;
  status: RegistrationTokenStatus;
}

/**
 * Request to create a registration token.
 */
export interface CreateRegistrationTokenRequest {
  /** Token expiration (e.g., "1h", "24h"). Min 1m, max 24h. Default: 1h */
  expiresIn?: string;
  /** Optional description for audit trail */
  description?: string;
}

/**
 * Response from creating a registration token.
 */
export interface CreateRegistrationTokenResponse {
  /** The full token value - shown only once! */
  token: string;
  /** Token prefix for identification (e.g., "zrt_abc1") */
  prefix: string;
  /** Token ID for management operations */
  id: string;
  /** The managed key this token is for */
  managedKeyName: string;
  /** Tenant ID */
  tenantId: string;
  /** When the token expires */
  expiresAt: string;
  /** Optional description */
  description?: string | null;
}

/**
 * Response from listing registration tokens.
 */
export interface ListRegistrationTokensResponse {
  tokens: RegistrationToken[];
}

/**
 * Response from the bootstrap endpoint.
 */
export interface BootstrapResponse {
  /** The API key value */
  key: string;
  /** Managed key name */
  name: string;
  /** Permissions on the key */
  permissions: string[];
  /** When the key expires */
  expiresAt: string;
  /** Notice about token consumption */
  _notice: string;
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
  /** Server emits only snake_case for this field. */
  totp_enabled?: boolean;
  /** @deprecated Use `totp_enabled` instead — the server only emits the snake_case variant. */
  totpEnabled?: boolean;
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
  roles?: string[];
}

export interface UpdateUserRequest {
  email?: string;
  role?: UserRole;
  status?: UserStatus;
  roles?: string[];
}

export interface UserFilter {
  role?: UserRole;
  status?: UserStatus;
  limit?: number;
  offset?: number;
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
  createdAt?: string;
  updatedAt?: string;
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
 *
 * Note: the server's /v1/secrets querystring does not accept a `tags` param —
 * any `tags` value in this filter is intentionally ignored by the SDK.
 */
export interface SecretFilter {
  type?: SecretType;
  /** Filter by semantic sub-type */
  subType?: SecretSubType;
  /** Filter by file MIME type */
  fileMime?: string;
  /** Find secrets expiring before this date (ISO 8601) */
  expiringBefore?: string;
  /** @deprecated The server does not support tag-based list filtering. This field is ignored. */
  tags?: string[];
  /** Filter by alias prefix (e.g., "web/*") */
  aliasPrefix?: string;
  limit?: number;
  offset?: number;
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
 * Secret history entry returned by GET /v1/secrets/:id/history.
 * Each entry represents a previous version that was superseded by an update.
 */
export interface SecretHistoryEntry {
  /** Numeric auto-increment primary key from secrets_history table. */
  id: number;
  secretId: string;
  tenant: string;
  alias: string;
  type: string;
  version: number;
  ttlUntil?: string | null;
  tags: string[];
  contentType?: string | null;
  createdBy: string;
  createdByUsername?: string | null;
  createdAt: string;
  supersededAt?: string | null;
  supersededBy?: string | null;
  supersededByUsername?: string | null;
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
export type KeySpec = 'AES_256' | 'AES_128' | 'RSA_2048' | 'RSA_4096' | 'ECC_NIST_P256' | 'ECC_NIST_P384';
export type KeyState = 'ENABLED' | 'DISABLED' | 'PENDING_DELETION';

export interface KmsKey {
  keyId: string;
  alias?: string;
  arn?: string;
  description?: string;
  keyState: KeyState;
  keyUsage: KeyUsage;
  keySpec: KeySpec;
  createdDate: string;
  deletionDate?: string;
  multiRegion?: boolean;
  origin?: string;
  tenantId?: string;
}

export interface CreateKeyRequest {
  alias?: string;
  description?: string;
  usage?: KeyUsage;
  keySpec?: KeySpec;
  origin?: string;
  multiRegion?: boolean;
  tags?: Array<{ key: string; value: string }>;
}

export interface EncryptRequest {
  keyId: string;
  plaintext: string;
  context: Record<string, string>;
}

export interface EncryptResponse {
  ciphertext: string;
  keyId: string;
  encryptionContext?: Record<string, string>;
}

export interface DecryptRequest {
  keyId?: string;
  ciphertext: string;
  context: Record<string, string>;
}

export interface DecryptResponse {
  plaintext: string;
  keyId: string;
  encryptionContext?: Record<string, string>;
}

export interface GenerateDataKeyRequest {
  keyId: string;
  keySpec?: 'AES_256' | 'AES_128';
  numberOfBytes?: number;
  context: Record<string, string>;
}

export interface GenerateDataKeyResponse {
  plaintext: string;
  ciphertext: string;
  keyId: string;
}

export interface ReEncryptRequest {
  ciphertext: string;
  sourceKeyId?: string;
  sourceContext: Record<string, string>;
  destinationKeyId: string;
  destinationContext: Record<string, string>;
}

export interface ReEncryptResponse {
  sourceKeyId: string;
  destinationKeyId: string;
  ciphertext: string;
}

export interface KeyFilter {
  state?: KeyState;
  limit?: number;
  offset?: number;
}

/**
 * KMS key rotation status.
 */
export interface RotationStatus {
  keyId: string;
  rotationEnabled: boolean;
  intervalDays?: number;
  lastRotationDate?: string;
  nextRotationDate?: string;
  rotationCount: number;
}

/**
 * A single entry in a KMS key's rotation history.
 */
export interface RotationHistoryEntry {
  id: string;
  keyId: string;
  oldVersion: number;
  newVersion: number;
  rotationType: string;
  rotationDate: string;
  initiatedBy: string;
  success: boolean;
  errorMessage?: string;
}

/**
 * Response from scheduling a KMS key for deletion.
 */
export interface ScheduleDeletionResponse {
  keyId: string;
  keyState: KeyState;
  deletionDate: string;
}

// ============================================================================
// Tenants
// ============================================================================

export type TenantStatus = 'active' | 'suspended' | 'archived';

export interface Tenant {
  id: string;
  name: string;
  status: TenantStatus;
  /** Server emits quota fields in snake_case. */
  max_secrets?: number;
  max_kms_keys?: number;
  max_storage_mb?: number;
  /** @deprecated Use `max_secrets` — the server only emits the snake_case variant. */
  maxSecrets?: number;
  /** @deprecated Use `max_kms_keys` — the server only emits the snake_case variant. */
  maxKmsKeys?: number;
  /** @deprecated Use `max_storage_mb` — the server only emits the snake_case variant. */
  maxStorageMb?: number;
  planTier?: string;
  auditLogVisible?: boolean;
  auditLogRetentionDays?: number;
  contactEmail?: string;
  contactName?: string;
  metadata?: string;
  createdAt?: string;
  created_at?: string;
  createdBy?: string;
  updatedAt?: string;
  updated_at?: string;
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
  limit?: number;
  offset?: number;
}

// ============================================================================
// Roles
// ============================================================================

export interface Role {
  id: string;
  name: string;
  description?: string;
  permissions: string[];
  /** Server emits only snake_case for these fields. */
  is_system?: boolean;
  user_count?: number;
  tenant_id?: string;
  created_at?: string;
  updated_at?: string;
  /** @deprecated Use `is_system` — the server only emits the snake_case variant. */
  isSystem?: boolean;
  /** @deprecated Use `tenant_id` — the server only emits the snake_case variant. */
  tenantId?: string;
  /** @deprecated Use `created_at` — the server only emits the snake_case variant. */
  createdAt?: string;
  /** @deprecated Use `updated_at` — the server only emits the snake_case variant. */
  updatedAt?: string;
}

export interface CreateRoleRequest {
  name: string;
  description?: string;
  permissions: string[];
}

export interface UpdateRoleRequest {
  name?: string;
  description?: string;
  permissions?: string[];
}

export interface RoleFilter {
  includeSystem?: boolean;
  limit?: number;
  offset?: number;
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
  enabled?: boolean;
  limit?: number;
  offset?: number;
}

// ============================================================================
// Audit
// ============================================================================

export interface AuditEntry {
  id: string;
  timestamp: string;
  action: string;
  resource: string;
  actor: string;
  clientCert: string;
  result: 'success' | 'failure';
  ip: string;
  metadata?: Record<string, unknown> | null;
}

/**
 * Raw audit log row as emitted by the export endpoint (`GET /v1/audit/export`
 * with `format=json`). This is the untransformed DB row shape — snake_case
 * field names, `ts` instead of `timestamp`, `client_cn` instead of
 * `clientCert`/`actor` — and is distinct from the camelCase-transformed
 * `AuditEntry` shape returned by the list route.
 */
export interface RawAuditEntry {
  /** Optional numeric primary key (may be absent on some rows). */
  id?: number;
  /** ISO 8601 timestamp of the audit event. */
  ts: string;
  /** Client common name (user/API-key identifier), or null for system events. */
  client_cn: string | null;
  /** Action that was performed (e.g. "secret.read"). */
  action: string;
  /** Resource path the action targeted. */
  resource: string;
  /** Outcome of the action — free-form string (e.g. "success", "failure"). */
  result: string;
  /** Client IP address. */
  ip: string;
  /** Optional structured metadata attached to the event. */
  metadata?: Record<string, unknown>;
}

export interface AuditFilter {
  /** Filter by client CN (maps to query param client_cn) */
  clientCn?: string;
  action?: string;
  resource?: string;
  /** ISO 8601 start date (maps to query param start_date) */
  startDate?: string;
  /** ISO 8601 end date (maps to query param end_date) */
  endDate?: string;
  limit?: number;
  offset?: number;
  /** Export format: json (default) or csv — used by exportLogs only */
  format?: 'json' | 'csv';
}

export interface AuditStats {
  total: number;
  successCount: number;
  failureCount: number;
  uniqueUsers: number;
  successRate: number;
  topActors: Array<{ actor: string; count: number }>;
  topActions: Array<{ action: string; count: number }>;
  recentFailures: Array<{ timestamp: string; action: string; actor: string; resource: string }>;
}

export interface AuditVerifyResult {
  valid: boolean;
  errors: string[];
  checkedEntries: number;
  lastVerified: string;
}

export interface AuditListResponse {
  items: AuditEntry[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
    hasMore: boolean;
  };
  stats: {
    successCount: number;
    failureCount: number;
    uniqueUsers: number;
  };
}

// ============================================================================
// Pagination
// ============================================================================

export interface PaginatedResponse<T> {
  items: T[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
    hasMore: boolean;
  };
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
// The named kinds are retained as documentation/IDE hints; `| string` keeps the
// type open to custom kinds.
// eslint-disable-next-line @typescript-eslint/no-redundant-type-constituents
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
  limit?: number;
  offset?: number;
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

// ============================================================================
// SSH Certificate Authority
// ============================================================================

/**
 * SSH CA key algorithm.
 */
export type SshCaKeyType = 'ed25519' | 'rsa-4096';

/**
 * Request to sign an SSH user public key into an OpenSSH certificate.
 *
 * `principals` is an admin override: supplying it requires `SSH_CA_ADMIN`
 * permission (or tenant admin-crypto access). For normal users it is omitted
 * and the server resolves principals from SSO group memberships.
 */
export interface SignSshCertificateRequest {
  /** The SSH user public key to sign, in OpenSSH format (e.g. "ssh-ed25519 AAAA..."). */
  publicKey: string;
  /** Requested certificate validity in seconds (clamped to the CA's max TTL). */
  ttlSeconds?: number;
  /** Explicit principals to embed (admin override; requires SSH_CA_ADMIN / admin-crypto). */
  principals?: string[];
}

/**
 * Result of signing an SSH user public key.
 *
 * `certificate` is a raw OpenSSH certificate string
 * (e.g. "ssh-ed25519-cert-v01@openssh.com AAAA..."), suitable for passing
 * directly to the `ssh2` library's `ConnectConfig.certificate` field.
 */
export interface SignSshCertificateResponse {
  /** Raw OpenSSH certificate string (ssh2-ready). */
  certificate: string;
  /** Certificate serial number (numeric, returned as a string). */
  serial: string;
  /** Principals granted by the certificate. */
  principals: string[];
  /** Validity start (ISO 8601). */
  validAfter: string;
  /** Validity end (ISO 8601). */
  validBefore: string;
  /** SHA256 fingerprint of the signed public key. */
  fingerprint: string;
}

/**
 * Public SSH CA public key (from the unauthenticated discovery endpoint).
 */
export interface SshCaPublicKey {
  /** CA public key in OpenSSH format. */
  publicKey: string;
  /** SHA256 fingerprint of the CA public key. */
  fingerprint: string;
  /** CA key algorithm. */
  keyType: SshCaKeyType;
}

/**
 * SSH CA status/configuration for the authenticated tenant (`GET /v1/ssh/ca`).
 */
export interface SshCaInfo {
  id: string;
  /** Whether the CA has been initialized for this tenant. */
  initialized: boolean;
  /** CA public key in OpenSSH format (null until initialized). */
  publicKey: string | null;
  /** SHA256 fingerprint of the CA public key (null until initialized). */
  fingerprint: string | null;
  /** CA key algorithm (null until initialized). */
  keyType: SshCaKeyType | null;
  /** Default certificate TTL in seconds (null until initialized). */
  defaultTtlSeconds: number | null;
  /** Maximum certificate TTL in seconds (null until initialized). */
  maxTtlSeconds: number | null;
  /** OpenSSH extensions permitted on issued certificates. */
  allowedExtensions: string[];
}

/**
 * Request to initialize the tenant SSH CA (`POST /v1/ssh/ca`).
 */
export interface InitSshCaRequest {
  /** CA key algorithm (default: ed25519). */
  keyType?: SshCaKeyType;
  /** Default certificate TTL in seconds (default: 28800 = 8h). */
  defaultTtlSeconds?: number;
  /** Maximum certificate TTL in seconds (default: 86400 = 24h). */
  maxTtlSeconds?: number;
  /** OpenSSH extensions permitted on issued certificates. */
  allowedExtensions?: string[];
}

/**
 * Newly initialized SSH CA (`POST /v1/ssh/ca` result).
 */
export interface SshCa {
  id: string;
  publicKey: string;
  fingerprint: string;
  keyType: SshCaKeyType;
  defaultTtlSeconds: number;
  maxTtlSeconds: number;
  allowedExtensions: string[];
  createdAt: string;
}

/**
 * Mapping from an SSO group to a set of SSH principals.
 */
export interface SshPrincipalMapping {
  id: string;
  /** SSO group ID. */
  groupId: string;
  /** SSO group name (present on list responses). */
  groupName?: string;
  /** SSO group display name (present on list responses). */
  groupDisplayName?: string | null;
  /** SSH principals granted to members of the group. */
  principals: string[];
  createdAt: string;
  /** User ID that created the mapping. */
  createdBy?: string | null;
}

/**
 * Request to create a principal mapping.
 */
export interface CreateSshPrincipalMappingRequest {
  /** SSO group ID. */
  groupId: string;
  /** SSH principals to grant (at least one). */
  principals: string[];
}

/**
 * Request to update a principal mapping's principals.
 */
export interface UpdateSshPrincipalMappingRequest {
  /** Replacement SSH principals (at least one). */
  principals: string[];
}

/**
 * A logical group of servers, used to author authorized-principals rules.
 */
export interface SshServerGroup {
  id: string;
  name: string;
  description: string | null;
  createdAt: string;
  /** User ID that created the group. */
  createdBy?: string | null;
}

/**
 * An access rule mapping a Linux user to the principals allowed to log in as it.
 */
export interface SshServerGroupAccessRule {
  /** Target Linux account (e.g. "root", "ubuntu"). */
  linuxUser: string;
  /** Principals permitted to authenticate as that Linux user. */
  allowedPrincipals: string[];
}

/**
 * Server group with its access rules (`GET /v1/ssh/server-groups/:id`).
 */
export interface SshServerGroupDetail extends SshServerGroup {
  accessRules: SshServerGroupAccessRule[];
}

/**
 * Request to create a server group.
 */
export interface CreateSshServerGroupRequest {
  name: string;
  description?: string | null;
}

/**
 * An issued SSH certificate record (list-row shape).
 */
export interface SshCertificate {
  id: string;
  /** Certificate serial number (numeric, returned as a string). */
  serial: string;
  userId: string | null;
  /** Username resolved from the user ID (present on list rows). */
  username?: string | null;
  /** SHA256 fingerprint of the signed public key. */
  fingerprint: string;
  principals: string[];
  /** Validity start (ISO 8601). */
  validAfter: string;
  /** Validity end (ISO 8601). */
  validBefore: string;
  revoked: boolean;
  revokedAt: string | null;
  revokedBy: string | null;
  revocationReason: string | null;
  createdAt: string;
}

/**
 * Full issued-certificate record (`GET /v1/ssh/certificates/:id`).
 *
 * Adds the embedded OpenSSH `extensions` and the requesting client IP, which
 * are not included in list rows.
 */
export interface SshCertificateDetail extends Omit<SshCertificate, 'username'> {
  /** OpenSSH certificate extensions (e.g. ["permit-pty", "permit-port-forwarding"]). */
  extensions: string[];
  /** Client IP the signing request originated from. */
  requestIp: string | null;
}

/**
 * Filter options for listing issued SSH certificates.
 */
export interface SshCertificateFilter {
  /** Only non-revoked, non-expired certificates. */
  activeOnly?: boolean;
  /** Filter by revocation state (true = revoked, false = not revoked). */
  revoked?: boolean;
  /** Filter by the requesting user ID. */
  userId?: string;
  limit?: number;
  offset?: number;
}
