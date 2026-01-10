# @zincapp/znvault-sdk

Official Node.js/TypeScript SDK for ZnVault secrets management system.

## Installation

```bash
npm install @zincapp/znvault-sdk
```

## Quick Start

```typescript
import { ZnVaultClient } from '@zincapp/znvault-sdk';

// Create client
const client = ZnVaultClient.builder()
  .baseUrl('https://vault.example.com:8443')
  .rejectUnauthorized(false) // For self-signed certs in development
  .build();

// Login
await client.login('username', 'password');

// Create a secret
const secret = await client.secrets.create({
  alias: 'api/production/db-credentials',
  tenant: 'acme',
  type: 'credential',
  data: {
    username: 'dbuser',
    password: 'secretpass123'
  },
  tags: ['database', 'primary']
});

// Decrypt a secret
const decrypted = await client.secrets.decrypt(secret.id);
console.log(decrypted.data.password);
```

## Configuration

### Builder Pattern

```typescript
const client = ZnVaultClient.builder()
  .baseUrl('https://vault.example.com:8443')
  .apiKey('znv_xxx_your_api_key')  // Optional: use API key instead of JWT
  .timeout(30000)                   // Request timeout in ms (default: 30000)
  .retries(3)                       // Retry attempts (default: 3)
  .rejectUnauthorized(true)         // TLS verification (default: true)
  .build();
```

### Direct Constructor

```typescript
const client = new ZnVaultClient({
  baseUrl: 'https://vault.example.com:8443',
  apiKey: 'znv_xxx_your_api_key',
  timeout: 30000,
  retries: 3,
  rejectUnauthorized: true
});
```

## Authentication

### JWT Authentication

```typescript
// Login with username/password
const result = await client.login('username', 'password');
console.log(result.user); // Logged in user info

// Login with 2FA
await client.login('username', 'password', '123456');

// Logout
await client.logout();
```

### API Key Authentication

```typescript
const client = ZnVaultClient.builder()
  .baseUrl('https://vault.example.com:8443')
  .apiKey('znv_xxx_your_api_key')
  .build();

// No login required - API key is used automatically
const secrets = await client.secrets.list({ tenant: 'acme' });
```

### Managed API Keys (Auto-Rotation)

Managed API keys automatically rotate based on a configured schedule or trigger. The SDK handles renewal transparently.

**Rotation Modes:**

| Mode | Description |
|------|-------------|
| `scheduled` | Rotates at fixed intervals (e.g., every 24 hours) |
| `on-use` | Rotates after each use (TTL resets on each bind) |
| `on-bind` | Rotates each time bind is called |

**Creating a Managed Key (Admin):**

```typescript
// Create a managed API key with scheduled rotation
const managedKey = await client.auth.createManagedApiKey({
  name: 'my-service-key',
  permissions: ['secret:read:metadata', 'secret:read:value'],
  rotationMode: 'scheduled',
  rotationInterval: '24h',  // Rotate every 24 hours
  gracePeriod: '5m',        // Old key valid for 5 minutes after rotation
  tenantId: 'acme'          // Required for superadmin
});
```

**Using a Managed Key (Agent/Service):**

```typescript
// Initialize client with managed key configuration
const client = ZnVaultClient.builder()
  .baseUrl('https://vault.example.com:8443')
  .managedKey({
    name: 'my-service-key',
    refreshBeforeExpiryMs: 30000, // Refresh 30s before rotation
    onKeyRotated: (newKey, oldKey) => {
      console.log('Key rotated successfully');
    },
    onRotationError: (error) => {
      console.error('Rotation failed:', error);
    }
  })
  .build();

// Initialize with current key value (from secure storage or env var)
const bindResponse = await client.initManagedKey(process.env.VAULT_API_KEY!);
console.log('Next rotation at:', bindResponse.nextRotationAt);

// SDK automatically refreshes before expiration
// All requests use the current valid key
const secrets = await client.secrets.list({ tenant: 'acme' });

// Check managed key status
if (client.isManagedKeyMode()) {
  const info = client.getManagedKeyInfo();
  console.log('Next rotation:', info?.nextRotationAt);
}

// Force immediate refresh if needed
await client.refreshManagedKey();

// Stop auto-rotation when shutting down
client.stopManagedKeyRotation();
```

**Managed Key CRUD Operations:**

```typescript
// List managed keys
const { keys } = await client.auth.listManagedApiKeys('acme');

// Get managed key details
const key = await client.auth.getManagedApiKey('my-service-key');

// Bind to get current key value (for agents)
const binding = await client.auth.bindManagedApiKey('my-service-key');
console.log('Current key:', binding.key);
console.log('Expires at:', binding.expiresAt);

// Force rotate immediately
const rotated = await client.auth.rotateManagedApiKey('my-service-key');

// Update configuration
await client.auth.updateManagedApiKeyConfig('my-service-key', {
  rotationInterval: '12h',
  gracePeriod: '10m'
});

// Delete managed key
await client.auth.deleteManagedApiKey('my-service-key');
```

## Secrets Management

```typescript
// Create a secret
const secret = await client.secrets.create({
  alias: 'api/production/api-key',
  tenant: 'acme',
  type: 'opaque',
  data: { key: 'sk_live_xxx' },
  tags: ['api', 'production']
});

// Get secret metadata
const metadata = await client.secrets.get(secret.id);

// Decrypt secret value
const decrypted = await client.secrets.decrypt(secret.id);

// Update secret
await client.secrets.update(secret.id, {
  data: { key: 'sk_live_new_key' }
});

// Rotate secret (creates new version)
await client.secrets.rotate(secret.id, {
  key: 'sk_live_rotated_key'
});

// Get secret history
const history = await client.secrets.getHistory(secret.id);

// Decrypt specific version
const oldVersion = await client.secrets.decryptVersion(secret.id, 1);

// List secrets
const secrets = await client.secrets.list({
  tenant: 'acme',
  type: 'credential',
  page: 1,
  pageSize: 20
});

// Delete secret
await client.secrets.delete(secret.id);
```

### Pattern Matching & Search

Use wildcard patterns with `*` to query secrets by path:

```typescript
// Find all secrets under a path
const webSecrets = await client.secrets.list({
  aliasPrefix: 'web/*'
});

// Find secrets containing "/env/" anywhere in the path
const envSecrets = await client.secrets.list({
  aliasPrefix: '*/env/*'
});

// SQL-like pattern matching
const dbSecrets = await client.secrets.list({
  aliasPrefix: '*/env/secret_*'
});

// Match multiple path segments
const prodDb = await client.secrets.list({
  aliasPrefix: 'db-*/prod*'
});
// Matches: db-mysql/production, db-postgres/prod-us, etc.

// Combine pattern with type filter
const credentials = await client.secrets.list({
  aliasPrefix: '*/production/*',
  type: 'credential'
});
```

**Pattern Examples:**

| Pattern | Matches |
|---------|---------|
| `web/*` | `web/api`, `web/frontend/config` |
| `*/env/*` | `app/env/vars`, `service/env/config` |
| `db-*/prod*` | `db-mysql/production`, `db-postgres/prod-us` |
| `*secret*` | `my-secret`, `api/secret/key`, `secret-config` |
| `*/production/db-*` | `app/production/db-main`, `api/production/db-replica` |

### File Upload/Download

```typescript
import fs from 'fs';

// Upload a file
const cert = await client.secrets.uploadFile(
  'ssl/production/api-cert',
  'acme',
  fs.readFileSync('/path/to/cert.pem'),
  'cert.pem',
  ['certificate', 'ssl']
);

// Download a file
const fileData = await client.secrets.downloadFile(cert.id);
fs.writeFileSync('/path/to/output.pem', fileData.content);
```

## KMS (Key Management Service)

```typescript
// Create a master key
const key = await client.kms.createKey({
  alias: 'alias/my-encryption-key',
  description: 'Production encryption key',
  usage: 'ENCRYPT_DECRYPT',
  keySpec: 'AES_256',
  tenantId: 'acme'
});

// Encrypt data
const encrypted = await client.kms.encrypt(key.id, 'sensitive data');
// or with context
const encrypted = await client.kms.encryptString(key.id, 'sensitive data', {
  app: 'my-service'
});

// Decrypt data
const decrypted = await client.kms.decryptString(key.id, encrypted);

// Encrypt/decrypt binary data
const encryptedBuffer = await client.kms.encryptBuffer(key.id, buffer);
const decryptedBuffer = await client.kms.decryptBuffer(key.id, encryptedBuffer);

// Generate data key (for envelope encryption)
const dataKey = await client.kms.generateDataKey(key.id, 'AES_256');
// dataKey.plaintext - use for encryption, then discard
// dataKey.ciphertextBlob - store alongside encrypted data

// Rotate key
await client.kms.rotateKey(key.id);

// Enable/disable key
await client.kms.disableKey(key.id);
await client.kms.enableKey(key.id);

// Schedule deletion
await client.kms.scheduleKeyDeletion(key.id, 7); // 7 days pending window
```

## Admin Operations

### User Management

```typescript
// Create user
const user = await client.users.create({
  username: 'alice',
  password: 'secure-password',
  email: 'alice@example.com',
  role: 'user',
  tenantId: 'acme'
});

// Assign role
await client.users.assignRole(user.id, roleId);

// Reset password
await client.users.resetPassword(user.id, 'new-password');

// Setup TOTP
const totp = await client.users.setupTotp(user.id);
console.log(totp.qrCode); // QR code for authenticator app
```

### Role Management

```typescript
// Create role
const role = await client.roles.create({
  name: 'secret-reader',
  description: 'Can read secrets',
  permissions: ['secret:read:metadata', 'secret:read:value'],
  tenantId: 'acme'
});

// List available permissions
const permissions = await client.roles.listPermissions();
```

### Tenant Management

```typescript
// Create tenant
const tenant = await client.tenants.create({
  id: 'acme',
  name: 'Acme Corporation',
  maxSecrets: 1000,
  maxKmsKeys: 50,
  contactEmail: 'admin@acme.com'
});

// Check quota
const quota = await client.tenants.checkQuota('acme', 'secrets');
console.log(`${quota.current}/${quota.limit} secrets used`);

// Suspend tenant
await client.tenants.suspend('acme');
```

### Policy Management (ABAC)

```typescript
// Create policy
const policy = await client.policies.create({
  name: 'production-access',
  description: 'Allow access to production secrets',
  effect: 'allow',
  actions: ['secret:read:value'],
  resources: ['secret:acme:production:*'],
  conditions: {
    ipAddress: { in: ['10.0.0.0/8'] }
  },
  tenantId: 'acme'
});

// Attach to user
await client.policies.attachToUser(policy.id, userId);

// Attach to role
await client.policies.attachToRole(policy.id, roleId);
```

## Audit Logs

```typescript
// List audit entries
const logs = await client.audit.list({
  tenantId: 'acme',
  action: 'secret:decrypt',
  startDate: '2024-01-01',
  endDate: '2024-12-31',
  page: 1,
  pageSize: 100
});

// Verify audit chain integrity
const verification = await client.audit.verify();
if (!verification.valid) {
  console.error('Audit log tampering detected!');
}
```

## Health Checks

```typescript
// Full health check
const health = await client.health.check();
console.log(health.status); // 'healthy', 'degraded', or 'unhealthy'

// Readiness check
const ready = await client.health.ready();

// Liveness check
const live = await client.health.live();
```

## Error Handling

```typescript
import {
  ZnVaultError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  RateLimitError,
  ValidationError
} from '@zincapp/znvault-sdk';

try {
  await client.secrets.get('non-existent');
} catch (error) {
  if (error instanceof NotFoundError) {
    console.log('Secret not found');
  } else if (error instanceof AuthenticationError) {
    console.log('Authentication failed - please login');
  } else if (error instanceof AuthorizationError) {
    console.log('Permission denied');
  } else if (error instanceof RateLimitError) {
    console.log(`Rate limited. Retry after ${error.retryAfter}s`);
  } else if (error instanceof ValidationError) {
    console.log('Invalid request:', error.details);
  } else if (error instanceof ZnVaultError) {
    console.log(`API error: ${error.message} (${error.statusCode})`);
  }
}
```

## TypeScript Support

The SDK is written in TypeScript and provides full type definitions:

```typescript
import type {
  Secret,
  SecretType,
  KmsKey,
  User,
  Role,
  Tenant,
  Policy,
  AuditEntry,
  CreateSecretRequest,
  SecretFilter,
  PaginatedResponse
} from '@zincapp/znvault-sdk';

// Types are automatically inferred
const secret: Secret = await client.secrets.get(id);
const secrets: PaginatedResponse<Secret> = await client.secrets.list();
```

## Testing

### Running Tests

The SDK uses an ephemeral Docker environment for integration testing. Tests run against a fresh vault instance that is automatically created and destroyed.

```bash
# From the SDK directory, use the SDK test runner:
../zn-vault/scripts/sdk-test-run.sh npm test

# Or if zn-vault is in a sibling directory:
../scripts/sdk-test-run.sh npm test
```

The test runner will:
1. Start a fresh vault container on port 9443
2. Initialize test data (tenant, users, secrets, API key)
3. Export credentials as environment variables
4. Run your tests
5. Clean up the container (regardless of test outcome)

### Environment Variables

When running tests, the following environment variables are set automatically:

| Variable | Description | Example |
|----------|-------------|---------|
| `ZNVAULT_BASE_URL` | Vault server URL | `https://localhost:9443` |
| `ZNVAULT_USERNAME` | Superadmin username | `admin` |
| `ZNVAULT_PASSWORD` | Superadmin password | `SdkSuperAdmin123456#` |
| `ZNVAULT_TENANT` | Test tenant ID | `sdk-test` |
| `ZNVAULT_API_KEY` | Pre-created API key | `znv_...` |

### Test Configuration

The test configuration is in `test/test-config.ts`. It automatically detects whether integration tests should run based on the presence of `ZNVAULT_BASE_URL`.

### Manual Testing

To run tests against an existing vault instance:

```bash
export ZNVAULT_BASE_URL=https://vault.example.com:8443
export ZNVAULT_USERNAME=admin
export ZNVAULT_PASSWORD=your-password
npm test
```

## License

Apache-2.0
