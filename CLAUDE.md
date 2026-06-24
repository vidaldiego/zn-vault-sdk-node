# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

ZnVault Node.js SDK (`@zincapp/znvault-sdk`) is the official TypeScript/Node.js client library for ZnVault secrets management. It provides full coverage of the ZnVault REST API with type-safe interfaces.

### Relationship to ZnVault Server

This SDK is part of the ZnVault ecosystem. The parent directory (`../`) contains the main ZnVault server - see `../CLAUDE.md` for server documentation.

```
zn-vault/                    # Parent - Vault server
├── src/                     # Server source code
├── zn-vault-sdk-node/       # THIS REPO - Node.js SDK
├── zn-vault-sdk-python/     # Python SDK
├── zn-vault-sdk-swift/      # Swift SDK
├── zn-vault-sdk-jvm/        # Kotlin/Java SDK
├── zn-vault-agent/          # Agent for certificate/secret sync
├── znvault-cli/             # Admin CLI
└── vault-secrets-app/       # macOS app
```

## Development Commands

```bash
# Install dependencies
npm install

# Build TypeScript to dist/
npm run build

# Type checking only
npm run typecheck

# Linting
npm run lint
npm run lint:fix

# Run tests
npm test

# Run tests with coverage
npm run test:coverage
```

### Integration Test Setup

Integration tests require a running vault instance. Use the SDK test runner from the parent directory:

```bash
# From parent zn-vault/ directory
./scripts/sdk-test-run.sh npm test
```

## Architecture

```
src/
├── index.ts              # ZnVaultClient class + ZnVaultClientBuilder + all public re-exports
├── types/
│   └── index.ts          # All shared TypeScript interfaces and types
├── http/
│   ├── client.ts         # HttpClient + error classes (ZnVaultError, AuthenticationError,
│   │                     #   AuthorizationError, NotFoundError, RateLimitError, ValidationError)
│   ├── body.ts           # Request body helpers
│   └── index.ts          # Re-exports
├── auth/
│   ├── client.ts         # AuthClient (login, refresh, logout, API-key ops)
│   ├── provider.ts       # AuthProvider interface + FileApiKeyAuth implementation
│   └── index.ts          # Re-exports
├── secrets/
│   ├── client.ts         # SecretsClient
│   └── index.ts          # Re-exports
├── kms/
│   ├── client.ts         # KmsClient
│   └── index.ts          # Re-exports
├── certificates/
│   ├── client.ts         # CertificatesClient (X.509 PKI)
│   └── index.ts          # Re-exports
├── ssh-ca/
│   ├── client.ts         # SSHCAClient
│   └── index.ts          # Re-exports
├── sso/
│   ├── client.ts         # SsoClient (OAuth2/OIDC SSO apps)
│   ├── middleware.ts      # Express/Fastify SSO middleware helpers
│   ├── types.ts          # SSO-specific types
│   └── index.ts          # Re-exports
├── audit/
│   ├── client.ts         # AuditClient
│   └── index.ts          # Re-exports
├── health/
│   ├── client.ts         # HealthClient
│   └── index.ts          # Re-exports
├── admin/                # Tenant-scoped admin clients
│   ├── users.ts          # UsersClient
│   ├── roles.ts          # RolesClient
│   ├── policies.ts       # PoliciesClient (ABAC)
│   ├── tenants.ts        # TenantsClient
│   └── index.ts          # Re-exports
└── superadmin/
    ├── auth.ts           # SuperadminAuthClient
    ├── index.ts          # ZnVaultSuperadminClient + re-exports
```

**Key entry points:**
- `src/index.ts` — the single import surface; exports `ZnVaultClient`, `ZnVaultClientBuilder`, all sub-clients, error classes, and all types from `src/types/index.ts`.
- `src/http/client.ts` — low-level HTTP layer; owns all error classes (`ZnVaultError` hierarchy). No auth-sub-directory exists; authentication providers live in `src/auth/provider.ts`.
- `src/admin/` — four flat files (no `client.ts`): each exports its own named client class directly.

## Release Process

**Publishing is handled automatically by GitHub Actions CI/CD.**

### Steps to Release

1. Update version in `package.json`:
   ```bash
   npm version patch  # or minor/major
   ```

2. Commit the version bump:
   ```bash
   git add package.json package-lock.json
   git commit -m "chore(release): vX.Y.Z"
   ```

3. Create and push tag:
   ```bash
   git tag vX.Y.Z
   git push origin main
   git push origin vX.Y.Z
   ```

4. GitHub Actions automatically:
   - Runs tests
   - Builds the package
   - Publishes to npm using OIDC authentication

### npm Package

- **Package:** `@zincapp/znvault-sdk`
- **Registry:** https://www.npmjs.com/package/@zincapp/znvault-sdk

### Verification

```bash
# Check published version
npm view @zincapp/znvault-sdk version

# Install latest
npm install @zincapp/znvault-sdk
```

### CI/CD Configuration

The GitHub Actions workflow (`.github/workflows/publish.yml`) handles:
- Running tests on PRs
- Publishing to npm on version tags (`v*`)
- OIDC-based npm authentication (provenance enabled)

## Code Standards

- **TypeScript**: Strict mode enabled, no `any` types
- **ESLint**: Enforces code quality and consistency
- **Testing**: Vitest for unit and integration tests
