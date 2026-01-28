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
├── index.ts              # Main exports
├── client.ts             # ZnVaultClient builder and configuration
├── http/                 # HTTP client implementation
│   ├── http-client.ts    # Axios-based HTTP client
│   └── auth/             # Authentication providers
│       ├── api-key.ts    # Static API key auth
│       ├── file-api-key.ts # File-based API key with auto-refresh
│       └── jwt.ts        # JWT token management
├── clients/              # API client implementations
│   ├── secrets.ts        # Secrets CRUD
│   ├── kms.ts            # Key Management Service
│   ├── auth.ts           # Authentication operations
│   ├── users.ts          # User management
│   ├── roles.ts          # Role management
│   ├── tenants.ts        # Tenant management
│   ├── policies.ts       # ABAC policy management
│   ├── audit.ts          # Audit log operations
│   └── health.ts         # Health checks
├── models/               # TypeScript interfaces and types
└── errors/               # Error classes
```

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
