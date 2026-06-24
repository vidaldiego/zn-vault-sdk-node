# Changelog

All notable changes to `@zincapp/znvault-sdk` are documented here.

---

## 4.2.0 — 2026-06-24

### ⚠️ Contract fixes (behavior-changing)

These changes correct SDK calls that did not work against the real ZnVault
server. Consumers relying on the old (broken) field names must update, but
those calls produced errors on any real server anyway.

- **KMS encrypt/decrypt** — request and response now use `ciphertext` (was
  `ciphertextBlob`). The `context` field (`Record<string, string>`) is
  required on `EncryptRequest`/`DecryptRequest`; pass `{}` for no context.
  `ReEncryptRequest` has been updated consistently (`ciphertext`,
  `sourceContext`, `destinationContext`).
- **KMS key fields** — `KmsKey` now exposes `keyId`, `keyUsage` (`KeyUsage`
  enum), and `createdDate` (ISO 8601 string). Previously the SDK surfaced raw
  server names (`id`, `usage`, `createdAt`) that differed between read and
  mutation endpoints. A normalizer (`normalizeKmsKey`) handles both server
  variants transparently; callers always see the canonical names.
- **KMS key state** — `KmsKey.keyState` is `KeyState` (`'ENABLED' |
  'DISABLED' | 'PENDING_DELETION'`). Previously it was typed as a plain
  string.
- **Auth field names** — login, 2FA, change-password, and
  force-change-password requests now send `totpCode` and `password` in
  camelCase to match the server contract (AUTH-01..05).
- **`ApiKey` type is snake_case** — `ApiKey.created_at`, `expires_at`,
  `last_used_at`, `tenant_id`, `is_active`, etc. match the raw server
  response. Previously the type used camelCase fields that the server never
  emitted (AUTH-06..09). `getApiKey` unwraps the bare object returned by the
  server.
- **Managed API key create** — `createManagedApiKey` now nests the key config
  under a `managed` property in the request body to match the server shape.
- **Rotate API key** — `rotateApiKey` sends only `name` in the body (was
  sending additional fields the server ignores).
- **Secrets** — `get` and `update` now route through the `/metadata` path;
  `getHistory` includes pagination parameters; `update` sends camelCase body
  fields (`newData`, `newAlias`); the unsupported `tags` query param has been
  removed from `list` (SECRET-01..04).
- **Audit filters** — `AuditFilter` uses `clientCn`, `startDate`, `endDate`,
  `limit`, `offset`. The client sends these as snake_case query params
  (`client_cn`, `start_date`, `end_date`) matching the server contract.
  `tenantId`, `page`, and `pageSize` are no longer part of `AuditFilter`
  (AUDIT-01..04).
- **Audit entry shapes** — `AuditEntry` uses camelCase response fields
  (`actor`, `clientCert`, `result`) matching the server. A correct timestamp
  type is used, and the phantom `stats` field on `AuditListResponse` has been
  removed. `exportLogs` is typed as `RawAuditEntry[]` (snake_case, matching
  the export endpoint's raw rows).
- **Health status enums** — `HealthStatus.status` is `'ok' | 'degraded' |
  'error'` (was `'healthy' | 'degraded' | 'unhealthy'`). `ReadinessStatus`
  is `'ready' | 'not ready' | 'degraded'`. `checks` now has typed `db` and
  `tls` sub-objects; `kmip` is a top-level sibling of `checks`, not nested
  inside it (HEALTH-01/02).
- **Admin types** — `Role`, `Tenant`, and `User` fields are snake_case
  (`created_at`, `updated_at`, `totp_enabled`, etc.) to match server
  responses. `Secret` optional timestamp fields corrected. `Tenant`
  camelCase timestamp aliases deprecated (ADMIN-01..03).
- **SSO introspection cache** — the in-memory token cache now re-checks
  expiry on every cache hit (fail-closed). Previously a cached token that
  expired in-flight could still be returned as valid (CACHE-01).

### Added

- **Docker E2E harness** (`npm run test:e2e`) — builds a `znvault:e2e` image
  from the parent server repo and runs 6 E2E suites proving the contract
  fixes against a live vault instance: KMS encrypt/decrypt (including
  `ciphertext` shape), auth login/2FA/API-key, secrets CRUD/history, audit
  list/stats/export, health checks, and SSH-CA KRL binary download (PKG-01,
  E2E harness tasks 15–19).
- **`audit.getStats()`** — new method returning aggregated audit statistics
  (total counts, success/failure breakdown, top actors and actions, recent
  failures) via `GET /v1/audit/stats` (AUDIT-04).
- **`responseType` option on HTTP client** — callers can pass
  `{ responseType: 'buffer' }` to receive a raw `Buffer` instead of parsed
  JSON. Used internally by `SSHCAClient.getKrl()` to return the binary
  OpenSSH KRL without corruption (BINARY-01).
- **`RawAuditEntry` type** — exported from the package for consumers who
  process raw `exportLogs()` rows directly.
- **CI workflow** (`.github/workflows/ci.yml`) — PR- and main-branch-triggered
  quality gate (typecheck, lint, build, unit tests) plus a Docker E2E job that
  boots a real vault instance and runs the full E2E suite (PKG-01). The
  pre-existing `publish.yml` handles npm publishing on version tags and was not
  changed.

### Fixed

- **Binary response safety** (BINARY-01) — HTTP client now reads all
  responses as Buffer first, then decodes to UTF-8 / JSON only when
  `responseType` is not `'buffer'`. Prevents OpenSSH KRL corruption on
  high-byte sequences.
- **Retry safety** (RETRY-01/02) — retries are now restricted to idempotent
  methods (`GET`, `HEAD`, `PUT`, `DELETE`). `POST` requests are not retried.
  `Retry-After` headers are respected and clamped to a 30-second maximum to
  avoid runaway back-off.
- **Request deadline** (TIMEOUT-01) — an overall per-request timeout (default
  30 s) is enforced end-to-end, preventing stalled connections from hanging
  indefinitely.
- **Managed-key rotation resilience** (ROTATION-01, MANAGEDKEY-01/02) — the
  managed-key rotation loop no longer crashes the process on transient
  network errors; errors are caught, logged, and the rotation timer is
  rescheduled. Key binding now handles the full server response shape.
- **JSON parse safety** (PARSE-01) — empty or non-JSON responses no longer
  throw an unhandled parse error; the client returns `null` / rethrows with
  context.
- **Alias URL encoding** (URL-01) — `getKeyByAlias` now URL-encodes the alias
  before embedding it in the path, so aliases containing `/` or special
  characters are routed correctly.
- **`keyMetadata` unwrap** — `getKey` and `getKeyByAlias` now unwrap the
  `{ keyMetadata: ... }` envelope returned by the server before normalizing
  the key object (KMS-04/05).

---
