# SDK Contract Fixes + Docker E2E Harness

**Date:** 2026-06-24
**Status:** Approved
**Target:** `@zincapp/znvault-sdk` 4.1.1 → 4.2.0 (contract fixes are bug fixes, but several change request/response field names the few existing consumers may rely on — treat as a minor with a prominent CHANGELOG "fixes" section)
**Server contract verified against:** `zn-vault` server routes in `/Users/diegovidal/Drive/zn-vault/src/routes/` (line-referenced below)

## Context

Two linked goals from the audit (`docs/audits/2026-06-24-sdk-audit.md`):

1. **Fix the confirmed contract bugs.** The SDK has systemic field-name/path/shape drift from the real server — KMS crypto is broken both directions, several auth flows 100% fail, audit/secrets/admin/health shapes are wrong. Plus four http-core runtime bugs.
2. **Build a real Docker E2E harness** so these fixes are *proven* against a live vault and drift can't silently return. A working vault-in-Docker SDK-test stack already exists in the parent repo; we make the SDK own an `npm run test:e2e` that boots a `znvault:e2e` image and runs the integration suite against it.

**Why both together:** the fixes are only trustworthy if exercised against the real server. The E2E harness is the verification mechanism for the fixes.

## Part A — Contract Fixes

All field names below are quoted from the real server routes. The server emits **dual camelCase+snake_case aliases** on some responses (login `user`, users, tenants) but **only snake_case** on others (roles, audit query params) and uses **wrapper/renamed** shapes elsewhere (KMS). Fixes target the server's actual contract; where the server dual-emits, the SDK uses the camelCase alias (already correct) and we only fix the genuinely one-sided cases.

### A1. KMS (`src/kms/client.ts`, types in `src/types/index.ts`)

| Finding | Fix | Server evidence |
|---|---|---|
| KMS-01 (Critical) | Rename `ciphertextBlob` → `ciphertext` on encrypt/decrypt/re-encrypt/generate-data-key requests AND responses. Update `EncryptResponse`, `DecryptRequest`, `GenerateDataKeyResponse`, and the `encryptString/encryptBuffer/decryptString/decryptBuffer` helpers. | `routes/kms/crypto.ts`: encrypt resp `{ keyId, ciphertext, encryptionContext }`; decrypt req reads `ciphertext`; re-encrypt `{ sourceKeyId, destinationKeyId, ciphertext }` |
| KMS-03 | `context` is **required** server-side on encrypt/decrypt/generate-data-key; re-encrypt uses `sourceContext`/`destinationContext` (required). Make `context` required in `EncryptRequest`/`DecryptRequest`/`GenerateDataKeyRequest` (default `{}` in the helper wrappers so ergonomic calls still work). | `routes/kms/schemas.ts` lines 72-108 — `context: Type.Record(...)` not optional |
| KMS-01 re-encrypt | `reEncrypt` must send `{ ciphertext, sourceKeyId?, sourceContext, destinationKeyId, destinationContext }` (currently sends `keyId`/`ciphertextBlob`). | `routes/kms/crypto.ts` re-encrypt body |
| KMS-04 | `getKey`/`getKeyByAlias` responses are wrapped `{ keyMetadata: {...} }`. Unwrap `response.keyMetadata`. | `routes/kms/keys.ts:217-231, 809-811` |
| KMS-05 | `KmsKey` type: server uses `keyState` (not `state`), `createdDate` (not `createdAt`); enum `ENABLED\|DISABLED\|PENDING_DELETION`. Align type + the `KeyState`/`KeyFilter` union. (List rows use `keyState`/`createdDate` too.) | `routes/kms/keys.ts:48-57, 217-231` |
| KMS-06 | `setRotationStatus` must send `{ enabled, intervalDays? }` (not `rotationEnabled`/`rotationPeriodDays`). Response is `{ keyId, rotationEnabled, intervalDays?, lastRotationDate?, nextRotationDate?, rotationCount }`. | `routes/kms/rotation.ts:93-101`, schemas 110-113 |
| KMS-07 | `getRotationHistory` returns `{ history: [...] }` with entry fields `{ id, keyId, oldVersion, newVersion, rotationType, rotationDate, initiatedBy, success, errorMessage? }` (not `{ versions }`). | `routes/kms/rotation.ts:300-313` |
| KMS-08 | `scheduleKeyDeletion` body field is `pendingWindowInDays` (not `pendingWindowDays`). | `routes/kms/schemas.ts:68-70` |
| KMS-09 | `createKey` server body has **no** rotation fields — drop `rotationEnabled`/`rotationPeriodDays` from the create call (callers use `setRotationStatus` after). Body supports `alias, description, usage, keySpec, origin, multiRegion, tags`. | `routes/kms/schemas.ts:18-48` |
| URL-01 | `getKeyByAlias` must `encodeURIComponent(alias)` in the path. | path-injection |

### A2. Auth (`src/auth/client.ts`, types)

| Finding | Fix | Server evidence |
|---|---|---|
| AUTH-01 | `login` sends `totpCode` (not `totp_code`). | `routes/auth/user/login.ts:44-48` |
| AUTH-02 | `changePassword` sends `{ currentPassword, newPassword }` (camelCase). | `routes/auth/user/password.ts:31-35` |
| AUTH-03 | `forceChangePassword` sends `{ userId, currentPassword, newPassword }` (not `username`+snake_case); fix return type to `{ message }`. | `password.ts:118-130` |
| AUTH-04 | `verify2fa` sends `{ totpCode }` (not `{ code }`). | `routes/auth/2fa.ts:128-139` |
| AUTH-05 | `disable2fa` sends `totpCode` (not `totp_code`) — currently the code is silently dropped. | `routes/auth/2fa.ts` |
| AUTH-06 | `getApiKey(id)` returns the bare public key object, not `{ apiKey }` — stop unwrapping `response.apiKey`. | `routes/auth/api-keys/crud.ts` (returns `toPublic(apiKey)`) |
| AUTH-07 | `ApiKey` type fields are snake_case from `toPublic()` (`tenant_id, created_by, expires_at, last_used, created_at, ip_allowlist, rotation_count, last_rotation`). Align the type. | `crud.ts:171-200` |
| AUTH-08 | `createManagedApiKey` must POST `/auth/api-keys` with a nested `managed: { rotationMode, rotationInterval?, gracePeriod?, notifyBefore?, webhookUrl? }` (no `/managed` create route exists). | `crud.ts:81-169` |
| AUTH-09 | `rotateApiKey` body only accepts optional `name` — drop `expiresInDays`. | `crud.ts:48-52, 89` |

### A3. Secrets (`src/secrets/client.ts`)

| Finding | Fix | Server evidence |
|---|---|---|
| SECRET-01 | `updateMetadata` path is `PATCH /v1/secrets/:id/metadata` (not `/meta/data`); body accepts only `{ tags? }`. | `routes/secrets/metadata.ts:30-50` |
| SECRET-02/CONTRACT-04 | `getHistory` returns `{ items, pagination }` (standard envelope); return `PaginatedResponse<SecretHistoryEntry>` with the server's camelCase fields. | `routes/secrets/history.ts:56-150` |
| SECRET-03 | `update` (PUT) body fields the handler reads: `{ data, subType?, fileName?, ttlUntil?, expiresAt?, tags?, contentType? }` (camelCase; `ttl_until` legacy alias also accepted). Fix the camelCase send. | `routes/secrets/update.ts:144-150` |
| SECRET-04 | `list` must not send a `tags` query param (not in the schema; silently ignored). Remove it (or document it's unsupported). | secrets list querystring schema |

### A4. Audit (`src/audit/client.ts`, types)

| Finding | Fix | Server evidence |
|---|---|---|
| AUDIT-01 | Remove `audit.get(id)` — `GET /v1/audit/:id` does not exist. | only `/v1/audit`, `/export`, `/stats`, `/verify` registered |
| AUDIT-02/CONTRACT-02 | List query params are snake_case: `{ client_cn?, action?, resource?, start_date?, end_date?, limit?, offset? }`. Map the SDK filter to these. | `routes/audit/list.ts:31-41` |
| AUDIT-03/CONTRACT-01 | `AuditEntry` shape: `{ id, timestamp, action, resource, actor, clientCert, result: 'success'\|'failure', ip, metadata }`. List also returns `stats: { successCount, failureCount, uniqueUsers }`. | `list.ts:43-114` |
| AUDIT-04 | `exportLogs` returns a bare array (json) — stop reading `response.entries`. | `routes/audit/export.ts` |
| CONTRACT-03 | Collapse the two conflicting `AuditVerifyResult` definitions into one matching the server. | `types/index.ts:920` + `audit/client.ts:10` |
| EXPORT-01 | Add a `getStats()` method returning `{ successCount, failureCount, uniqueUsers }` (the exported `AuditStats` type currently has no producer + wrong shape). | `list.ts` stats block |

### A5. Admin types (`src/types/index.ts`)

`User`, `Role`, `Tenant` types. The server **dual-emits** camelCase+snake_case for `User`/`Tenant` (so the SDK's camelCase mostly works, but `totpEnabled`/quota fields are only snake_case). `Role` is **only** snake_case (`is_system`, `user_count`, `created_at`, `updated_at`).
- ADMIN-01: add `totp_enabled` (or accept that `totpEnabled` is undefined) — server only emits `totp_enabled`. Make non-present fields optional.
- ADMIN-02: `Role` → `is_system`, `user_count`, `created_at`, `updated_at` (or expose both). Fix the type so `role.isSystem` isn't always undefined.
- ADMIN-03: `Tenant` quota fields (`max_secrets`, `max_kms_keys`, `max_storage_mb`) are snake_case-only; align.
- OPT-01: `Secret.createdAt/updatedAt` typed required but omitted by several projections → make optional.
- TYPE-01: drop the dead `{ success, data }` unwrap in `TenantsClient.get` (server returns bare `Tenant`).
- TYPE-03: `CertificateKind` already fixed (`| string` + scoped disable) — no-op.

### A6. Health (`src/health/client.ts`)

- HEALTH-01: `status` enum `'ok'|'degraded'|'error'` (not `healthy/unhealthy`); `checks: { db, tls, kmip? }` (not `database/encryption/kms`).
- HEALTH-02: `ReadinessStatus` → `{ status: 'ready'|'not ready'|'degraded', timestamp, reason? }` (503 when not ready).
- EXPORT-02: collapse the double-defined `HealthStatus`/`HealthCheck` types.

### A7. HTTP core (`src/http/client.ts`)

| Finding | Fix |
|---|---|
| BINARY-01 (High) | `executeRequest` accumulates the response as a UTF-8 string (`data += chunk`), corrupting binary bodies (breaks `getKrl`). Fix: collect `Buffer[]` chunks, `Buffer.concat`, then `.toString('utf8')` for JSON parsing but pass the raw Buffer through for binary endpoints. Add a `responseType: 'buffer'` request option; `getKrl` uses it and returns the concatenated Buffer untouched. |
| RETRY-01 | Don't retry non-idempotent methods (POST/PATCH) on 5xx / network errors by default. Retry GET/PUT/DELETE (idempotent) and always honor 429. Add `idempotent` flag per request; the verb-based default is safe. |
| RETRY-02 | Clamp `Retry-After` to a max (e.g. 60s) so a hostile/huge header can't block for days. |
| ROTATION-01 | In `doManagedKeyRefresh`, call `scheduleManagedKeyRefresh()` in a `finally`/catch too, so a transient bind failure reschedules instead of permanently stopping rotation. |
| MANAGEDKEY-02 | Clamp the rotation `setTimeout` delay to ≤ 2^31-1 ms; if the true delay is larger, schedule a chained re-check rather than overflow to ~1ms busy-loop. |
| MANAGEDKEY-01 | The `isRefreshing` early-return fabricates an empty `ManagedKeyBindResponse`. Instead, await the in-flight refresh (share a single promise) and return its real result. |
| PARSE-01 | When a 2xx body isn't JSON and the caller didn't ask for text/buffer, surface a clear error (or only fall back to raw string for declared text endpoints) rather than silently returning a string typed as T. |
| TLS-01 | Keep secure-by-default; document the `NODE_TLS_REJECT_UNAUTHORIZED` global interaction; ensure `SSOClient` honors the same default as `HttpClient`. |
| TIMEOUT-01 | Add an overall request deadline (wall-clock) in addition to the socket idle timeout; handle `res` `aborted`/`close`. |

### A8. SSO (`src/sso/client.ts`, `src/sso/middleware.ts`)

- CACHE-01: introspection cache must re-check the token's own `exp` on a cache hit (don't extend effective lifetime).
- PKG-04: make the root `.` export expose the same SSO guard surface as `./sso`; remove/wire the dead `createExpressSSOScopes_Roles`.

### Out of scope / no-op
- DOC-01 (CLAUDE.md layout drift), NAMING-01 (`tokens` mirrors the server faithfully — cosmetic), ERGO-01 (nice-to-have helpers). Note these in CHANGELOG as known/intentional; fix DOC-01 since it's cheap.
- Rejected findings (AUTH-05-impact, REFRESH-01, PKG-02) — already validated as false; no action.

## Part B — Docker E2E Harness (in the SDK repo)

**Topology constraint (forced, not a choice):** the SDK is its own git repo nested in the server repo; the **server source lives in the parent** (`../src`, `../docker/Dockerfile.sdk-test`, `../scripts/sdk-entrypoint.js`). The SDK repo has no server code, so the `znvault:e2e` image must build with the **parent as build context**. The *orchestration* lives in the SDK; the *image build* sources from the parent.

### Components (all new, under the SDK repo)

1. **`docker-compose.e2e.yml`** (SDK repo root) — two services:
   - `postgres` (postgres:16-alpine, tmpfs, healthcheck) — copied from the proven sdk-test compose.
   - `vault` — `build: { context: .., dockerfile: docker/Dockerfile.sdk-test }`, `image: znvault:e2e` (this is what creates+tags the `:e2e` image), `SDK_TEST_MODE=true`, port `9443:8443`, the `sdk-health-check.js` healthcheck (waits for both health AND seeded `sdk-test.env`).
   - This **reuses the existing parent Dockerfile + `sdk-entrypoint.js` seeding** (tenant `sdk-test`, the 6 role users, secrets, KMS keys, API keys) — no re-implementation.

2. **`scripts/e2e.sh`** (SDK repo) — `up` / `down` / `run` / `env`:
   - `up`: `docker compose -f docker-compose.e2e.yml up -d --build`, wait for the vault container to be healthy, then `docker cp`/`exec cat /app/data/sdk-test.env` → write `.e2e.env` in the SDK repo.
   - `run`: `up` → `set -a; source .e2e.env` → `vitest run` (integration suites) → capture exit → `down` (unless `--keep`).
   - `down`: `docker compose -f docker-compose.e2e.yml down -v` + remove `.e2e.env`.
   - Self-contained: assumes it's run from the SDK repo with the parent repo present at `..` (documented prerequisite). Fails with a clear message if `../docker/Dockerfile.sdk-test` is missing.

3. **npm scripts** (SDK `package.json`):
   - `test:e2e` → `bash scripts/e2e.sh run`
   - `test:e2e:up` / `test:e2e:down` / `test:e2e:keep` for iterative dev.

4. **`vitest.e2e.config.ts`** — includes `test/**/*.test.ts` but the suite already self-gates on `ZNVAULT_BASE_URL`; the harness sets it, so integration blocks run. (Unit-only runs stay `npm test` and skip integration.)

5. **Test changes (TEST-01..04):**
   - Make all integration suites skip gracefully on `CONNECTION_ERROR`/`TIMEOUT` (currently only ssh-ca does) so a bare `npm test` with no server is green — TEST-02.
   - Remove vacuous `if (match)` assertions (TEST-04) — fail loudly if the seeded resource is missing.
   - Add E2E coverage for the **fixed** paths: KMS encrypt→decrypt round-trip, auth change-password/2FA field names, audit list with snake_case filters, secrets update/getHistory, health enums, getKrl binary integrity. These are the proof the fixes work.
   - Remove orphaned `test-types.ts` + empty `tests/` (PKG-03).

6. **CI (`.github/workflows/e2e.yml` in the SDK repo):** a job that checks out the SDK **and the parent server repo** (the build context), runs `npm run test:e2e`, on PRs. (Separate from the publish workflow.) Also add `npm run typecheck` + `npm run lint` + `npm test` (unit) as a fast pre-gate, addressing PKG-01.

### What `:e2e` means here
`znvault:e2e` is a locally-built, seeded vault image tagged by `docker-compose.e2e.yml`'s `image:` directive. It is reproducible (`--build`), ephemeral (tmpfs), and the single artifact the SDK E2E suite runs against. No registry/publish pipeline is introduced (deferred).

## Error Handling, Testing, Success Criteria

- **Error handling:** no new error types; fixes preserve the existing `ZnVaultError` hierarchy. http-core fixes make failures *safer* (no unsafe POST retry, no rotation dead-stop).
- **Testing:** every Part-A fix gets an E2E assertion in Part B against the real seeded vault. Unit tests (mocked) stay for fast CI; E2E proves the contract.
- **Success criteria:**
  - `npm test` (unit) green with no server; `npm run test:e2e` green against `znvault:e2e`.
  - KMS encrypt→decrypt round-trips; `changePassword`/2FA/`verify2fa` succeed; `audit.list` returns rows; `secrets.getHistory` returns `{items,pagination}`; `getKrl` returns byte-identical KRL.
  - `npm run typecheck` + `npm run lint` clean; build clean; SSH-CA surface unchanged.
  - Published 4.2.0 on npm.

## Sequencing
1. Part A fixes (grouped by client) + adjust existing unit tests.
2. Part B harness (compose/scripts/npm) — bring up `znvault:e2e`.
3. Add E2E assertions proving each fix; run the full suite green.
4. CI workflow; typecheck/lint/build gate.
5. CHANGELOG + bump 4.2.0 + release (OIDC tag flow).

## YAGNI / Non-goals
- No registry/publish of `:e2e` (local build only).
- No rewrite of the parent repo's sdk-entrypoint seeding (reuse as-is).
- No new SDK features beyond the audit fixes + the missing `getStats`.
- No SSH transport (unchanged from prior scope).
