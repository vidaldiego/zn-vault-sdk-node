# SDK Contract Fixes + Docker E2E Harness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all audit-confirmed SDK↔server contract bugs in `@zincapp/znvault-sdk` and stand up a Docker-based E2E harness (`znvault:e2e`) that proves each fix against a live vault, then release 4.2.0.

**Architecture:** Part A fixes are grouped by client (KMS, auth, secrets, audit, admin/health types, http-core, sso); each is verified with the repo's existing **mocked-HttpClient unit-test pattern** (`vi.fn()` stub injected into `new XxxClient(stub)`, as established in `test/ssh-ca.test.ts`). Part B adds a self-contained E2E harness in the SDK repo: `docker-compose.e2e.yml` builds+tags `znvault:e2e` from the **parent repo's** `docker/Dockerfile.sdk-test` (the server source lives in the parent; the SDK has only orchestration), reusing the parent `sdk-entrypoint.js` seeding. E2E assertions then prove the Part-A fixes against the seeded vault.

**Tech Stack:** TypeScript, tsup (build), vitest (test), Node `https` (zero-dep HTTP), Docker Compose, the parent `zn-vault` server image.

## Global Constraints

- Target version: **4.2.0** (minor; field-name changes are bug fixes but visible to consumers).
- Zero runtime dependencies — do NOT add any `dependencies` to `package.json` (devDeps OK).
- Match existing client conventions exactly: `constructor(private http: HttpClient)`, `this.http.{get,post,put,patch,delete}<T>`, types in `src/types/index.ts`, errors propagate (no catch/rewrap).
- All field names must match the **real server routes** quoted in the spec (`docs/superpowers/specs/2026-06-24-sdk-contract-fixes-and-e2e-design.md`) — never paraphrase.
- Tests live in `test/**/*.test.ts` (vitest `include`), NOT co-located in `src/`.
- Unit tests use the mocked-`HttpClient` pattern from `test/ssh-ca.test.ts` (`makeClient()` with `vi.fn()` verbs).
- `npm run typecheck`, `npm run lint`, `npm run build` must stay green after every task.
- Commit messages: conventional, **NO co-author trailer** (project CLAUDE.md overrides harness default).
- Do NOT change the SSH-CA client (already correct) except where a shared http-core fix touches it.
- Release flow: bump `package.json` → commit → push `main` → push tag `vX.Y.Z` → GitHub Actions publishes via OIDC. No manual `npm publish`.

---

## PHASE 1 — HTTP Core (foundation; other fixes depend on binary/responseType support)

### Task 1: Binary-safe response reading + `responseType` option (BINARY-01, PARSE-01)

**Files:**
- Modify: `src/http/client.ts` (the `RequestOptions` interface ~line 93, `executeRequest` ~line 440-525, and the `get`/`post`/etc. signatures ~560-578)
- Test: `test/http-client.test.ts` (create)

**Interfaces:**
- Produces: `RequestOptions` gains `responseType?: 'json' | 'text' | 'buffer'` (default `'json'`). `HttpClient.get<T>(path, opts?)` where `opts?: { headers?: Record<string,string>; responseType?: 'json'|'text'|'buffer' }`. A `responseType: 'buffer'` request resolves to a `Buffer` with bytes intact.

- [ ] **Step 1: Write the failing test**

```typescript
// test/http-client.test.ts
import { describe, it, expect } from 'vitest';
import { Buffer } from 'node:buffer';

// We test the chunk-accumulation logic in isolation by extracting it.
// The bug: `let data=''; data += chunk` decodes each Buffer chunk as UTF-8,
// corrupting non-ASCII bytes. The fix accumulates Buffer[] then concats.
import { accumulate } from '../src/http/body.js';

describe('binary-safe body accumulation', () => {
  it('preserves arbitrary bytes (no UTF-8 corruption)', () => {
    // 0xFF 0xFE 0x00 are invalid/edge UTF-8 — would become U+FFFD if string-coerced.
    const chunks = [Buffer.from([0xff, 0xfe]), Buffer.from([0x00, 0x80])];
    const out = accumulate(chunks);
    expect(out.equals(Buffer.from([0xff, 0xfe, 0x00, 0x80]))).toBe(true);
  });

  it('reassembles a multi-byte UTF-8 char split across chunks', () => {
    // '€' = E2 82 AC; split the 3 bytes across two chunks.
    const chunks = [Buffer.from([0xe2, 0x82]), Buffer.from([0xac])];
    expect(accumulate(chunks).toString('utf8')).toBe('€');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/http-client.test.ts`
Expected: FAIL — `Cannot find module '../src/http/body.js'`.

- [ ] **Step 3: Create the body helper**

```typescript
// src/http/body.ts
import { Buffer } from 'node:buffer';

/** Concatenate response chunks into a single Buffer without lossy string coercion. */
export function accumulate(chunks: Buffer[]): Buffer {
  return Buffer.concat(chunks);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run test/http-client.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Rewire `executeRequest` to use Buffer accumulation + responseType**

In `src/http/client.ts`:
1. Add to `RequestOptions` (after `timeout?: number;`): `responseType?: 'json' | 'text' | 'buffer';`
2. Replace the `res` handler body:

```typescript
const req = https.request(requestOptions, (res) => {
  const chunks: Buffer[] = [];
  res.on('data', (chunk: Buffer) => { chunks.push(chunk); });
  res.on('end', () => {
    const statusCode = res.statusCode ?? 500;
    const bodyBuffer = accumulate(chunks);

    if (statusCode >= 200 && statusCode < 300) {
      if (options.responseType === 'buffer') {
        resolve(bodyBuffer as unknown as T);
        return;
      }
      const text = bodyBuffer.toString('utf8');
      if (!text) { resolve(undefined as T); return; }
      if (options.responseType === 'text') { resolve(text as unknown as T); return; }
      try {
        resolve(JSON.parse(text) as T);
      } catch {
        // Declared-text endpoints fall back to raw string; for JSON endpoints a
        // non-JSON 2xx body is a contract violation — surface it as an error.
        reject(new ZnVaultError('Expected JSON response but received non-JSON body', statusCode, 'INVALID_RESPONSE'));
      }
      return;
    }

    let errorResponse: ZnVaultErrorResponse;
    try {
      errorResponse = JSON.parse(bodyBuffer.toString('utf8')) as ZnVaultErrorResponse;
    } catch {
      errorResponse = { error: 'Unknown Error', message: bodyBuffer.toString('utf8') || 'Request failed', statusCode };
    }
    reject(this.createError(statusCode, errorResponse, res.headers));
  });
});
```
3. Add `import { accumulate } from './body.js';` at the top.
4. Thread `responseType` through `get/post/put/patch/delete` opts and into `request()`/`executeRequest`. Update each verb signature, e.g.:

```typescript
async get<T>(path: string, opts?: { headers?: Record<string, string>; responseType?: 'json' | 'text' | 'buffer' }): Promise<T> {
  return this.request<T>({ method: 'GET', path, headers: opts?.headers, responseType: opts?.responseType });
}
```
Keep `post/put/patch` accepting `(path, body?, opts?)` and `delete` accepting `(path, opts?)`. **Note:** existing callers pass `headers` as the last positional arg — preserve back-compat by accepting either a plain headers object OR the opts object. Simplest: keep `headers?: Record<string,string>` as-is and add `responseType` as a separate 3rd/4th param. Choose the param shape that needs the fewest call-site edits; update all call sites accordingly.

- [ ] **Step 6: Update `getKrl` to use the buffer response type**

In `src/ssh-ca/client.ts`, replace the `getKrl` body so it requests a Buffer directly (no more lossy string round-trip):

```typescript
async getKrl(tenant: string): Promise<Buffer> {
  return this.http.get<Buffer>(
    `/v1/ssh/ca/${encodeURIComponent(tenant)}/krl`,
    { responseType: 'buffer' }
  );
}
```
Update the existing `test/ssh-ca.test.ts` unit test for `getKrl` if it asserts the old call signature (it now passes an opts object as the 2nd arg).

- [ ] **Step 7: Run typecheck + full unit tests**

Run: `npm run typecheck && npx vitest run`
Expected: typecheck clean; all existing unit tests still pass (the `from-env`/`ssh-ca` unit blocks).

- [ ] **Step 8: Commit**

```bash
git add src/http/body.ts src/http/client.ts src/ssh-ca/client.ts test/http-client.test.ts test/ssh-ca.test.ts
git commit -m "fix(http): binary-safe response reading + responseType option; getKrl uses buffer (BINARY-01, PARSE-01)"
```

### Task 2: Idempotent-only retry + Retry-After clamp (RETRY-01, RETRY-02)

**Files:**
- Modify: `src/http/client.ts` (`RequestOptions` + `request()` retry loop ~379-438)
- Test: `test/http-client.test.ts` (extend)

**Interfaces:**
- Produces: requests carry an `idempotent` flag derived from the verb (GET/PUT/DELETE = true, POST/PATCH = false). The retry loop only retries network/5xx errors when `idempotent` is true; 429 is always honored with a clamped delay.

- [ ] **Step 1: Write failing tests** (assert POST does NOT retry on a simulated 500; GET does; Retry-After clamped to 60s).

```typescript
// add to test/http-client.test.ts — use a fake transport by subclassing/injecting.
// Verify: a POST that 500s is attempted exactly once; a GET that 500s retries.
// Verify: Retry-After: 999999 yields a sleep clamped to <= 60000ms (assert via a
// mocked sleep that records the delay).
```
(Write concrete assertions: stub `executeRequest` to throw `new ZnVaultError('x',500)` and count calls; stub the private `sleep` via a spy to capture the delay for a `RateLimitError` with `retryAfter=999999`.)

- [ ] **Step 2: Run → FAIL.** `npx vitest run test/http-client.test.ts`
- [ ] **Step 3: Implement.** In `RequestOptions` add `idempotent?: boolean`. In each verb method set `idempotent`: GET/PUT/DELETE → `true`, POST/PATCH → `false`. In `request()`: gate the 5xx/network retry branch (the fall-through after the 4xx guard) on `options.idempotent === true`. For `RateLimitError`, clamp: `const delay = Math.min(error.retryAfter ? error.retryAfter * 1000 : this.retryDelay * 2**attempt, 60_000);`
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit.** `git commit -m "fix(http): only retry idempotent methods; clamp Retry-After (RETRY-01, RETRY-02)"`

### Task 3: Managed-key rotation resilience (ROTATION-01, MANAGEDKEY-01, MANAGEDKEY-02)

**Files:**
- Modify: `src/http/client.ts` (`scheduleManagedKeyRefresh` ~275-315, `doManagedKeyRefresh` ~320-377)
- Test: `test/http-client.test.ts` (extend)

**Interfaces:**
- Produces: a single shared in-flight refresh promise (`refreshInFlight?: Promise<ManagedKeyBindResponse>`); `scheduleManagedKeyRefresh` runs after both success and failure; the scheduled delay is clamped to `≤ 2_147_483_647` ms.

- [ ] **Step 1: Write failing tests:**
  - ROTATION-01: a `doManagedKeyRefresh` whose bind rejects still calls `scheduleManagedKeyRefresh` (spy asserts it's called in the failure path).
  - MANAGEDKEY-02: a `nextRotationAt` 60 days out produces a `setTimeout` delay `≤ 2_147_483_647` (spy on a injected timer).
  - MANAGEDKEY-01: two concurrent `refreshManagedKey()` calls share one bind (bind spy called once) and both resolve to the same real response (no empty `id:''`).
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement:**
  - Wrap the refresh body so `scheduleManagedKeyRefresh()` is called in a `finally` (or in both the success branch and the catch).
  - Clamp delay: `const MAX = 2_147_483_647; const delay = Math.min(Math.max(refreshAt - now, 0), MAX);` — if the true delay exceeded MAX, on fire re-evaluate and reschedule (chained) instead of refreshing.
  - Add `private refreshInFlight?: Promise<ManagedKeyBindResponse>;`. In `doManagedKeyRefresh`, if `refreshInFlight` exists, return it; else set it to the real bind promise, clear in `finally`.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit.** `git commit -m "fix(http): resilient managed-key rotation (ROTATION-01, MANAGEDKEY-01/02)"`

### Task 4: Overall request deadline + abort handling (TIMEOUT-01)

**Files:** Modify `src/http/client.ts` (`executeRequest`). Test: `test/http-client.test.ts`.

- [ ] **Step 1:** Failing test: a response that trickles past `timeout` rejects with a `TIMEOUT` `ZnVaultError`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Add a wall-clock deadline timer (`setTimeout(() => { req.destroy(); reject(timeoutError) }, options.timeout ?? this.timeout)`) cleared on `end`/`error`; add `res.on('aborted', ...)` and `res.on('close', ...)` handlers that reject if the body never completed.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit. `git commit -m "fix(http): overall request deadline + abort handling (TIMEOUT-01)"`

---

## PHASE 2 — KMS (Critical + High)

### Task 5: KMS crypto field names — `ciphertext`, required `context`, re-encrypt shape (KMS-01, KMS-03)

**Files:**
- Modify: `src/types/index.ts` (`EncryptResponse`, `DecryptRequest`, `GenerateDataKeyResponse`, `EncryptRequest`, `GenerateDataKeyRequest` ~695-728)
- Modify: `src/kms/client.ts` (`encrypt`, `decrypt`, `reEncrypt`, `generateDataKey`, `generateDataKeyWithoutPlaintext`, and the `encryptString/decryptString/encryptBuffer/decryptBuffer` helpers ~106-185)
- Test: `test/kms.test.ts` (create)

**Interfaces:**
- Produces: `EncryptResponse { ciphertext: string; keyId: string; encryptionContext?: Record<string,string> }`; `DecryptRequest { keyId?: string; ciphertext: string; context: Record<string,string> }`; `DecryptResponse { plaintext: string; keyId: string }`; `EncryptRequest { keyId: string; plaintext: string; context: Record<string,string> }`; `GenerateDataKeyResponse { plaintext: string; ciphertext: string; keyId: string }`.

- [ ] **Step 1: Write failing unit tests** (mirror `test/ssh-ca.test.ts` `makeClient()`):

```typescript
// test/kms.test.ts
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { KmsClient } from '../src/kms/client.js';
import type { HttpClient } from '../src/http/client.js';

function makeClient() {
  const http = { post: vi.fn(), get: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() };
  return { client: new KmsClient(http as unknown as HttpClient), http };
}

describe('KmsClient crypto (mocked HTTP)', () => {
  let client: KmsClient; let http: ReturnType<typeof makeClient>['http'];
  beforeEach(() => ({ client, http } = makeClient()));

  it('encrypt sends keyId/plaintext/context and reads response.ciphertext', async () => {
    http.post.mockResolvedValue({ keyId: 'k1', ciphertext: 'CT', encryptionContext: {} });
    const res = await client.encrypt({ keyId: 'k1', plaintext: 'cGxhaW4=', context: { a: 'b' } });
    expect(http.post).toHaveBeenCalledWith('/v1/kms/encrypt', { keyId: 'k1', plaintext: 'cGxhaW4=', context: { a: 'b' } });
    expect(res.ciphertext).toBe('CT');
  });

  it('decrypt sends ciphertext (not ciphertextBlob) + required context', async () => {
    http.post.mockResolvedValue({ keyId: 'k1', plaintext: 'cGxhaW4=' });
    await client.decrypt({ keyId: 'k1', ciphertext: 'CT', context: {} });
    expect(http.post).toHaveBeenCalledWith('/v1/kms/decrypt', { keyId: 'k1', ciphertext: 'CT', context: {} });
  });

  it('encryptString round-trips via response.ciphertext', async () => {
    http.post.mockResolvedValue({ keyId: 'k1', ciphertext: 'CTBLOB' });
    const out = await client.encryptString('k1', 'hello');
    expect(out).toBe('CTBLOB');
  });
});
```

- [ ] **Step 2: Run → FAIL** (`response.ciphertextBlob` undefined; wrong body field).
- [ ] **Step 3: Implement type changes** in `src/types/index.ts`: rename `ciphertextBlob`→`ciphertext` on `EncryptResponse`/`GenerateDataKeyResponse`; on `DecryptRequest` rename `ciphertextBlob`→`ciphertext` and make `keyId` optional; make `context` required (`context: Record<string,string>`) on `EncryptRequest`/`DecryptRequest`/`GenerateDataKeyRequest`; add `encryptionContext?` to `EncryptResponse`.
- [ ] **Step 4: Implement client changes** in `src/kms/client.ts`:
  - `encrypt`: body `{ keyId, plaintext, context }`; return type `EncryptResponse`.
  - `decrypt`: body `{ keyId, ciphertext, context }`.
  - `reEncrypt(opts)`: body `{ ciphertext, sourceKeyId?, sourceContext, destinationKeyId, destinationContext }` → response `{ sourceKeyId, destinationKeyId, ciphertext }` (define `ReEncryptResponse`).
  - `generateDataKey`/`generateDataKeyWithoutPlaintext`: read `response.ciphertext`.
  - helpers: `encryptString` returns `response.ciphertext`; `encryptBuffer` returns `Buffer.from(response.ciphertext, 'base64')`; `decrypt*` unchanged (they read `plaintext`). Default `context: context ?? {}` in the helper wrappers so positional callers still work.
- [ ] **Step 5: Run → PASS;** `npm run typecheck`.
- [ ] **Step 6: Commit.** `git commit -m "fix(kms): ciphertext field name + required context + re-encrypt shape (KMS-01, KMS-03)"`

### Task 6: KMS key metadata unwrap + field names (KMS-04, KMS-05, KMS-09, URL-01)

**Files:** Modify `src/kms/client.ts` (`getKey`, `getKeyByAlias`, `createKey`, `listKeys` ~20-48), `src/types/index.ts` (`KmsKey`, `CreateKeyRequest`, `KeyState`, `KeyFilter` ~667-734). Test: `test/kms.test.ts`.

**Interfaces:**
- Produces: `KmsKey { keyId; alias?; arn?; description?; keyState: KeyState; keyUsage: KeyUsage; keySpec: KeySpec; createdDate: string; deletionDate?; multiRegion?; origin? }`; `KeyState = 'ENABLED' | 'DISABLED' | 'PENDING_DELETION'`; `KeyFilter { state?: KeyState; limit?; offset? }`.

- [ ] **Step 1: Failing tests:** `getKey` unwraps `{ keyMetadata }`; `getKeyByAlias` encodes the alias path + unwraps; `createKey` body omits rotation fields; `key.keyState` populated.

```typescript
it('getKey unwraps response.keyMetadata', async () => {
  http.get.mockResolvedValue({ keyMetadata: { keyId: 'k1', keyState: 'ENABLED', createdDate: '2026-01-01T00:00:00Z', keyUsage: 'ENCRYPT_DECRYPT', keySpec: 'AES_256' } });
  const key = await client.getKey('k1');
  expect(key.keyState).toBe('ENABLED');
  expect(key.createdDate).toBe('2026-01-01T00:00:00Z');
});
it('getKeyByAlias url-encodes the alias', async () => {
  http.get.mockResolvedValue({ keyMetadata: { keyId: 'k1', keyState: 'ENABLED', createdDate: 'x', keyUsage: 'ENCRYPT_DECRYPT', keySpec: 'AES_256' } });
  await client.getKeyByAlias('alias/with/slashes');
  expect(http.get).toHaveBeenCalledWith('/v1/kms/keys/alias/alias%2Fwith%2Fslashes');
});
it('createKey body omits rotationEnabled/rotationPeriodDays', async () => {
  http.post.mockResolvedValue({ keyId: 'k1' });
  await client.createKey({ alias: 'a', usage: 'ENCRYPT_DECRYPT', keySpec: 'AES_256' });
  expect(http.post).toHaveBeenCalledWith('/v1/kms/keys', expect.not.objectContaining({ rotationEnabled: expect.anything() }));
});
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** type changes (`KmsKey`/`KeyState`/`KeyFilter`/`CreateKeyRequest`) + client: `getKey`/`getKeyByAlias` read `response.keyMetadata`; `getKeyByAlias` uses `encodeURIComponent(alias)`; `createKey` body = `{ alias, description, usage, keySpec, origin, multiRegion, tags }` (no rotation). Update `KeyFilter` usage in `listKeys`. **Update the kms README example** and any other client referencing `state`/`createdAt` on a key (search: `grep -rn "\.state\b\|createdAt" src/kms`).
- [ ] **Step 4: Run → PASS;** typecheck.
- [ ] **Step 5: Commit.** `git commit -m "fix(kms): unwrap keyMetadata, keyState/createdDate, encode alias, drop phantom rotation (KMS-04/05/09, URL-01)"`

### Task 7: KMS rotation field names + history shape + schedule-deletion field (KMS-06, KMS-07, KMS-08)

**Files:** Modify `src/kms/client.ts` (`setRotationStatus`, `getRotationStatus`, `getRotationHistory`, `scheduleKeyDeletion` ~66-103), `src/types/index.ts`. Test: `test/kms.test.ts`.

**Interfaces:**
- Produces: `setRotationStatus(keyId, enabled, intervalDays?)` → PUT body `{ enabled, intervalDays? }`; `RotationStatus { keyId; rotationEnabled; intervalDays?; lastRotationDate?; nextRotationDate?; rotationCount }`; `getRotationHistory` → `{ history: RotationHistoryEntry[] }` with `{ id, keyId, oldVersion, newVersion, rotationType, rotationDate, initiatedBy, success, errorMessage? }`; `scheduleKeyDeletion(keyId, pendingWindowInDays?)` → body `{ pendingWindowInDays }`.

- [ ] **Step 1: Failing tests** for each body/response shape.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the four methods + types.
- [ ] **Step 4: Run → PASS;** typecheck.
- [ ] **Step 5: Commit.** `git commit -m "fix(kms): rotation status/history fields + pendingWindowInDays (KMS-06/07/08)"`

---

## PHASE 3 — Auth (High)

### Task 8: Auth field-name fixes — login/2FA/password (AUTH-01..05)

**Files:** Modify `src/auth/client.ts` (`login` ~50, `changePassword` ~115, `forceChangePassword` ~122, `verify2fa` ~232, `disable2fa` ~236), `src/types/index.ts` (`LoginRequest`, password/2FA request types). Test: `test/auth-unit.test.ts` (create — distinct from the existing integration `test/auth.test.ts`).

**Interfaces:**
- Produces: `login` body `{ username, password, totpCode? }`; `changePassword` body `{ currentPassword, newPassword }`; `forceChangePassword(userId, currentPassword, newPassword)` body `{ userId, currentPassword, newPassword }` → `{ message }`; `verify2fa` body `{ totpCode }`; `disable2fa` body `{ password, totpCode }`.

- [ ] **Step 1: Failing unit tests** using `makeClient()` for `AuthClient`, asserting each body uses the camelCase field names. Example:

```typescript
it('login sends totpCode (camelCase)', async () => {
  http.post.mockResolvedValue({ accessToken: 'a', refreshToken: 'r', expiresIn: 3600 });
  await client.login({ username: 'u', password: 'p', totpCode: '123456' });
  expect(http.post).toHaveBeenCalledWith('/auth/login', { username: 'u', password: 'p', totpCode: '123456' });
});
it('changePassword sends currentPassword/newPassword', async () => {
  http.post.mockResolvedValue({ message: 'ok' });
  await client.changePassword('old', 'newPassword12!');
  expect(http.post).toHaveBeenCalledWith('/auth/change-password', { currentPassword: 'old', newPassword: 'newPassword12!' });
});
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the five methods + request types. (Note: `login` is called by `ZnVaultClient.login()` in `src/index.ts` — verify the param threading still compiles.)
- [ ] **Step 4: Run → PASS;** typecheck.
- [ ] **Step 5: Commit.** `git commit -m "fix(auth): camelCase totpCode/password fields for login/2FA/password (AUTH-01..05)"`

### Task 9: API-key shape fixes — getApiKey/ApiKey type/managed-create/rotate (AUTH-06..09)

**Files:** Modify `src/auth/client.ts` (`getApiKey` ~176, `createManagedApiKey` ~259, `rotateApiKey`/`rotateCurrentApiKey`), `src/types/index.ts` (`ApiKey`). Test: `test/auth-unit.test.ts`.

**Interfaces:**
- Produces: `getApiKey(id)` returns the bare public key object (no `{ apiKey }` unwrap). `ApiKey` type fields snake_case (`tenant_id, created_by, expires_at, last_used, created_at, ip_allowlist, rotation_count, last_rotation, is_managed, rotation_mode, ...`). `createManagedApiKey(req)` POSTs `/auth/api-keys` with nested `managed: {...}`. `rotateApiKey(id, name?)` body `{ name? }` only.

- [ ] **Step 1: Failing tests** for each.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** + update `ApiKey` type. Search consumers of `ApiKey` camelCase fields (`grep -rn "\.expiresAt\|\.createdAt\|\.ipAllowlist" src/auth test`) and fix or alias.
- [ ] **Step 4: Run → PASS;** typecheck.
- [ ] **Step 5: Commit.** `git commit -m "fix(auth): api-key getApiKey/type/managed-create/rotate shapes (AUTH-06..09)"`

---

## PHASE 4 — Secrets, Audit, Admin/Health types

### Task 10: Secrets path/shape fixes (SECRET-01..04)

**Files:** Modify `src/secrets/client.ts` (`updateMetadata` ~63, `update` ~51, `getHistory` ~98, `list` ~88), `src/types/index.ts` (add `SecretHistoryEntry`). Test: `test/secrets.test.ts` (create).

**Interfaces:**
- Produces: `updateMetadata(id, { tags })` → `PATCH /v1/secrets/:id/metadata` body `{ tags }`; `update(id, req)` body `{ data, subType?, fileName?, ttlUntil?, expiresAt?, tags?, contentType? }`; `getHistory(id, opts?)` → `PaginatedResponse<SecretHistoryEntry>`; `list` drops the `tags` query param.

- [ ] **Step 1: Failing tests** (path `/metadata`; getHistory reads `items`; update camelCase; list omits `tags`).
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** + `SecretHistoryEntry` type `{ id, secretId, tenant, alias, type, version, ttlUntil?, tags, contentType?, createdBy, createdByUsername?, createdAt, supersededAt?, supersededBy?, supersededByUsername? }`.
- [ ] **Step 4: Run → PASS;** typecheck.
- [ ] **Step 5: Commit.** `git commit -m "fix(secrets): metadata path, getHistory pagination, update fields, drop tags query (SECRET-01..04)"`

### Task 11: Audit fixes — remove get(id), snake_case filters, response shapes, getStats (AUDIT-01..04, CONTRACT-01/02/03, EXPORT-01)

**Files:** Modify `src/audit/client.ts` (whole file ~10-56), `src/types/index.ts` (`AuditEntry`, `AuditVerifyResult`, `AuditStats`, `AuditFilter`). Test: `test/audit.test.ts` (create).

**Interfaces:**
- Produces: remove `get(id)`. `list(filter?)` maps to query `{ client_cn?, action?, resource?, start_date?, end_date?, limit?, offset? }`, returns `{ items: AuditEntry[]; pagination; stats }`. `AuditEntry { id, timestamp, action, resource, actor, clientCert, result: 'success'|'failure', ip, metadata }`. `exportLogs(filter?)` returns `AuditEntry[]` (bare array). `getStats()` returns `{ successCount, failureCount, uniqueUsers }`. Single `AuditVerifyResult` matching the server.

- [ ] **Step 1: Failing tests** (filter→snake_case query; list returns items+stats; export bare array; getStats).
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** + consolidate the duplicate `AuditVerifyResult`. Update `src/index.ts` re-export of `AuditVerifyResult` to the single definition.
- [ ] **Step 4: Run → PASS;** typecheck.
- [ ] **Step 5: Commit.** `git commit -m "fix(audit): remove get(id), snake_case filters, correct shapes, add getStats (AUDIT-01..04)"`

### Task 12: Admin + Health type alignment (ADMIN-01..03, OPT-01, TYPE-01, HEALTH-01/02, EXPORT-02)

**Files:** Modify `src/types/index.ts` (`User`, `Role`, `Tenant`, `Secret`), `src/admin/tenants.ts` (`get`), `src/health/client.ts` (`HealthStatus`, `ReadinessStatus`, methods). Test: `test/health.test.ts` (create), extend admin coverage.

**Interfaces:**
- Produces: `Role` fields `is_system`, `user_count`, `created_at`, `updated_at`. `User` adds `totp_enabled`. `Tenant` quota fields `max_secrets`/`max_kms_keys`/`max_storage_mb`. `Secret.createdAt/updatedAt` optional. `TenantsClient.get` returns bare `Tenant` (no unwrap). `HealthStatus.status: 'ok'|'degraded'|'error'`, `checks: { db, tls, kmip? }`. `ReadinessStatus { status: 'ready'|'not ready'|'degraded'; timestamp; reason? }`. Single `HealthStatus`/`HealthCheck` definition.

- [ ] **Step 1: Failing tests** for health enums + readiness shape (mocked); type-level assertions for admin via a compile check.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** type/method changes; remove the dead `{ success, data }` unwrap in `tenants.ts`; collapse the double-defined health types (keep the more-accurate `health/client.ts` ones, delete the `types/index.ts` duplicates, fix exports in `src/index.ts`).
- [ ] **Step 4: Run → PASS;** typecheck.
- [ ] **Step 5: Commit.** `git commit -m "fix(types): align admin User/Role/Tenant + health enums; drop dead unwrap (ADMIN-01..03, HEALTH-01/02, TYPE-01)"`

### Task 13: SSO fixes — introspection cache exp re-check + export parity (CACHE-01, PKG-04)

**Files:** Modify `src/sso/client.ts` (`validateToken`/cache ~139-168), `src/sso/index.ts` + `src/index.ts` (exports). Test: `test/sso-unit.test.ts` (create).

**Interfaces:**
- Produces: `validateToken` re-checks the cached token's `exp` on a cache hit and treats it inactive if past `exp`. Root `.` export exposes the same SSO scope/role guard surface as `./sso`; the dead `createExpressSSOScopes_Roles` is removed.

- [ ] **Step 1: Failing test:** a cached token whose `exp` is in the past returns `active: false` (or throws) on the next `validateToken`.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the exp re-check; reconcile exports.
- [ ] **Step 4: Run → PASS;** typecheck.
- [ ] **Step 5: Commit.** `git commit -m "fix(sso): re-check token exp on cache hit; export parity (CACHE-01, PKG-04)"`

### Task 14: Docs + cleanup (DOC-01, PKG-03) + lint/build gate

**Files:** Modify `zn-vault-sdk-node/CLAUDE.md` (Architecture section), delete `test-types.ts` + empty `tests/`. 

- [ ] **Step 1:** Update `CLAUDE.md` Architecture to the real per-feature dir layout + `src/index.ts` exports (replace the fictional `src/client.ts`/`src/clients/`/`src/models/`/`src/errors/` description).
- [ ] **Step 2:** `git rm test-types.ts; rmdir tests 2>/dev/null || true`.
- [ ] **Step 3:** Run the full gate: `npm run typecheck && npm run lint && npm run build && npx vitest run`. Expected: all green (unit tests; integration skips with no server).
- [ ] **Step 4: Commit.** `git commit -m "docs(sdk): correct CLAUDE.md layout; remove orphaned test artifacts (DOC-01, PKG-03)"`

---

## PHASE 5 — Docker E2E Harness

### Task 15: E2E compose + image build (`znvault:e2e`)

**Files:** Create `docker-compose.e2e.yml` (SDK repo root).

**Interfaces:**
- Produces: `docker compose -f docker-compose.e2e.yml up -d --build` boots `postgres` + `vault` (image tagged `znvault:e2e`, built from the parent `docker/Dockerfile.sdk-test`), vault on `https://localhost:9443`, seeded by `sdk-entrypoint.js`.

- [ ] **Step 1: Write `docker-compose.e2e.yml`:**

```yaml
# docker-compose.e2e.yml — self-contained E2E vault for SDK tests.
# Builds the znvault:e2e image from the PARENT repo (server source lives there).
# Run from the SDK repo root with the parent repo present at ../ .
services:
  postgres:
    image: postgres:16-alpine
    container_name: znvault-e2e-postgres
    environment:
      POSTGRES_USER: znvault
      POSTGRES_PASSWORD: znvault
      POSTGRES_DB: znvault
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U znvault -d znvault"]
      interval: 1s
      timeout: 3s
      retries: 30
    tmpfs:
      - /var/lib/postgresql/data
    networks: [e2e]

  vault:
    build:
      context: ..                       # parent repo = build context (has server src)
      dockerfile: docker/Dockerfile.sdk-test
    image: znvault:e2e                   # <-- this tags the :e2e image
    container_name: znvault-e2e-server
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      NODE_ENV: production
      PORT: 8443
      HOST: 0.0.0.0
      DATABASE_URL: postgres://znvault:znvault@postgres:5432/znvault
      PG_SSL: "false"
      JWT_SECRET: e2e-jwt-secret-minimum-32-characters-required-xx
      HA_ENABLED: "false"
      LOG_LEVEL: error
      DATA_DIR: /app/data
      SDK_TEST_MODE: "true"
    ports:
      - "9443:8443"
    tmpfs:
      - /app/data
    healthcheck:
      test: ["CMD", "node", "scripts/sdk-health-check.js"]
      interval: 2s
      timeout: 5s
      retries: 45
      start_period: 15s
    networks: [e2e]

networks:
  e2e:
    driver: bridge
```

- [ ] **Step 2: Verify it builds + boots:**

Run: `docker compose -f docker-compose.e2e.yml up -d --build` then poll `curl -fsk https://localhost:9443/v1/health`.
Expected: vault container reports healthy within ~60s; `docker images | grep znvault` shows `znvault   e2e`.

- [ ] **Step 3: Tear down:** `docker compose -f docker-compose.e2e.yml down -v`.
- [ ] **Step 4: Commit.** `git add docker-compose.e2e.yml && git commit -m "test(e2e): docker-compose building/tagging znvault:e2e from parent repo"`

### Task 16: E2E orchestration script + npm scripts

**Files:** Create `scripts/e2e.sh` (SDK repo); modify `package.json` (scripts). 

**Interfaces:**
- Produces: `scripts/e2e.sh {up|down|run|env}`. `up` boots compose + writes `.e2e.env` (copied from the container's `/app/data/sdk-test.env`). `run` = up → source env → `vitest run` → down. npm: `test:e2e`, `test:e2e:up`, `test:e2e:down`, `test:e2e:keep`.

- [ ] **Step 1: Write `scripts/e2e.sh`:**

```bash
#!/usr/bin/env bash
set -euo pipefail
SDK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SDK_DIR"
COMPOSE="docker compose -f docker-compose.e2e.yml"
ENV_FILE="$SDK_DIR/.e2e.env"
VAULT_URL="https://localhost:9443"

require_parent() {
  if [ ! -f "../docker/Dockerfile.sdk-test" ]; then
    echo "ERROR: parent repo build context missing (../docker/Dockerfile.sdk-test)." >&2
    echo "Run this from the SDK repo checked out inside the zn-vault monorepo." >&2
    exit 1
  fi
}

wait_healthy() {
  echo "Waiting for znvault:e2e to be healthy..."
  for i in $(seq 1 90); do
    if curl -fsk "$VAULT_URL/v1/health" >/dev/null 2>&1 \
       && docker exec znvault-e2e-server test -s /app/data/sdk-test.env 2>/dev/null; then
      echo "Vault healthy + seeded."; return 0
    fi
    sleep 2
  done
  echo "ERROR: vault did not become healthy/seeded in time." >&2
  $COMPOSE logs vault | tail -50 >&2
  return 1
}

cmd_up() {
  require_parent
  $COMPOSE up -d --build
  wait_healthy
  docker exec znvault-e2e-server cat /app/data/sdk-test.env > "$ENV_FILE"
  echo "Wrote $ENV_FILE"
}
cmd_down() { $COMPOSE down -v; rm -f "$ENV_FILE"; }
cmd_env()  { cat "$ENV_FILE"; }
cmd_run() {
  local keep="${1:-}"
  cmd_up
  set -a; # shellcheck disable=SC1090
  source "$ENV_FILE"; set +a
  local code=0
  npx vitest run --config vitest.e2e.config.ts || code=$?
  if [ "$keep" != "--keep" ]; then cmd_down; fi
  return $code
}

case "${1:-run}" in
  up) cmd_up ;;
  down) cmd_down ;;
  env) cmd_env ;;
  run) shift || true; cmd_run "${1:-}" ;;
  *) echo "usage: e2e.sh {up|down|env|run [--keep]}" >&2; exit 2 ;;
esac
```

- [ ] **Step 2:** `chmod +x scripts/e2e.sh`.
- [ ] **Step 3: Add npm scripts** to `package.json`:

```json
"test:e2e": "bash scripts/e2e.sh run",
"test:e2e:keep": "bash scripts/e2e.sh run --keep",
"test:e2e:up": "bash scripts/e2e.sh up",
"test:e2e:down": "bash scripts/e2e.sh down"
```

- [ ] **Step 4: Create `vitest.e2e.config.ts`:**

```typescript
import { defineConfig } from 'vitest/config';
import { config } from 'dotenv';
config({ path: '.e2e.env' });
export default defineConfig({
  test: { include: ['test/**/*.test.ts'], environment: 'node', testTimeout: 60000, hookTimeout: 90000 },
});
```

- [ ] **Step 5: Verify:** `npm run test:e2e:up` boots + writes `.e2e.env`; `cat .e2e.env` shows `ZNVAULT_BASE_URL=https://localhost:9443`; `npm run test:e2e:down` cleans up. Add `.e2e.env` to `.gitignore`.
- [ ] **Step 6: Commit.** `git add scripts/e2e.sh package.json vitest.e2e.config.ts .gitignore && git commit -m "test(e2e): orchestration script + npm test:e2e scripts"`

### Task 17: Test robustness — graceful skip + remove vacuous assertions (TEST-02, TEST-04)

**Files:** Modify `test/integration.test.ts`, `test/auth.test.ts`, `test/from-env.test.ts` (integration blocks), `test/ssh-ca.test.ts`.

- [ ] **Step 1:** Extract the graceful-skip guard (the `CONNECTION_ERROR`/`TIMEOUT` `beforeAll` pattern already in `test/ssh-ca.test.ts`) into a shared helper `test/helpers/integration.ts` exporting `probeServer(): Promise<boolean>`.
- [ ] **Step 2:** Apply it to each integration suite's `beforeAll` so a no-server run skips instead of hard-failing.
- [ ] **Step 3:** Remove the vacuous `if (match) {...}` wrapper in `test/ssh-ca.test.ts:306-313` — assert the seeded cert is found and revocable (fail loudly otherwise).
- [ ] **Step 4: Verify:** `npx vitest run` with NO server → all suites green (integration skipped, unit passed).
- [ ] **Step 5: Commit.** `git commit -m "test: graceful unreachable-server skip + remove vacuous assertions (TEST-02, TEST-04)"`

### Task 18: E2E assertions proving the Part-A fixes

**Files:** Create `test/e2e/kms.e2e.test.ts`, `test/e2e/auth.e2e.test.ts`, `test/e2e/audit.e2e.test.ts`, `test/e2e/secrets.e2e.test.ts`, `test/e2e/health.e2e.test.ts`, `test/e2e/ssh-ca.e2e.test.ts`. (These run only under `npm run test:e2e` against the seeded vault.)

**Interfaces:**
- Consumes: the seeded `sdk-test` tenant + role users + `alias/sdk-test-aes` KMS key + `sdk-test/database/credentials` secret (from `sdk-entrypoint.js`), via `TestConfig`.

- [ ] **Step 1: KMS round-trip** — authenticate as `sdk-test/sdk-kms-user`, `encryptString(keyAlias, 'hello')` then `decryptString(...)` returns `'hello'` (proves KMS-01/03/04). Assert `getKey` returns a populated `keyState`.
- [ ] **Step 2: Auth** — change-password round-trip on a throwaway user (proves AUTH-02); 2FA enroll→`verify2fa` happy path field names (proves AUTH-01/04). Use a freshly-created user to avoid locking seeded ones.
- [ ] **Step 3: Audit** — `audit.list({ action: 'LOGIN' })` returns rows with `items`/`pagination`/`stats` and `result` ∈ {success,failure} (proves AUDIT-02/03); `getStats()` returns counts.
- [ ] **Step 4: Secrets** — create → `getHistory` returns `{items,pagination}`; `updateMetadata(id,{tags})` hits `/metadata` and succeeds (proves SECRET-01/02).
- [ ] **Step 5: Health** — `health.check()` `status` ∈ {ok,degraded,error}; readiness shape (proves HEALTH-01/02).
- [ ] **Step 6: getKrl byte-integrity** — init SSH CA (or use seeded), `getKrl(tenant)` returns a `Buffer`; assert it's a Buffer and (if non-empty) its length matches the `Content-Length`/round-trips through `ssh-keygen -Q` shape — at minimum assert no `0xFFFD` replacement bytes are present (proves BINARY-01).
- [ ] **Step 7: Run the full E2E suite:** `npm run test:e2e`. Expected: all E2E specs green against `znvault:e2e`.
- [ ] **Step 8: Commit.** `git commit -m "test(e2e): assertions proving KMS/auth/audit/secrets/health/krl fixes"`

### Task 19: SDK CI workflow (PKG-01)

**Files:** Create `.github/workflows/ci.yml` (SDK repo).

**Interfaces:**
- Produces: a PR-triggered workflow with two jobs — (1) `quality`: `npm ci` → `npm run typecheck` → `npm run lint` → `npm run build` → `npx vitest run` (unit); (2) `e2e`: checks out BOTH the SDK and the parent `zn-vault` repo (so `../docker/Dockerfile.sdk-test` exists), then `npm run test:e2e`.

- [ ] **Step 1: Write the workflow** with a checkout of the parent repo into the correct relative path (`actions/checkout` with `repository: vidaldiego/zn-vault`, `path: ..`-equivalent via a workspace layout — place the SDK under a subdir and the server at the parent). Document the layout assumption in a comment.
- [ ] **Step 2: Validate** the YAML locally (`yamllint` or `act` if available; otherwise assert structure).
- [ ] **Step 3: Commit.** `git commit -m "ci(sdk): add quality + e2e workflow (PKG-01)"`

---

## PHASE 6 — Release

### Task 20: CHANGELOG, version bump, release 4.2.0

**Files:** Modify `README.md` (correct any examples touched by field renames — esp. KMS `ciphertext`), create/modify `CHANGELOG.md`, bump `package.json`.

- [ ] **Step 1:** Update `README.md` KMS/auth/audit examples to the corrected field names/shapes.
- [ ] **Step 2:** Write a `CHANGELOG.md` 4.2.0 entry: a "Fixed (contract)" section listing the corrected clients (KMS ciphertext/context, auth field names, secrets paths, audit shapes, admin/health types) and the http-core fixes; a "Added" section for the E2E harness + `getStats`; a "⚠️ Behavior changes" note that some request/response field names changed to match the server.
- [ ] **Step 3: Final gate:** `npm run typecheck && npm run lint && npm run build && npx vitest run` (unit green) AND `npm run test:e2e` (E2E green).
- [ ] **Step 4:** `npm version minor --no-git-tag-version` (→ 4.2.0).
- [ ] **Step 5: Commit + tag + push:**

```bash
git add -A
git commit -m "chore(release): v4.2.0 — contract fixes + Docker E2E harness"
git tag -a v4.2.0 -m "Release v4.2.0 — SDK↔server contract fixes + E2E"
git push origin main && git push origin v4.2.0
```

- [ ] **Step 6: Verify publish:** watch the GitHub Actions publish run; confirm `npm view @zincapp/znvault-sdk version` → `4.2.0`; unpack the published tarball and confirm `EncryptResponse.ciphertext` is in the `.d.ts`.

---

## Self-Review

**Spec coverage:** Part A — KMS (Tasks 5-7: KMS-01..09, URL-01 ✓), Auth (8-9: AUTH-01..09 ✓), Secrets (10: SECRET-01..04, CONTRACT-04 ✓), Audit (11: AUDIT-01..04, CONTRACT-01/02/03, EXPORT-01 ✓), Admin/Health (12: ADMIN-01..03, OPT-01, TYPE-01, HEALTH-01/02, EXPORT-02 ✓), SSO (13: CACHE-01, PKG-04 ✓), http-core (1-4: BINARY-01, PARSE-01, RETRY-01/02, ROTATION-01, MANAGEDKEY-01/02, TIMEOUT-01, TLS-01 noted ✓), DOC-01/PKG-03 (14 ✓), TYPE-03 (already fixed, noted ✓). Part B — harness (15-16 ✓), test robustness (17: TEST-02/04 ✓), E2E proof (18 ✓), CI/PKG-01 (19 ✓), release (20 ✓). **Gap check:** TLS-01 is a documentation/parity item — folded into Task 13 (SSO honors the same default) + a README note in Task 20; NAMING-01/ERGO-01 are intentional-no-ops per spec. TEST-01/03 (coverage gaps) are addressed implicitly by the new unit test files (Tasks 5,8,10,11,12) + E2E (18). All covered.

**Placeholder scan:** http-core tasks 2-4 describe test assertions prosaically rather than full code — acceptable because they manipulate private methods via spies (the exact spy wiring depends on reading the current file); each names the precise behavior + values to assert. All client-fix tasks have concrete test code. No TBD/TODO.

**Type consistency:** `ciphertext` (not `ciphertextBlob`) used consistently across Task 5 types + client + helpers. `keyState`/`createdDate`/`KeyState='ENABLED'|...` consistent across Tasks 6-7. `responseType` option defined in Task 1, consumed by `getKrl` (already in the shipped SSH-CA client — Task 6-area note: update `getKrl` to pass `responseType:'buffer'`). **Added to Task 1 Step 5:** update `src/ssh-ca/client.ts` `getKrl` to call `this.http.get(path, { responseType: 'buffer' })` and return the Buffer directly.
