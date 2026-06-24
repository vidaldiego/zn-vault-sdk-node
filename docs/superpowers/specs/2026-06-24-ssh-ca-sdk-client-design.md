# SSH-CA Client for `@zincapp/znvault-sdk` (Node)

**Date:** 2026-06-24
**Status:** Approved
**Target version:** 4.0.0 → 4.1.0 (additive minor)
**Server contract verified against:** `zn-vault` server v1.46.6, `src/routes/ssh-ca/*` and `src/db/repo.ssh-ca.ts`

## Context

- **Current state:** The Node SDK wraps KMS, secrets, certificates, auth, audit, health, and admin
  resources. It does **not** wrap the SSH Certificate Authority endpoints (`/v1/ssh/*`), so a consumer
  must call the REST API by hand.
- **Problem:** A NestJS service (archon) needs to mint short-lived OpenSSH user certificates per host
  connection: generate an ephemeral keypair, call `sign({ publicKey, principals, ttlSeconds })`, and feed
  the returned cert straight into the `ssh2` library's `ConnectConfig` for cert-based auth. Hand-rolling
  the REST call in every consumer is error-prone.
- **Solution:** A first-class `SSHCAClient` that owns the `/v1/ssh/*` surface, mirroring the existing
  `CertificatesClient` / `KmsClient` exactly, reachable as `client.sshca`. Signing only — **no** SSH
  transport/connection capability is added to the SDK.
- **Affected components (all in `zn-vault-sdk-node/`):**
  - `src/ssh-ca/client.ts` (new) — the client class
  - `src/ssh-ca/index.ts` (new) — re-export stub
  - `src/types/index.ts` — new SSH-CA section (types)
  - `src/index.ts` — wire `_sshca` field + `get sshca()` accessor + exports
  - `test/ssh-ca.test.ts` (new) — mocked unit + integration tests
  - `README.md`, `package.json` (version bump)

## Verified Server Contract

All authenticated routes derive tenant from the JWT via `requireTenantFromContext` — **the client sends
no `tenant` param on authenticated routes**. Only the three *public* CA-discovery routes take a `:tenant`
path segment (they are unauthenticated and intended for server-side config distribution).

| # | Method & Path | Auth | Request | Success response |
|---|---------------|------|---------|------------------|
| 1 | `POST /v1/ssh/sign` | JWT (`SSH_SIGN`; `principals` override needs `SSH_CA_ADMIN`/admin-crypto) | `{ publicKey, ttlSeconds?, principals? }` | `200 { certificate, serial, principals, validAfter, validBefore, fingerprint }` |
| 2 | `GET /v1/ssh/ca/:tenant/public-key` | Public | — | `200 { publicKey, fingerprint, keyType }` |
| 3 | `GET /v1/ssh/ca/:tenant/public-key/raw` | Public | — | `200` `text/plain` raw key string |
| 4 | `GET /v1/ssh/ca/:tenant/krl` | Public | — | `200` `application/octet-stream` binary KRL |
| 5 | `GET /v1/ssh/ca` | JWT (`SSH_CA_READ`) | — | `200 { id, initialized, publicKey, fingerprint, keyType, defaultTtlSeconds, maxTtlSeconds, allowedExtensions }` |
| 6 | `POST /v1/ssh/ca` | JWT (`SSH_CA_ADMIN`) | `{ keyType?, defaultTtlSeconds?, maxTtlSeconds?, allowedExtensions? }` | `201 { id, publicKey, fingerprint, keyType, defaultTtlSeconds, maxTtlSeconds, allowedExtensions, createdAt }` |
| 7 | `DELETE /v1/ssh/ca` | JWT (`SSH_CA_ADMIN`) | — | `204` |
| 8 | `GET /v1/ssh/principal-mappings` | JWT (`SSH_CA_READ`) | — | `200 { items: SshPrincipalMapping[] }` (no pagination) |
| 9 | `POST /v1/ssh/principal-mappings` | JWT (`SSH_CA_ADMIN`) | `{ groupId, principals }` | `201 { id, groupId, principals, createdAt }` |
| 10 | `PUT /v1/ssh/principal-mappings/:mappingId` | JWT (`SSH_CA_ADMIN`) | `{ principals }` | `200 { success: true }` |
| 11 | `DELETE /v1/ssh/principal-mappings/:mappingId` | JWT (`SSH_CA_ADMIN`) | — | `204` |
| 12 | `GET /v1/ssh/server-groups` | JWT (`SSH_CA_READ`) | — | `200 { items: SshServerGroup[] }` (no pagination) |
| 13 | `POST /v1/ssh/server-groups` | JWT (`SSH_CA_ADMIN`) | `{ name, description? }` | `201 { id, name, description, createdAt }` |
| 14 | `GET /v1/ssh/server-groups/:groupId` | JWT (`SSH_CA_READ`) | — | `200 { id, name, description, accessRules: [{ linuxUser, allowedPrincipals }], createdAt }` |
| 15 | `DELETE /v1/ssh/server-groups/:groupId` | JWT (`SSH_CA_ADMIN`) | — | `204` |
| 16 | `PUT /v1/ssh/server-groups/:groupId/access` | JWT (`SSH_CA_ADMIN`) | `{ linuxUser, allowedPrincipals }` | `200 { linuxUser, allowedPrincipals }` (upsert) |
| 17 | `DELETE /v1/ssh/server-groups/:groupId/access/:linuxUser` | JWT (`SSH_CA_ADMIN`) | — | `204` |
| 18 | `GET /v1/ssh/server-groups/:groupId/authorized-principals` | JWT (`SSH_CA_READ`) | — | `200` `text/plain` AuthorizedPrincipalsFile content |
| 19 | `GET /v1/ssh/certificates` | JWT (`SSH_CA_READ`) | query `limit?, offset?, activeOnly?, revoked?, userId?` | `200 { items: SshCertificate[], pagination }` |
| 20 | `GET /v1/ssh/certificates/:certificateId` | JWT (`SSH_CA_READ`) | — | `200 SshCertificateDetail` (adds `extensions`, `requestIp`) |
| 21 | `POST /v1/ssh/certificates/:certificateId/revoke` | JWT (`SSH_CA_ADMIN`) | `{ reason? }` | `200 { success: true, message }` |

### Field-shape facts that drive the types

- **`sign` response is `ssh2`-ready as-is.** `certificate` is a **raw OpenSSH cert string** (begins
  `ssh-ed25519-cert-v01@openssh.com ...` / `ssh-rsa-cert-v01@openssh.com ...`), not base64. This is
  exactly what `ssh2`'s `ConnectConfig` accepts for the `certificate` field. The SDK returns it verbatim.
- **`serial` is a `string`** in JSON (DB `bigint`), e.g. `"123456789"`. Type it as `string`.
- **`validAfter` / `validBefore` are ISO 8601 strings**, matching the SDK's existing timestamp convention.
- **List wrappers differ:** `/v1/ssh/certificates` uses the standard `{ items, pagination }`
  (→ `PaginatedResponse<SshCertificate>`). `principal-mappings` and `server-groups` lists return a bare
  `{ items: [...] }` with **no** `pagination`. The client returns `T[]` for those (unwrapping `items`),
  matching how `certificates.listExpiring()` returns a bare array for a non-paginated list endpoint.
- **Admin override is the same `sign` endpoint** — there is no separate route. Passing `principals` in the
  body triggers the admin path server-side (requires `SSH_CA_ADMIN` or admin-crypto). So `sign(request)`
  with `principals` set IS the admin-override call; no extra method needed.

## Client Surface (`SSHCAClient`)

Mirrors `CertificatesClient`: `constructor(private http: HttpClient) {}`, `this.http.{post,get,put,delete}<T>`,
types imported from `../types/index.js`, a class-level doc comment noting tenant is server-derived.

```ts
class SSHCAClient {
  // --- Signing (the load-bearing path) ---
  sign(request: SignSshCertificateRequest): Promise<SignSshCertificateResponse>;   // POST /v1/ssh/sign
  // Ergonomic convenience mirroring kms.encryptString: positional args → primitive.
  signString(publicKey: string, options?: { principals?: string[]; ttlSeconds?: number }): Promise<string>; // returns the raw cert string

  // --- Public CA discovery (no auth; tenant in path) ---
  getCaPublicKey(tenant: string): Promise<SshCaPublicKey>;          // GET .../public-key (JSON)
  getCaPublicKeyRaw(tenant: string): Promise<string>;              // GET .../public-key/raw (text)
  getKrl(tenant: string): Promise<Buffer>;                          // GET .../krl (octet-stream → Buffer)

  // --- CA lifecycle (tenant from JWT) ---
  getCa(): Promise<SshCaInfo>;                                      // GET /v1/ssh/ca
  initCa(request?: InitSshCaRequest): Promise<SshCa>;              // POST /v1/ssh/ca
  deleteCa(): Promise<void>;                                        // DELETE /v1/ssh/ca

  // --- Principal mappings (SSO group → principals) ---
  listPrincipalMappings(): Promise<SshPrincipalMapping[]>;
  createPrincipalMapping(req: CreateSshPrincipalMappingRequest): Promise<SshPrincipalMapping>;
  updatePrincipalMapping(mappingId: string, req: UpdateSshPrincipalMappingRequest): Promise<void>;
  deletePrincipalMapping(mappingId: string): Promise<void>;

  // --- Server groups + access rules ---
  listServerGroups(): Promise<SshServerGroup[]>;
  createServerGroup(req: CreateSshServerGroupRequest): Promise<SshServerGroup>;
  getServerGroup(groupId: string): Promise<SshServerGroupDetail>;
  deleteServerGroup(groupId: string): Promise<void>;
  setServerGroupAccess(groupId: string, rule: SshServerGroupAccessRule): Promise<SshServerGroupAccessRule>;
  deleteServerGroupAccess(groupId: string, linuxUser: string): Promise<void>;
  getAuthorizedPrincipals(groupId: string): Promise<string>;       // text/plain

  // --- Issued certificate records ---
  listCertificates(filter?: SshCertificateFilter): Promise<PaginatedResponse<SshCertificate>>;
  getCertificate(certificateId: string): Promise<SshCertificateDetail>;
  revokeCertificate(certificateId: string, reason?: string): Promise<void>;
}
```

**Ergonomics for the archon consumer:** `sign(request)` is the obvious primary call — a plain
`{ publicKey, principals, ttlSeconds }` object in, `{ certificate, ... }` out, no hidden global state, one
HTTP POST. `signString()` is the one-liner when the caller only wants the cert string to hand to `ssh2`.
The non-2xx `revoke`/`update` "{ success }" bodies are swallowed (methods return `void`/`Promise<void>`),
since the SDK convention is to return the resource or nothing, and these carry no resource.

**`Buffer`/text handling:** `HttpClient.get` resolves non-JSON bodies as the raw string (its `JSON.parse`
falls through to `resolve(data as T)`). `getKrl` requests the octet-stream and wraps the result in a
`Buffer` (mirroring `certificates.download` returning a `Buffer`). `getCaPublicKeyRaw` /
`getAuthorizedPrincipals` return the string directly.

## Types (`src/types/index.ts`, new `SSH Certificate Authority` section)

Named in the existing `EncryptRequest`/`EncryptResponse`/`KmsKey` style. Highlights:

- `SignSshCertificateRequest { publicKey: string; ttlSeconds?: number; principals?: string[] }`
- `SignSshCertificateResponse { certificate: string; serial: string; principals: string[]; validAfter: string; validBefore: string; fingerprint: string }`
- `SshCaKeyType = 'ed25519' | 'rsa-4096'`
- `SshCaPublicKey { publicKey: string; fingerprint: string; keyType: SshCaKeyType }`
- `SshCaInfo` (the `GET /v1/ssh/ca` shape, includes `initialized: boolean`) and `SshCa` (the `POST` result)
- `InitSshCaRequest { keyType?; defaultTtlSeconds?; maxTtlSeconds?; allowedExtensions? }`
- `SshPrincipalMapping`, `CreateSshPrincipalMappingRequest`, `UpdateSshPrincipalMappingRequest`
- `SshServerGroup`, `SshServerGroupDetail`, `SshServerGroupAccessRule`, `CreateSshServerGroupRequest`
- `SshCertificate`, `SshCertificateDetail`, `SshCertificateFilter`

All timestamps `string` (ISO 8601); `serial` `string`; optional fields `?`; nullable server fields typed
`| null` to match the real JSON.

## Integration

In `src/index.ts`, following the exact pattern used for every other sub-client:
- `private _sshca: SSHCAClient;`
- `this._sshca = new SSHCAClient(this.httpClient);` in the constructor
- `get sshca(): SSHCAClient { return this._sshca; }`
- `export { SSHCAClient } from './ssh-ca/index.js';`
- New SSH-CA types flow out automatically via the existing `export * from './types/index.js';`

It inherits the same auth plumbing (`apiKey` / `apiKeyFile` / `fromEnv` / `fromEnvCustom` / managed-key
rotation) because it uses the shared `HttpClient` — **no separate auth path**.

## Testing (`test/ssh-ca.test.ts`)

Per the decision to do **both**:

1. **Mocked unit tests** (run in CI with no server). A minimal stub HttpClient (`vi.fn()`-backed
   `post`/`get`/`put`/`delete`) is injected directly into `new SSHCAClient(stub)`:
   - `sign()` happy path — asserts `POST /v1/ssh/sign` with body `{ publicKey, ttlSeconds }`, and that the
     `certificate`/`serial`/`principals` are returned verbatim (cert string passed through untouched).
   - **Admin principals override** — `sign({ publicKey, principals: ['root'] })` includes `principals` in
     the posted body.
   - **Auth-error path** — stub rejects with `AuthorizationError` (403); assert it propagates.
   - **List/pagination** — `listCertificates({ limit, offset })` builds the right query string and returns
     `{ items, pagination }`; plus a `listPrincipalMappings()` case asserting the bare-`items` unwrap.
2. **Integration tests** (`describe.skipIf(!TestConfig.isIntegrationEnabled())`) in the existing style:
   `initCa` (idempotent/ignore-409) → `getCaPublicKey` → real `sign` against the live CA → assert the cert
   string is `ssh-*-cert-v01@openssh.com` → `listCertificates` → `revokeCertificate`.

This introduces the only `vi.fn` mocking in the repo, but it is the only way to exercise the four named
cases in CI (which has no vault), which the user explicitly asked for.

## Error Handling

No new error types. The shared `HttpClient` already maps 400→`ValidationError`, 401→`AuthenticationError`,
403→`AuthorizationError`, 404→`NotFoundError`, 429→`RateLimitError`, else→`ZnVaultError`. SSH-CA methods
make no attempt to catch/translate — errors surface as the existing classes, matching every other client.

## Release

Additive minor: `4.0.0 → 4.1.0`. Per `RELEASING.md` / `CLAUDE.md`: bump `package.json`, commit, push
`main`, push tag `v4.1.0`; GitHub Actions builds, tests, and publishes to npm via OIDC Trusted Publishing.
No manual `npm publish`.

## Success Criteria

- `import { SSHCAClient, SignSshCertificateRequest } from '@zincapp/znvault-sdk'` works.
- `client.sshca.sign({ publicKey, principals, ttlSeconds })` returns `{ certificate, serial, principals,
  validAfter, validBefore, fingerprint }`, `certificate` being a raw OpenSSH cert string `ssh2` accepts.
- `npm run typecheck`, `npm run lint`, `npm run build` clean; mocked unit tests pass with no server.
- KMS/secrets/certificates clients untouched; no unrelated refactors.
- Published `4.1.0` visible on npm.

## Non-Goals (YAGNI)

- No SSH connection/transport in the SDK (signing only).
- No new auth path; no per-call client construction helpers (the existing client is already cheap to call
  per-connection).
- No wrapping of superadmin cross-tenant SSH routes (none exist under `/v1/ssh`; the public `:tenant`
  discovery routes are the only tenant-in-path surface and are covered).
