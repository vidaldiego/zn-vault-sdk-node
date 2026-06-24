# Task 11 Report: Audit Fixes (AUDIT-01..04, CONTRACT-01/02/03, EXPORT-01)

## Files Modified

| File | Change |
|------|--------|
| `src/audit/client.ts` | Full rewrite: removed `get(id)`, fixed `list()` to use snake_case params, fixed `exportLogs()` to return bare array, added `getStats()`. `AuditVerifyResult` definition moved out. |
| `src/audit/index.ts` | Removed `type AuditVerifyResult` re-export (no longer defined in client.ts). |
| `src/types/index.ts` | Fixed `AuditEntry` (correct server shape), `AuditFilter` (camelCase SDK-facing, maps to snake_case on wire), `AuditStats` (full server shape), `AuditVerifyResult` (single, server-correct definition). Added `AuditListResponse` type. |
| `src/index.ts` | Removed `type AuditVerifyResult` from explicit `audit/index.js` re-export (avoids duplicate since `export * from './types/index.js'` already exports it). |
| `test/audit.test.ts` | New test file (created from scratch). |

## Duplicate AuditVerifyResult Resolution

There were two conflicting definitions:
- `src/types/index.ts`: `{ valid, entriesChecked, brokenAt? }` — wrong (doesn't match server)
- `src/audit/client.ts`: `{ valid, totalEntries, verifiedEntries, firstBrokenEntry?, error? }` — also wrong

**Server contract** (from `src/routes/audit/verify.ts` response schema):
```
{ valid: boolean, errors: string[], checkedEntries: number, lastVerified: string }
```

Resolution: Updated `src/types/index.ts` to the server-correct shape. Deleted the definition from `src/audit/client.ts`. Removed the re-export of `AuditVerifyResult` from `src/audit/index.ts` (it was re-exported from client.ts). The single definition in `src/types/index.ts` is now published via `export * from './types/index.js'` in `src/index.ts`.

## Real verify/stats Route Shapes Found

### `/v1/audit/verify` (verify.ts)
```typescript
{
  valid: boolean;
  errors: string[];
  checkedEntries: number;
  lastVerified: string; // new Date().toISOString() added by route handler
}
```

### `/v1/audit/stats` (stats.ts)
```typescript
{
  total: number;
  successCount: number;
  failureCount: number;
  uniqueUsers: number;
  successRate: number;
  topActors: Array<{ actor: string; count: number }>;
  topActions: Array<{ action: string; count: number }>;
  recentFailures: Array<{ timestamp: string; action: string; actor: string; resource: string }>;
}
```

Note: the `list()` response also embeds a stats sub-object `{ successCount, failureCount, uniqueUsers }` (no `total`/`successRate`/`topActors`/`topActions`/`recentFailures` — those are only on `/v1/audit/stats`).

## AuditEntry Shape (from list.ts transformation, ~line 104-114)
```typescript
{
  id: string;      // entry.id?.toString() ?? ''
  timestamp: string; // entry.ts
  action: string;
  resource: string;
  actor: string;   // entry.client_cn ?? 'system'
  clientCert: string; // entry.client_cn ?? ''
  result: 'success' | 'failure';
  ip: string;
  metadata?: Record<string, unknown> | null;
}
```

## AuditFilter (SDK-facing camelCase → wire snake_case mapping)
| SDK field | Query param |
|-----------|-------------|
| `clientCn` | `client_cn` |
| `action` | `action` |
| `resource` | `resource` |
| `startDate` | `start_date` |
| `endDate` | `end_date` |
| `limit` | `limit` |
| `offset` | `offset` |
| `format` (exportLogs only) | `format` |

## Fix wave 1

### Proof: export route sends raw DB rows (snake_case)

**`src/routes/audit/export.ts` line 101:**
```typescript
return await reply
  .header('Content-Type', 'application/json')
  .header('Content-Disposition', 'attachment; filename="audit-logs.json"')
  .send(entries);   // entries is the raw AuditEntry from repo.audit.ts
```

**`src/db/repo.audit.ts` lines 86–95 — raw DB row interface:**
```typescript
export interface AuditEntry {
  id?: number;
  ts: string;
  client_cn: string | null;
  action: string;
  resource: string;
  result: string;
  ip: string;
  metadata?: Record<string, unknown>;
}
```

The export route does NOT apply the camelCase transformation that `list.ts` applies (id→string, ts→timestamp, client_cn→actor/clientCert, result→'success'|'failure'). It sends the raw rows verbatim.

### RawAuditEntry added to `src/types/index.ts`

```typescript
export interface RawAuditEntry {
  id?: number;
  ts: string;
  client_cn: string | null;
  action: string;
  resource: string;
  result: string;    // free-form, not the 'success'|'failure' union
  ip: string;
  metadata?: Record<string, unknown>;
}
```

### `exportLogs` return type changed

In `src/audit/client.ts`: `Promise<AuditEntry[]>` → `Promise<RawAuditEntry[]>`, with JSDoc noting the snake_case/untransformed shape.

### Test change (`test/audit.test.ts` EXPORT-01)

Mock objects updated to raw shape (`ts`, `client_cn`, `result: string`). Added assertion:
```typescript
const callArg: string = http.get.mock.calls[0][0] as string;
expect(callArg).toContain('format=json');
```
And raw-field assertions:
```typescript
expect(result[0].ts).toBe('2026-01-15T10:00:00Z');
expect(result[0].client_cn).toBe('acme/admin');
expect(result[0].result).toBe('success');
```

### Verification output

```
npx vitest run test/audit.test.ts
✓ test/audit.test.ts (6 tests) 5ms
Test Files  1 passed (1)
    Tests  6 passed (6)

npm run typecheck && npm run lint && npm run build
→ typecheck: 0 errors
→ lint: 0 errors
→ build: CJS + ESM + DTS success
```
