// Path: zn-vault-sdk-node/test/secrets.test.ts

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SecretsClient } from '../src/secrets/client.js';
import type { HttpClient } from '../src/http/client.js';

function makeClient() {
  const http = { post: vi.fn(), get: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() };
  return { client: new SecretsClient(http as unknown as HttpClient), http };
}

// SECRET-01: updateMetadata PATCHes /v1/secrets/:id/metadata with body { tags } only
describe('SecretsClient updateMetadata (SECRET-01)', () => {
  let client: SecretsClient; let http: ReturnType<typeof makeClient>['http'];
  beforeEach(() => ({ client, http } = makeClient()));

  it('PATCHes /v1/secrets/:id/metadata (not /meta/data)', async () => {
    const mockResponse = {
      id: 'sec-1',
      alias: 'web/prod/key',
      tenant: 'acme',
      type: 'opaque',
      version: 2,
      tags: ['prod', 'api'],
      createdBy: 'admin',
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-06-01T00:00:00.000Z',
    };
    http.patch.mockResolvedValue(mockResponse);
    await client.updateMetadata('sec-1', { tags: ['prod', 'api'] });
    const [path] = http.patch.mock.calls[0] as [string, unknown];
    expect(path).toBe('/v1/secrets/sec-1/metadata');
    // Must NOT use the old /meta/data path
    expect(path).not.toContain('meta/data');
  });

  it('sends only { tags } in body (not ttl_until or expires_at)', async () => {
    http.patch.mockResolvedValue({ id: 'sec-1', alias: 'k', tenant: 'acme', type: 'opaque', version: 1, tags: ['t'], createdAt: '', updatedAt: '' });
    await client.updateMetadata('sec-1', { tags: ['t'] });
    const body = http.patch.mock.calls[0][1] as Record<string, unknown>;
    expect(body).toHaveProperty('tags');
    expect(body).not.toHaveProperty('ttl_until');
    expect(body).not.toHaveProperty('expires_at');
    // ttlUntil and expiresAt must also not appear (legacy camelCase variants)
    expect(body).not.toHaveProperty('ttlUntil');
    expect(body).not.toHaveProperty('expiresAt');
  });

  it('returns the server response shape', async () => {
    const mockResponse = {
      id: 'sec-2',
      alias: 'db/prod/pass',
      tenant: 'acme',
      type: 'credential',
      version: 3,
      tags: ['db'],
      createdBy: 'user1',
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-06-24T00:00:00.000Z',
    };
    http.patch.mockResolvedValue(mockResponse);
    const result = await client.updateMetadata('sec-2', { tags: ['db'] });
    expect(result.id).toBe('sec-2');
    expect(result.updatedAt).toBe('2026-06-24T00:00:00.000Z');
  });
});

// SECRET-02: getHistory returns PaginatedResponse<SecretHistoryEntry> from response.items
describe('SecretsClient getHistory (SECRET-02)', () => {
  let client: SecretsClient; let http: ReturnType<typeof makeClient>['http'];
  beforeEach(() => ({ client, http } = makeClient()));

  const paginatedResponse = {
    items: [
      {
        id: 1,
        secretId: 'sec-3',
        tenant: 'acme',
        alias: 'web/prod/cert',
        type: 'opaque',
        version: 1,
        ttlUntil: null,
        tags: ['tls'],
        contentType: 'application/x-pem-file',
        createdBy: 'admin',
        createdByUsername: 'admin',
        createdAt: '2026-01-01T00:00:00.000Z',
        supersededAt: '2026-06-01T00:00:00.000Z',
        supersededBy: 'user1',
        supersededByUsername: 'alice',
      },
    ],
    pagination: { total: 1, limit: 50, offset: 0, hasMore: false },
  };

  it('GETs /v1/secrets/:id/history', async () => {
    http.get.mockResolvedValue(paginatedResponse);
    await client.getHistory('sec-3');
    const [path] = http.get.mock.calls[0] as [string];
    expect(path).toMatch(/^\/v1\/secrets\/sec-3\/history/);
  });

  it('reads response.items (not response.history)', async () => {
    http.get.mockResolvedValue(paginatedResponse);
    const result = await client.getHistory('sec-3');
    // Must return PaginatedResponse shape, not a plain array
    expect(result).toHaveProperty('items');
    expect(result).toHaveProperty('pagination');
    expect(Array.isArray(result.items)).toBe(true);
    expect(result.items).toHaveLength(1);
    expect(result.items[0].id).toBe(1);
    expect(typeof result.items[0].id).toBe('number');
    expect(result.items[0].secretId).toBe('sec-3');
  });

  it('exposes SecretHistoryEntry fields', async () => {
    http.get.mockResolvedValue(paginatedResponse);
    const result = await client.getHistory('sec-3');
    const entry = result.items[0];
    expect(entry.secretId).toBe('sec-3');
    expect(entry.tenant).toBe('acme');
    expect(entry.alias).toBe('web/prod/cert');
    expect(entry.createdByUsername).toBe('admin');
    expect(entry.supersededBy).toBe('user1');
    expect(entry.supersededByUsername).toBe('alice');
  });

  it('returns pagination metadata', async () => {
    http.get.mockResolvedValue(paginatedResponse);
    const result = await client.getHistory('sec-3');
    expect(result.pagination.total).toBe(1);
    expect(result.pagination.hasMore).toBe(false);
  });

  it('passes limit and offset as query params when provided', async () => {
    http.get.mockResolvedValue({ items: [], pagination: { total: 0, limit: 10, offset: 20, hasMore: false } });
    await client.getHistory('sec-4', { limit: 10, offset: 20 });
    const [path] = http.get.mock.calls[0] as [string];
    expect(path).toContain('limit=10');
    expect(path).toContain('offset=20');
  });
});

// SECRET-03: update body uses camelCase ttlUntil (not ttl_until)
describe('SecretsClient update (SECRET-03)', () => {
  let client: SecretsClient; let http: ReturnType<typeof makeClient>['http'];
  beforeEach(() => ({ client, http } = makeClient()));

  it('PUT body uses camelCase ttlUntil (not ttl_until)', async () => {
    http.put.mockResolvedValue({ id: 'sec-5', alias: 'k', tenant: 'acme', type: 'credential', version: 2, createdAt: '', updatedAt: '' });
    await client.update('sec-5', {
      data: { username: 'user', password: 'pass' },
      ttlUntil: '2027-01-01T00:00:00.000Z',
    });
    const body = http.put.mock.calls[0][1] as Record<string, unknown>;
    expect(body).toHaveProperty('ttlUntil', '2027-01-01T00:00:00.000Z');
    expect(body).not.toHaveProperty('ttl_until');
  });

  it('PUT /v1/secrets/:id with full camelCase body shape', async () => {
    http.put.mockResolvedValue({ id: 'sec-6', alias: 'k', tenant: 'acme', type: 'opaque', version: 3, createdAt: '', updatedAt: '' });
    await client.update('sec-6', {
      data: { content: 'hello' },
      subType: 'generic',
      fileName: 'config.txt',
      ttlUntil: '2027-06-01T00:00:00.000Z',
      expiresAt: '2027-12-31T00:00:00.000Z',
      tags: ['env'],
      contentType: 'text/plain',
    });
    const [path, body] = http.put.mock.calls[0] as [string, Record<string, unknown>];
    expect(path).toBe('/v1/secrets/sec-6');
    expect(body.data).toEqual({ content: 'hello' });
    expect(body.subType).toBe('generic');
    expect(body.fileName).toBe('config.txt');
    expect(body.ttlUntil).toBe('2027-06-01T00:00:00.000Z');
    expect(body.expiresAt).toBe('2027-12-31T00:00:00.000Z');
    expect(body.tags).toEqual(['env']);
    expect(body.contentType).toBe('text/plain');
    // Must not send snake_case variants
    expect(body).not.toHaveProperty('ttl_until');
    expect(body).not.toHaveProperty('expires_at');
    expect(body).not.toHaveProperty('file_name');
    expect(body).not.toHaveProperty('content_type');
    expect(body).not.toHaveProperty('sub_type');
  });
});

// SECRET-04: list does NOT include a tags query param
describe('SecretsClient list (SECRET-04)', () => {
  let client: SecretsClient; let http: ReturnType<typeof makeClient>['http'];
  beforeEach(() => ({ client, http } = makeClient()));

  const emptyPage = { items: [], pagination: { total: 0, limit: 50, offset: 0, hasMore: false } };

  it('does NOT append tags to the query string', async () => {
    http.get.mockResolvedValue(emptyPage);
    await client.list({ tags: ['prod'] } as Parameters<typeof client.list>[0]);
    const [path] = http.get.mock.calls[0] as [string];
    expect(path).not.toContain('tags=');
  });

  it('still sends other valid filter params (type, subType, aliasPrefix, limit, offset)', async () => {
    http.get.mockResolvedValue(emptyPage);
    await client.list({ type: 'credential', subType: 'password', aliasPrefix: 'web/', limit: 10, offset: 5 });
    const [path] = http.get.mock.calls[0] as [string];
    expect(path).toContain('type=credential');
    expect(path).toContain('subType=password');
    expect(path).toContain('aliasPrefix=web%2F');
    expect(path).toContain('limit=10');
    expect(path).toContain('offset=5');
    expect(path).not.toContain('tags=');
  });

  it('returns PaginatedResponse<Secret>', async () => {
    http.get.mockResolvedValue({ items: [{ id: 'sec-7', alias: 'k', tenant: 'acme', type: 'opaque', version: 1, createdAt: '', updatedAt: '' }], pagination: { total: 1, limit: 50, offset: 0, hasMore: false } });
    const result = await client.list();
    expect(result.items).toHaveLength(1);
    expect(result.pagination.total).toBe(1);
  });
});
