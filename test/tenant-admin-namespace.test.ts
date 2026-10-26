import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ZnVaultSuperadminClient } from '../src/index.js';

describe('superadmin tenant management over HTTPS', () => {
  let server: Server;
  let directory: string;
  let client: ZnVaultSuperadminClient;
  const requests: string[] = [];

  beforeAll(async () => {
    directory = mkdtempSync(join(tmpdir(), 'znvault-sdk-tenant-test-'));
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
      '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'cert.pem'),
      '-subj', '/CN=localhost'], { stdio: 'ignore' });
    server = createServer({ key: readFileSync(join(directory, 'key.pem')),
      cert: readFileSync(join(directory, 'cert.pem')) }, (request, response) => {
      requests.push(`${request.method} ${request.url}`);
      request.resume();
      if (request.url?.startsWith('/v1/tenants')) {
        response.writeHead(307, { Location: `/v1/superadmin${request.url.slice(3)}` });
        response.end();
        return;
      }
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ id: 'acme', items: [] }));
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Missing test address');
    client = new ZnVaultSuperadminClient({ baseUrl: `https://127.0.0.1:${address.port}`,
      apiKey: 'test-only-key', rejectUnauthorized: false, retries: 0 });
  });

  afterAll(async () => {
    if (server) await new Promise<void>((resolve, reject) =>
      server.close(error => error ? reject(error) : resolve()));
    if (directory) rmSync(directory, { recursive: true, force: true });
  });

  it('uses the authenticated administrative namespace without relying on redirects', async () => {
    await client.tenants.create({ id: 'acme', name: 'Acme' });
    await client.tenants.get('acme');
    await client.tenants.update('acme', { name: 'Acme 2' });
    await client.tenants.list();
    await client.tenants.setStatus('acme', 'active');
    await client.tenants.getUsage('acme');
    await client.tenants.checkQuota('acme', 'secrets');
    await client.tenants.delete('acme');
    expect(requests).toEqual([
      'POST /v1/superadmin/tenants', 'GET /v1/superadmin/tenants/acme',
      'PATCH /v1/superadmin/tenants/acme', 'GET /v1/superadmin/tenants',
      'PUT /v1/superadmin/tenants/acme/status', 'GET /v1/superadmin/tenants/acme/usage',
      'GET /v1/superadmin/tenants/acme/quota/secrets', 'DELETE /v1/superadmin/tenants/acme',
    ]);
  });
});
