// Path: zn-vault-sdk-node/test/ssh-ca.test.ts

import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { SSHCAClient } from '../src/ssh-ca/client.js';
import { AuthorizationError } from '../src/http/client.js';
import type { HttpClient } from '../src/http/client.js';
import type { ZnVaultClient } from '../src/index.js';
import { TestConfig } from './test-config.js';

/**
 * A raw OpenSSH certificate string (as returned by POST /v1/ssh/sign) begins
 * with one of these certificate key-type tokens.
 */
const SSH_CERT_PREFIXES = [
  'ssh-ed25519-cert-v01@openssh.com',
  'ssh-rsa-cert-v01@openssh.com',
];

// ============================================================================
// Unit tests (mocked HttpClient) — run in CI with no server.
// ============================================================================

/**
 * Build an SSHCAClient backed by a stubbed HttpClient. Each HTTP verb is a
 * vi.fn so tests can assert the exact path/body and control the response.
 */
function makeClient(): {
  client: SSHCAClient;
  http: { post: ReturnType<typeof vi.fn>; get: ReturnType<typeof vi.fn>; put: ReturnType<typeof vi.fn>; delete: ReturnType<typeof vi.fn> };
} {
  const http = {
    post: vi.fn(),
    get: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  };
  const client = new SSHCAClient(http as unknown as HttpClient);
  return { client, http };
}

describe('SSHCAClient (unit, mocked HTTP)', () => {
  let client: SSHCAClient;
  let http: ReturnType<typeof makeClient>['http'];

  beforeEach(() => {
    ({ client, http } = makeClient());
  });

  describe('sign', () => {
    it('posts to /v1/ssh/sign and returns the certificate verbatim (happy path)', async () => {
      const cert = `${SSH_CERT_PREFIXES[0]} AAAAI...base64blob... user@host`;
      http.post.mockResolvedValue({
        certificate: cert,
        serial: '123456789',
        principals: ['ubuntu'],
        validAfter: '2026-06-24T10:00:00.000Z',
        validBefore: '2026-06-24T11:00:00.000Z',
        fingerprint: 'SHA256:abcdef',
      });

      const result = await client.sign({
        publicKey: 'ssh-ed25519 AAAAC3Nz... user@host',
        ttlSeconds: 3600,
      });

      // Exact path + body shape (no principals on the non-admin path).
      expect(http.post).toHaveBeenCalledTimes(1);
      expect(http.post).toHaveBeenCalledWith('/v1/ssh/sign', {
        publicKey: 'ssh-ed25519 AAAAC3Nz... user@host',
        ttlSeconds: 3600,
        principals: undefined,
      });

      // Certificate string is passed through untouched (ssh2-ready) and serial is a string.
      expect(result.certificate).toBe(cert);
      expect(result.serial).toBe('123456789');
      expect(typeof result.serial).toBe('string');
      expect(result.principals).toEqual(['ubuntu']);
      expect(result.validAfter).toBe('2026-06-24T10:00:00.000Z');
      expect(result.fingerprint).toBe('SHA256:abcdef');
    });

    it('includes explicit principals in the body on the admin override path', async () => {
      http.post.mockResolvedValue({
        certificate: `${SSH_CERT_PREFIXES[0]} AAAA... admin@host`,
        serial: '987654321',
        principals: ['root', 'ops'],
        validAfter: '2026-06-24T10:00:00.000Z',
        validBefore: '2026-06-24T11:00:00.000Z',
        fingerprint: 'SHA256:fedcba',
      });

      const result = await client.sign({
        publicKey: 'ssh-ed25519 AAAA... admin@host',
        principals: ['root', 'ops'],
        ttlSeconds: 1800,
      });

      expect(http.post).toHaveBeenCalledWith('/v1/ssh/sign', {
        publicKey: 'ssh-ed25519 AAAA... admin@host',
        ttlSeconds: 1800,
        principals: ['root', 'ops'],
      });
      expect(result.principals).toEqual(['root', 'ops']);
    });

    it('signString returns just the raw certificate string', async () => {
      const cert = `${SSH_CERT_PREFIXES[0]} AAAA... user@host`;
      http.post.mockResolvedValue({
        certificate: cert,
        serial: '1',
        principals: ['ubuntu'],
        validAfter: '2026-06-24T10:00:00.000Z',
        validBefore: '2026-06-24T11:00:00.000Z',
        fingerprint: 'SHA256:x',
      });

      const out = await client.signString('ssh-ed25519 AAAA... user@host', {
        principals: ['ubuntu'],
        ttlSeconds: 3600,
      });

      expect(out).toBe(cert);
      expect(http.post).toHaveBeenCalledWith('/v1/ssh/sign', {
        publicKey: 'ssh-ed25519 AAAA... user@host',
        ttlSeconds: 3600,
        principals: ['ubuntu'],
      });
    });

    it('propagates an AuthorizationError (403) from the HTTP layer', async () => {
      http.post.mockRejectedValue(
        new AuthorizationError('Direct principal specification requires SSH_CA_ADMIN permission')
      );

      await expect(
        client.sign({ publicKey: 'ssh-ed25519 AAAA... user@host', principals: ['root'] })
      ).rejects.toBeInstanceOf(AuthorizationError);
    });
  });

  describe('listCertificates', () => {
    it('builds the query string and returns the paginated envelope', async () => {
      http.get.mockResolvedValue({
        items: [
          {
            id: 'cert-1',
            serial: '42',
            userId: 'user-1',
            username: 'alice',
            fingerprint: 'SHA256:aaa',
            principals: ['ubuntu'],
            validAfter: '2026-06-24T10:00:00.000Z',
            validBefore: '2026-06-24T11:00:00.000Z',
            revoked: false,
            revokedAt: null,
            revokedBy: null,
            revocationReason: null,
            createdAt: '2026-06-24T10:00:00.000Z',
          },
        ],
        pagination: { total: 1, limit: 10, offset: 0, hasMore: false },
      });

      const page = await client.listCertificates({ limit: 10, offset: 0, activeOnly: true });

      const calledPath = http.get.mock.calls[0][0] as string;
      expect(calledPath.startsWith('/v1/ssh/certificates?')).toBe(true);
      expect(calledPath).toContain('limit=10');
      expect(calledPath).toContain('activeOnly=true');
      expect(page.items).toHaveLength(1);
      expect(page.items[0].serial).toBe('42');
      expect(page.pagination.hasMore).toBe(false);
    });

    it('omits the query string entirely when no filter is supplied', async () => {
      http.get.mockResolvedValue({
        items: [],
        pagination: { total: 0, limit: 50, offset: 0, hasMore: false },
      });

      await client.listCertificates();

      expect(http.get).toHaveBeenCalledWith('/v1/ssh/certificates');
    });
  });

  describe('listPrincipalMappings', () => {
    it('unwraps the bare { items } list (no pagination wrapper)', async () => {
      http.get.mockResolvedValue({
        items: [
          { id: 'm1', groupId: 'g1', principals: ['ubuntu'], createdAt: '2026-06-24T10:00:00.000Z' },
        ],
      });

      const mappings = await client.listPrincipalMappings();

      expect(http.get).toHaveBeenCalledWith('/v1/ssh/principal-mappings');
      expect(Array.isArray(mappings)).toBe(true);
      expect(mappings[0].groupId).toBe('g1');
    });
  });

  describe('CA lifecycle and revoke', () => {
    it('posts CA init options through to /v1/ssh/ca', async () => {
      http.post.mockResolvedValue({ id: 'ca-1' });
      await client.initCa({ keyType: 'ed25519', defaultTtlSeconds: 3600 });
      expect(http.post).toHaveBeenCalledWith('/v1/ssh/ca', {
        keyType: 'ed25519',
        defaultTtlSeconds: 3600,
        maxTtlSeconds: undefined,
        allowedExtensions: undefined,
      });
    });

    it('revokeCertificate posts the reason to the revoke endpoint', async () => {
      http.post.mockResolvedValue({ success: true, message: 'ok' });
      await client.revokeCertificate('cert-1', 'compromised');
      expect(http.post).toHaveBeenCalledWith('/v1/ssh/certificates/cert-1/revoke', {
        reason: 'compromised',
      });
    });
  });
});

// ============================================================================
// Integration tests (require a running vault) — skipped without ZNVAULT_BASE_URL.
// ============================================================================

const shouldRunIntegration = TestConfig.isIntegrationEnabled();

/** Length-prefix a buffer per the SSH wire format (RFC 4251 string). */
function sshString(data: Buffer): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  return Buffer.concat([len, data]);
}

/**
 * Generate an ephemeral ed25519 keypair and return the public key in OpenSSH
 * authorized_keys format ("ssh-ed25519 <base64> comment"). Node emits the key
 * as JWK; we re-encode the 32-byte public key into the OpenSSH wire format.
 */
function generateOpenSshPublicKey(): string {
  const { publicKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  const raw = Buffer.from(jwk.x, 'base64url'); // 32-byte ed25519 public key
  const keyType = Buffer.from('ssh-ed25519');
  const blob = Buffer.concat([sshString(keyType), sshString(raw)]);
  return `ssh-ed25519 ${blob.toString('base64')} sdk-integration-test`;
}

describe.skipIf(!shouldRunIntegration)('SSHCAClient (integration)', () => {
  let client: ZnVaultClient | undefined;
  // When ZNVAULT_BASE_URL is configured but no server is actually reachable
  // (e.g. a local `npm test` without the SDK test stack up), skip the live
  // tests instead of hard-failing the suite.
  let serverUnreachable = false;

  beforeAll(async () => {
    try {
      client = await TestConfig.createTenantAdminClient();
      // Ensure the CA exists; ignore "already initialized" (409).
      try {
        await client.sshca.initCa({ keyType: 'ed25519' });
      } catch (err) {
        // 409 = already initialized — fine for an idempotent setup.
        const code = (err as { statusCode?: number }).statusCode;
        if (code !== 409) throw err;
      }
    } catch (err) {
      const code = (err as { errorCode?: string }).errorCode;
      if (code === 'CONNECTION_ERROR' || code === 'TIMEOUT') {
        serverUnreachable = true;
        return;
      }
      throw err;
    }
  });

  it('reports the CA as initialized with a public key', async () => {
    if (serverUnreachable || !client) return;
    const ca = await client.sshca.getCa();
    expect(ca.initialized).toBe(true);
    expect(ca.publicKey).toBeTruthy();
    expect(['ed25519', 'rsa-4096']).toContain(ca.keyType);
  });

  it('signs an ephemeral key into a raw OpenSSH certificate (admin override)', async () => {
    if (serverUnreachable || !client) return;
    const publicKey = generateOpenSshPublicKey();
    // Admin override path: tenant admin specifies principals directly.
    const result = await client.sshca.sign({
      publicKey,
      principals: ['ubuntu'],
      ttlSeconds: 3600,
    });

    expect(typeof result.certificate).toBe('string');
    expect(SSH_CERT_PREFIXES.some((p) => result.certificate.startsWith(p))).toBe(true);
    expect(typeof result.serial).toBe('string');
    expect(result.principals).toContain('ubuntu');

    // The freshly issued cert should appear in the list, then be revocable.
    const page = await client.sshca.listCertificates({ limit: 50 });
    expect(Array.isArray(page.items)).toBe(true);
    const match = page.items.find((c) => c.serial === result.serial);
    if (match) {
      await client.sshca.revokeCertificate(match.id, 'integration-test cleanup');
      const after = await client.sshca.getCertificate(match.id);
      expect(after.revoked).toBe(true);
    }
  });
});
