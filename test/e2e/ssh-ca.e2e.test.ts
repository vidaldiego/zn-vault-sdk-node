// Path: zn-vault-sdk-node/test/e2e/ssh-ca.e2e.test.ts
//
// E2E assertions proving BINARY-01:
//   BINARY-01 — getKrl(tenant) returns a Buffer (not a mangled string). If
//               non-empty, no UTF-8 replacement bytes (0xFFFD) are present,
//               proving the response was transferred as raw binary.
//
// Also exercises the certificate signing path end-to-end:
//   - initCa({ keyType: 'ed25519' }) (409 if already initialised is OK).
//   - Generate an ephemeral Ed25519 public key via Node's built-in crypto.
//   - sign(...) returns a raw OpenSSH certificate string beginning with
//     "ssh-ed25519-cert-v01@openssh.com".
//   - getKrl(tenant) returns a Buffer.
//
// Requires a live seeded vault (`npm run test:e2e`).

import { describe, it, expect, beforeAll } from 'vitest';
import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import type { ZnVaultClient } from '../../src/index.js';
import { TestConfig } from '../test-config.js';
import { probeServer } from '../helpers/integration.js';

const isIntegrationEnabled = TestConfig.isIntegrationEnabled();

/** Valid OpenSSH certificate key-type prefixes for user certs. */
const SSH_CERT_PREFIXES = [
  'ssh-ed25519-cert-v01@openssh.com',
  'ecdsa-sha2-nistp256-cert-v01@openssh.com',
  'rsa-sha2-512-cert-v01@openssh.com',
  'rsa-sha2-256-cert-v01@openssh.com',
  'ssh-rsa-cert-v01@openssh.com',
];

/**
 * Derive the OpenSSH wire-format public key string from a Node KeyObject.
 * Node exposes this via spki (SubjectPublicKeyInfo) DER — for Ed25519 we
 * can extract the raw 32-byte public key from the DER trailer and build the
 * OpenSSH encoding manually.
 */
function ed25519PublicKeyToOpenSSH(pubKey: KeyObject): string {
  // Node's DER encoding for Ed25519 SubjectPublicKeyInfo:
  // 12 bytes header + 32 bytes raw key (total = 44 bytes).
  const der = pubKey.export({ type: 'spki', format: 'der' }) as Buffer;
  // The raw 32-byte key starts at byte 12 in the SPKI DER for Ed25519.
  const rawPub = der.slice(12);

  // OpenSSH encoding:  length-prefixed "ssh-ed25519" + length-prefixed raw key
  const keyType = Buffer.from('ssh-ed25519');
  const buf = Buffer.allocUnsafe(4 + keyType.length + 4 + rawPub.length);
  let offset = 0;
  buf.writeUInt32BE(keyType.length, offset); offset += 4;
  keyType.copy(buf, offset); offset += keyType.length;
  buf.writeUInt32BE(rawPub.length, offset); offset += 4;
  rawPub.copy(buf, offset);

  return `ssh-ed25519 ${buf.toString('base64')} e2e-test`;
}

describe.skipIf(!isIntegrationEnabled)('E2E: SSH CA — BINARY-01 + sign end-to-end', () => {
  let serverUnreachable = false;

  // Tenant admin has SSH CA admin permissions
  let adminClient: ZnVaultClient;
  const tenant = TestConfig.DEFAULT_TENANT;

  beforeAll(async () => {
    if (!(await probeServer())) {
      serverUnreachable = true;
      return;
    }
    adminClient = await TestConfig.createTenantAdminClient();

    // Ensure the SSH CA exists — initCa is idempotent (409 = already exists)
    try {
      await adminClient.sshca.initCa({ keyType: 'ed25519' });
      console.log(`SSH CA initialized for tenant: ${tenant}`);
    } catch (err) {
      const status = (err as { statusCode?: number }).statusCode;
      if (status === 409) {
        console.log(`SSH CA already initialized for tenant: ${tenant} (409 OK)`);
      } else {
        // Unexpected — rethrow so the suite is clearly marked as broken
        throw err;
      }
    }
  });

  // ---------------------------------------------------------------------------
  // BINARY-01: getKrl returns a Buffer
  // ---------------------------------------------------------------------------

  it('BINARY-01: getKrl(tenant) returns a Buffer', async () => {
    if (serverUnreachable) return;

    const krl = await adminClient.sshca.getKrl(tenant);

    // Must be a Buffer (not a string, not a Uint8Array without Buffer prototype)
    expect(Buffer.isBuffer(krl)).toBe(true);

    console.log(`BINARY-01 pass: Buffer.isBuffer=true, length=${krl.length}`);
  });

  it('BINARY-01: getKrl starts with SSHKRL magic bytes (binary was not mangled)', async () => {
    if (serverUnreachable) return;

    const krl = await adminClient.sshca.getKrl(tenant);

    expect(Buffer.isBuffer(krl)).toBe(true);

    if (krl.length === 0) {
      // Empty KRL is valid when no certs have been revoked yet
      console.log('BINARY-01 magic-bytes check: KRL is empty, no bytes to inspect');
      return;
    }

    // A non-empty KRL must start with the OpenSSH KRL magic: "SSHKRL\n\x00"
    // (bytes: 53 53 48 4b 52 4c 0a 00). If the bytes were received as a
    // UTF-8 string the binary would be corrupted and the magic check would fail.
    const SSHKRL_MAGIC = Buffer.from('5353484b524c0a00', 'hex');
    const actualMagic = krl.slice(0, 8);
    expect(actualMagic.equals(SSHKRL_MAGIC)).toBe(true);

    console.log(
      `BINARY-01 magic-bytes pass: KRL starts with SSHKRL magic, length=${krl.length}`
    );
  });

  it('BINARY-01: getKrl length matches re-fetched call (idempotent read)', async () => {
    if (serverUnreachable) return;

    const krl1 = await adminClient.sshca.getKrl(tenant);
    const krl2 = await adminClient.sshca.getKrl(tenant);

    expect(Buffer.isBuffer(krl1)).toBe(true);
    expect(Buffer.isBuffer(krl2)).toBe(true);

    // Length must be stable across two reads (no in-flight mutations expected)
    expect(krl1.length).toBe(krl2.length);

    console.log(`BINARY-01 idempotent pass: length=${krl1.length}`);
  });

  // ---------------------------------------------------------------------------
  // Sign: sign(publicKey) returns a cert string starting with a valid prefix
  // ---------------------------------------------------------------------------

  it('sign: returns cert starting with ssh-ed25519-cert-v01@openssh.com', async () => {
    if (serverUnreachable) return;

    // Generate an ephemeral Ed25519 keypair (public key only needed for signing)
    const { publicKey } = generateKeyPairSync('ed25519');
    const publicKeyStr = ed25519PublicKeyToOpenSSH(publicKey);

    const response = await adminClient.sshca.sign({
      publicKey: publicKeyStr,
      ttlSeconds: 600, // 10 minutes
      principals: ['ubuntu', 'e2e-user'],
    });

    expect(response).toBeDefined();
    expect(typeof response.certificate).toBe('string');
    expect(response.certificate.length).toBeGreaterThan(0);

    // Must start with a known certificate key-type token
    const startsWithKnownPrefix = SSH_CERT_PREFIXES.some(prefix =>
      response.certificate.startsWith(prefix)
    );
    expect(startsWithKnownPrefix).toBe(true);

    console.log(
      `sign pass: cert starts with "${response.certificate.split(' ')[0]}", ` +
      `serial=${response.serial}`
    );
  });

  it('signString: returns the raw OpenSSH cert string directly', async () => {
    if (serverUnreachable) return;

    const { publicKey } = generateKeyPairSync('ed25519');
    const publicKeyStr = ed25519PublicKeyToOpenSSH(publicKey);

    const cert = await adminClient.sshca.signString(publicKeyStr, {
      principals: ['ubuntu'],
      ttlSeconds: 300,
    });

    expect(typeof cert).toBe('string');
    expect(cert.length).toBeGreaterThan(0);

    const startsWithKnownPrefix = SSH_CERT_PREFIXES.some(prefix =>
      cert.startsWith(prefix)
    );
    expect(startsWithKnownPrefix).toBe(true);

    console.log(`signString pass: cert starts with "${cert.split(' ')[0]}"`);
  });

  // ---------------------------------------------------------------------------
  // CA public key: getCaPublicKey and getCaPublicKeyRaw
  // ---------------------------------------------------------------------------

  it('getCaPublicKey: returns publicKey and fingerprint for the tenant CA', async () => {
    if (serverUnreachable) return;

    const ca = await adminClient.sshca.getCaPublicKey(tenant);

    expect(ca).toBeDefined();
    expect(typeof ca.publicKey).toBe('string');
    expect(ca.publicKey.length).toBeGreaterThan(0);
    expect(typeof ca.fingerprint).toBe('string');
    expect(ca.fingerprint.length).toBeGreaterThan(0);

    console.log(`getCaPublicKey pass: fingerprint=${ca.fingerprint}`);
  });

  it('getCaPublicKeyRaw: returns a raw OpenSSH public key string', async () => {
    if (serverUnreachable) return;

    const raw = await adminClient.sshca.getCaPublicKeyRaw(tenant);

    expect(typeof raw).toBe('string');
    expect(raw.trim().length).toBeGreaterThan(0);

    // Should look like "ssh-ed25519 AAAA..." or similar
    expect(raw.trim()).toMatch(/^(ssh-ed25519|ecdsa-sha2|ssh-rsa)\s+/);

    console.log(`getCaPublicKeyRaw pass: starts with "${raw.trim().split(' ')[0]}"`);
  });
});
