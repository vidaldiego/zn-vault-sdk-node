import { ZnVaultClient, GenerateKeypairRequest, PublicKeyInfo, PublishResult } from './src/index.js';

// This file tests that all new types and methods are properly exported and type-safe
const client = ZnVaultClient.create('https://localhost:8443');

// Test generateKeypair types
const keypairRequest: GenerateKeypairRequest = {
  algorithm: 'Ed25519',
  alias: 'test/key',
  tenant: 'acme',
  publishPublicKey: true,
  tags: ['test']
};

// Test method signatures (type checking only)
async function testMethods() {
  // Generate keypair
  const keypair = await client.secrets.generateKeypair(keypairRequest);
  const privateKeyId: string = keypair.privateKey.id;
  const publicKeyPem: string = keypair.publicKey.publicKeyPem;
  
  // Publish
  const publishResult: PublishResult = await client.secrets.publish('secret-id');
  const publicUrl: string = publishResult.publicUrl;
  
  // Unpublish
  await client.secrets.unpublish('secret-id');
  
  // Get public key (no auth)
  const publicKey: PublicKeyInfo = await client.secrets.getPublicKey('acme', 'test/key-public');
  const fingerprint: string = publicKey.fingerprint;
  
  // List public keys (no auth)
  const publicKeys = await client.secrets.listPublicKeys('acme');
  const keys: PublicKeyInfo[] = publicKeys.keys;
}

console.log('Type checking passed!');
