// Path: zn-vault-sdk-node/test/http-client.test.ts
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
