// Path: zn-vault-sdk-node/src/http/body.ts
import { Buffer } from 'node:buffer';

/** Concatenate response chunks into a single Buffer without lossy string coercion. */
export function accumulate(chunks: Buffer[]): Buffer {
  return Buffer.concat(chunks);
}
