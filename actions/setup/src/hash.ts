import { createHash } from 'node:crypto';

import { SetupError } from './errors.js';

export const SHA256_PATTERN = /^[0-9a-f]{64}$/;

export function normalizeTrustedSha256(value: string): string | undefined {
  if (value.length === 0) {
    return undefined;
  }
  if (value !== value.trim() || !/^[0-9A-Fa-f]{64}$/.test(value)) {
    throw new SetupError('sha256 must be exactly 64 hexadecimal characters');
  }
  return value.toLowerCase();
}

export function sha256Bytes(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}
