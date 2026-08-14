import { createHash, timingSafeEqual } from 'node:crypto';

import type { ApiKeyAuthResult } from '../types';

export interface ApiKeyRecord {
  keyHash: string;
  tenantId?: string;
  organizationId?: string;
  keyType?: string;
  scopes: string[];
}

export type ApiKeyLookup = (
  prefix: string,
) => Promise<ApiKeyRecord[] | null | undefined>;

export interface VerifyApiKeyOptions {
  hash?: string;
  prefixLength?: number;
  lookup: ApiKeyLookup;
}

export function hashApiKey(key: string, hash = 'sha256'): string {
  return createHash(hash).update(key).digest('hex');
}

function constantTimeEqual(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, 'hex');
  const bBuf = Buffer.from(b, 'hex');
  if (aBuf.length !== bBuf.length) return false;
  return timingSafeEqual(aBuf, bBuf);
}

export async function verifyApiKey(
  key: string,
  options: VerifyApiKeyOptions,
): Promise<ApiKeyAuthResult> {
  const { hash = 'sha256', prefixLength = 12, lookup } = options;

  if (!key) {
    return { valid: false, scopes: [], reason: 'missing_key' };
  }

  const prefix = key.slice(0, prefixLength);
  const keyHash = hashApiKey(key, hash);

  const records = await lookup(prefix);
  if (!records || records.length === 0) {
    return { valid: false, scopes: [], reason: 'unknown_prefix' };
  }

  for (const record of records) {
    if (constantTimeEqual(record.keyHash, keyHash)) {
      return {
        valid: true,
        tenantId: record.tenantId,
        organizationId: record.organizationId,
        keyType: record.keyType,
        scopes: record.scopes,
      };
    }
  }

  return { valid: false, scopes: [], reason: 'hash_mismatch' };
}
