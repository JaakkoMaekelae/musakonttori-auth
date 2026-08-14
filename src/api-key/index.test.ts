import { describe, expect, it } from 'vitest';

import { hashApiKey, verifyApiKey, type ApiKeyRecord } from './index';

const PREFIX = 'lg_sk_live_';

function makeLookup(records: ApiKeyRecord[]) {
  return async () => records;
}

describe('verifyApiKey', () => {
  it('accepts a key whose full hash matches a stored record', async () => {
    const key = `${PREFIX}abc123secretkey`;
    const record: ApiKeyRecord = {
      keyHash: hashApiKey(key),
      organizationId: 'org_1',
      keyType: 'server',
      scopes: ['events:read'],
    };

    const result = await verifyApiKey(key, { lookup: makeLookup([record]) });

    expect(result.valid).toBe(true);
    expect(result.organizationId).toBe('org_1');
    expect(result.keyType).toBe('server');
    expect(result.scopes).toEqual(['events:read']);
  });

  it('rejects a key on prefix collision (different hash)', async () => {
    const key = `${PREFIX}aaaaaaaaaaaaaaaaaaaaaaaaaa`;
    const otherKey = `${PREFIX}bbbbbbbbbbbbbbbbbbbbbbbbbb`;
    // Both share the same prefix; the stored record belongs to the other key.
    const record: ApiKeyRecord = {
      keyHash: hashApiKey(otherKey),
      tenantId: 'tenant_1',
      keyType: 'server',
      scopes: ['*'],
    };

    const result = await verifyApiKey(key, { lookup: makeLookup([record]) });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('hash_mismatch');
  });

  it('rejects when the lookup returns no records for the prefix', async () => {
    const result = await verifyApiKey(`${PREFIX}zzzzzzzzzzzzzzzzzz`, {
      lookup: async () => null,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('unknown_prefix');
  });

  it('rejects an empty key', async () => {
    const result = await verifyApiKey('', { lookup: makeLookup([]) });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('missing_key');
  });

  it('compares in constant time without throwing on length mismatch', async () => {
    // timingSafeEqual throws if buffers differ in length; the comparison must
    // guard that and return false instead.
    const key = `${PREFIX}cccccccccccccccccccccccc`;
    const record: ApiKeyRecord = {
      keyHash: 'deadbeef', // shorter than a real sha256 digest
      scopes: [],
    };

    const result = await verifyApiKey(key, { lookup: makeLookup([record]) });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('hash_mismatch');
  });

  it('supports a configurable hash algorithm', async () => {
    const key = `${PREFIX}dddddddddddddddddddddddd`;
    const record: ApiKeyRecord = {
      keyHash: hashApiKey(key, 'sha512'),
      scopes: [],
    };

    const result = await verifyApiKey(key, {
      hash: 'sha512',
      lookup: makeLookup([record]),
    });
    expect(result.valid).toBe(true);
  });
});
