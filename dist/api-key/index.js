import { createHash, timingSafeEqual } from 'node:crypto';
export function hashApiKey(key, hash = 'sha256') {
    return createHash(hash).update(key).digest('hex');
}
function constantTimeEqual(a, b) {
    const aBuf = Buffer.from(a, 'hex');
    const bBuf = Buffer.from(b, 'hex');
    if (aBuf.length !== bBuf.length)
        return false;
    return timingSafeEqual(aBuf, bBuf);
}
export async function verifyApiKey(key, options) {
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
//# sourceMappingURL=index.js.map