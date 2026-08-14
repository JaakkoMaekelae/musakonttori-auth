import { A as ApiKeyAuthResult } from '../types-VQzFiU4K.js';

interface ApiKeyRecord {
    keyHash: string;
    tenantId?: string;
    organizationId?: string;
    keyType?: string;
    scopes: string[];
}
type ApiKeyLookup = (prefix: string) => Promise<ApiKeyRecord[] | null | undefined>;
interface VerifyApiKeyOptions {
    hash?: string;
    prefixLength?: number;
    lookup: ApiKeyLookup;
}
declare function hashApiKey(key: string, hash?: string): string;
declare function verifyApiKey(key: string, options: VerifyApiKeyOptions): Promise<ApiKeyAuthResult>;

export { type ApiKeyLookup, type ApiKeyRecord, type VerifyApiKeyOptions, hashApiKey, verifyApiKey };
