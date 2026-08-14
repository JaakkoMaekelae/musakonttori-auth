import type { ApiKeyAuthResult } from '../types';
export interface ApiKeyRecord {
    keyHash: string;
    tenantId?: string;
    organizationId?: string;
    keyType?: string;
    scopes: string[];
}
export type ApiKeyLookup = (prefix: string) => Promise<ApiKeyRecord[] | null | undefined>;
export interface VerifyApiKeyOptions {
    hash?: string;
    prefixLength?: number;
    lookup: ApiKeyLookup;
}
export declare function hashApiKey(key: string, hash?: string): string;
export declare function verifyApiKey(key: string, options: VerifyApiKeyOptions): Promise<ApiKeyAuthResult>;
//# sourceMappingURL=index.d.ts.map