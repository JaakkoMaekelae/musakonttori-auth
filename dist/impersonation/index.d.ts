import type { ImpersonationClaims, ImpersonationContext, ImpersonationMode } from '../types';
export declare const IMPERSONATION_COOKIE = "mk_impersonation_token";
export declare const IMPERSONATION_TARGET_COOKIE = "mk_impersonation_target";
export declare const IMPERSONATION_TARGET_EMAIL_COOKIE = "mk_impersonation_target_email";
export declare const IMPERSONATION_MODE_COOKIE = "mk_impersonation_mode";
export declare const IMPERSONATION_MODES: readonly ["READ_ONLY", "FULL", "BREAK_GLASS"];
export interface CookieOptions {
    path?: string;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: 'lax' | 'strict' | 'none';
    maxAge?: number;
}
export interface CookieStore {
    get(name: string): {
        value: string;
    } | undefined;
    set(name: string, value: string, options: CookieOptions): void;
    delete(name: string): void;
}
export interface SignImpersonationTokenInput {
    workspaceId: string;
    adminUserId: string;
    adminEmail: string;
    mode: ImpersonationMode;
    secret: string;
}
export declare function signImpersonationToken(input: SignImpersonationTokenInput): Promise<string>;
export declare function verifyImpersonationToken(token: string, secret: string): Promise<ImpersonationClaims | null>;
export declare function setImpersonationCookies(store: CookieStore, token: string, claims: ImpersonationClaims): Promise<void>;
export declare function getImpersonationFromCookies(store: CookieStore): Promise<ImpersonationContext | null>;
export declare function clearImpersonationCookies(store: CookieStore): void;
//# sourceMappingURL=index.d.ts.map