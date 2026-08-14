import { d as ImpersonationMode, c as ImpersonationContext, I as ImpersonationClaims } from '../types-VQzFiU4K.js';

declare const IMPERSONATION_COOKIE = "mk_impersonation_token";
declare const IMPERSONATION_TARGET_COOKIE = "mk_impersonation_target";
declare const IMPERSONATION_TARGET_EMAIL_COOKIE = "mk_impersonation_target_email";
declare const IMPERSONATION_MODE_COOKIE = "mk_impersonation_mode";
declare const IMPERSONATION_MODES: readonly ["READ_ONLY", "FULL", "BREAK_GLASS"];
interface CookieOptions {
    path?: string;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: 'lax' | 'strict' | 'none';
    maxAge?: number;
}
interface CookieStore {
    get(name: string): {
        value: string;
    } | undefined;
    set(name: string, value: string, options: CookieOptions): void;
    delete(name: string): void;
}
interface SignImpersonationTokenInput {
    workspaceId: string;
    adminUserId: string;
    adminEmail: string;
    mode: ImpersonationMode;
    secret: string;
    ttlSeconds?: number;
}
declare function signImpersonationToken(input: SignImpersonationTokenInput): Promise<string>;
declare function verifyImpersonationToken(token: string, secret: string): Promise<ImpersonationClaims | null>;
declare function setImpersonationCookies(store: CookieStore, token: string, claims: ImpersonationClaims): Promise<void>;
declare function getImpersonationFromCookies(store: CookieStore): Promise<ImpersonationContext | null>;
declare function clearImpersonationCookies(store: CookieStore): void;

export { type CookieOptions, type CookieStore, IMPERSONATION_COOKIE, IMPERSONATION_MODES, IMPERSONATION_MODE_COOKIE, IMPERSONATION_TARGET_COOKIE, IMPERSONATION_TARGET_EMAIL_COOKIE, type SignImpersonationTokenInput, clearImpersonationCookies, getImpersonationFromCookies, setImpersonationCookies, signImpersonationToken, verifyImpersonationToken };
