import type { AuthSession } from '../types';
import { type CookieStore } from '../impersonation';
export type { CookieStore } from '../impersonation';
export type ServiceJwtProvider = () => Promise<string> | string;
export interface GetSessionOptions {
    cookieName?: string;
    activeWorkspaceCookieName?: string;
    accountsApiUrl?: string;
    serviceJwtProvider?: ServiceJwtProvider;
    cookieStore?: CookieStore;
}
export declare function defaultServiceJwtProvider(): Promise<string>;
export declare function getSession(options?: GetSessionOptions): Promise<AuthSession | null>;
//# sourceMappingURL=index.d.ts.map