import { a as AuthSession } from '../types-VQzFiU4K.js';
import { CookieStore } from '../impersonation/index.js';

type ServiceJwtProvider = () => Promise<string> | string;
interface GetSessionOptions {
    cookieName?: string;
    activeWorkspaceCookieName?: string;
    accountsApiUrl?: string;
    serviceJwtProvider?: ServiceJwtProvider;
    cookieStore?: CookieStore;
}
declare function defaultServiceJwtProvider(): Promise<string>;
declare function getSession(options?: GetSessionOptions): Promise<AuthSession | null>;

export { CookieStore, type GetSessionOptions, type ServiceJwtProvider, defaultServiceJwtProvider, getSession };
