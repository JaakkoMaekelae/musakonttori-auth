import { SignJWT, importPKCS8 } from 'jose';

import type {
  AuthSession,
  ImpersonationContext,
  WorkspaceMembership,
} from '../types';
import { getImpersonationFromCookies, type CookieStore } from '../impersonation';

export type { CookieStore } from '../impersonation';

const ACCOUNTS_ISSUER = 'accounts.musakonttori.fi';
const SERVICE_EXPIRY = '5m';
const ACTIVE_WORKSPACE_COOKIE = 'mk_active_workspace';
const DEFAULT_SESSION_COOKIE = 'mk-session';

export type ServiceJwtProvider = () => Promise<string> | string;

export interface GetSessionOptions {
  cookieName?: string;
  activeWorkspaceCookieName?: string;
  accountsApiUrl?: string;
  serviceJwtProvider?: ServiceJwtProvider;
  cookieStore?: CookieStore;
}

interface MeResponse {
  id: string;
  email: string;
  name: string | null;
  locale?: string | null;
  memberships?: WorkspaceMembership[];
}

export async function defaultServiceJwtProvider(): Promise<string> {
  const privateKey = process.env.SERVICE_JWT_PRIVATE_KEY;
  if (!privateKey) throw new Error('SERVICE_JWT_PRIVATE_KEY not set');
  const serviceName = process.env.ACCOUNTS_SERVICE_NAME ?? 'musakonttori-products';
  const key = await importPKCS8(privateKey, 'RS256');
  return new SignJWT({ sub: serviceName })
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuedAt()
    .setExpirationTime(SERVICE_EXPIRY)
    .setIssuer(serviceName)
    .setAudience(ACCOUNTS_ISSUER)
    .sign(key);
}

export async function getSession(
  options: GetSessionOptions = {},
): Promise<AuthSession | null> {
  const store = options.cookieStore;
  if (!store) throw new Error('getSession requires a cookieStore');

  const cookieName =
    options.cookieName ?? process.env.ACCOUNTS_SESSION_COOKIE ?? DEFAULT_SESSION_COOKIE;
  const token = store.get(cookieName)?.value;
  if (!token) return null;

  const accountsApiUrl = (
    options.accountsApiUrl ?? process.env.ACCOUNTS_API_URL ?? ''
  ).replace(/\/+$/, '');

  const serviceJwtProvider = options.serviceJwtProvider ?? defaultServiceJwtProvider;

  const activeWorkspaceCookieName =
    options.activeWorkspaceCookieName ?? ACTIVE_WORKSPACE_COOKIE;
  const activeWorkspaceCookieValue = store.get(activeWorkspaceCookieName)?.value ?? null;

  const impersonation: ImpersonationContext | null =
    await getImpersonationFromCookies(store);

  try {
    const serviceToken = await serviceJwtProvider();
    const res = await fetch(`${accountsApiUrl}/api/me`, {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${serviceToken}`,
        'X-User-Token': `Bearer ${token}`,
      },
    });

    if (!res.ok) return null;

    const me = (await res.json()) as MeResponse;
    const memberships = (me.memberships ?? []).filter(
      (m) => m.status === 'active',
    );

    const activeWorkspaceId =
      impersonation?.workspaceId ??
      activeWorkspaceCookieValue ??
      memberships[0]?.workspaceId ??
      null;

    const activeMembership =
      memberships.find((m) => m.workspaceId === activeWorkspaceId) ??
      memberships[0] ??
      null;

    return {
      user: {
        id: me.id,
        email: me.email,
        name: me.name ?? null,
        locale: me.locale ?? null,
      },
      memberships,
      activeWorkspaceId,
      role: activeMembership?.role ?? null,
      isImpersonating: impersonation !== null,
    };
  } catch {
    return null;
  }
}
