import { SignJWT, jwtVerify } from 'jose';

import type { ImpersonationClaims, ImpersonationContext, ImpersonationMode } from '../types';

export const IMPERSONATION_COOKIE = 'mk_impersonation_token';
export const IMPERSONATION_TARGET_COOKIE = 'mk_impersonation_target';
export const IMPERSONATION_TARGET_EMAIL_COOKIE = 'mk_impersonation_target_email';
export const IMPERSONATION_MODE_COOKIE = 'mk_impersonation_mode';

export const IMPERSONATION_MODES = ['READ_ONLY', 'FULL', 'BREAK_GLASS'] as const;

const AUDIENCE = 'musakonttori-products';
const ISSUER = 'musakonttori-accounts';
const TTL_SECONDS = 300;
const COOKIE_MAX_AGE = 3600;

export interface CookieOptions {
  path?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'lax' | 'strict' | 'none';
  maxAge?: number;
}

export interface CookieStore {
  get(name: string): { value: string } | undefined;
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

function encodeSecret(secret: string): Uint8Array {
  return new TextEncoder().encode(secret);
}

export async function signImpersonationToken(
  input: SignImpersonationTokenInput,
): Promise<string> {
  return new SignJWT({
    admin_sub: input.adminUserId,
    admin_email: input.adminEmail,
    mode: input.mode,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(input.workspaceId)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(`${TTL_SECONDS}s`)
    .sign(encodeSecret(input.secret));
}

export async function verifyImpersonationToken(
  token: string,
  secret: string,
): Promise<ImpersonationClaims | null> {
  try {
    const { payload } = await jwtVerify(token, encodeSecret(secret), {
      audience: AUDIENCE,
      issuer: ISSUER,
    });
    if (typeof payload.sub !== 'string') return null;

    const mode = payload.mode;
    const resolvedMode: ImpersonationMode =
      typeof mode === 'string' && (IMPERSONATION_MODES as readonly string[]).includes(mode)
        ? (mode as ImpersonationMode)
        : 'READ_ONLY';

    return {
      workspaceId: payload.sub,
      adminUserId: typeof payload.admin_sub === 'string' ? payload.admin_sub : '',
      adminEmail: typeof payload.admin_email === 'string' ? payload.admin_email : '',
      mode: resolvedMode,
    };
  } catch {
    return null;
  }
}

function cookieOptions(): CookieOptions {
  return {
    path: '/',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: COOKIE_MAX_AGE,
  };
}

function impersonationSecret(): string {
  const secret = process.env.IMPERSONATION_SECRET;
  if (!secret) throw new Error('IMPERSONATION_SECRET not set');
  return secret;
}

export async function setImpersonationCookies(
  store: CookieStore,
  token: string,
  claims: ImpersonationClaims,
): Promise<void> {
  store.set(IMPERSONATION_COOKIE, token, cookieOptions());
  store.set(IMPERSONATION_TARGET_COOKIE, claims.workspaceId, cookieOptions());
  store.set(IMPERSONATION_TARGET_EMAIL_COOKIE, claims.adminEmail, cookieOptions());
  store.set(IMPERSONATION_MODE_COOKIE, claims.mode, cookieOptions());
}

export async function getImpersonationFromCookies(
  store: CookieStore,
): Promise<ImpersonationContext | null> {
  const token = store.get(IMPERSONATION_COOKIE)?.value;
  if (!token) return null;
  const claims = await verifyImpersonationToken(token, impersonationSecret());
  if (!claims) return null;
  return { ...claims, isImpersonating: true };
}

export function clearImpersonationCookies(store: CookieStore): void {
  for (const name of [
    IMPERSONATION_COOKIE,
    IMPERSONATION_TARGET_COOKIE,
    IMPERSONATION_TARGET_EMAIL_COOKIE,
    IMPERSONATION_MODE_COOKIE,
  ]) {
    store.delete(name);
  }
}
