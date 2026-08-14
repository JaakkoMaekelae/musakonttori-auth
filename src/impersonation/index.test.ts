import { SignJWT } from 'jose';
import { afterEach, describe, expect, it } from 'vitest';

import {
  clearImpersonationCookies,
  getImpersonationFromCookies,
  IMPERSONATION_COOKIE,
  IMPERSONATION_MODE_COOKIE,
  IMPERSONATION_TARGET_COOKIE,
  IMPERSONATION_TARGET_EMAIL_COOKIE,
  setImpersonationCookies,
  signImpersonationToken,
  verifyImpersonationToken,
  type CookieStore,
} from './index';

const SECRET = 'test-impersonation-secret';

const CLAIMS = {
  workspaceId: 'ws_123',
  adminUserId: 'user_admin',
  adminEmail: 'admin@musakonttori.fi',
  mode: 'FULL' as const,
};

function makeStore(initial?: Record<string, string>): CookieStore & { values: Map<string, { value: string; options: Record<string, unknown> }> } {
  const values = new Map<string, { value: string; options: Record<string, unknown> }>();
  for (const [name, value] of Object.entries(initial ?? {})) {
    values.set(name, { value, options: {} });
  }
  return {
    values,
    get(name) {
      const entry = values.get(name);
      return entry ? { value: entry.value } : undefined;
    },
    set(name, value, options) {
      values.set(name, { value, options: { ...options } });
    },
    delete(name) {
      values.delete(name);
    },
  };
}

afterEach(() => {
  delete process.env.IMPERSONATION_SECRET;
  delete process.env.NODE_ENV;
});

describe('signImpersonationToken / verifyImpersonationToken', () => {
  it('round-trips sub/admin_sub/admin_email/mode', async () => {
    const token = await signImpersonationToken({ ...CLAIMS, secret: SECRET });
    const claims = await verifyImpersonationToken(token, SECRET);

    expect(claims).not.toBeNull();
    expect(claims?.workspaceId).toBe('ws_123');
    expect(claims?.adminUserId).toBe('user_admin');
    expect(claims?.adminEmail).toBe('admin@musakonttori.fi');
    expect(claims?.mode).toBe('FULL');
  });

  it('rejects a tampered token', async () => {
    const token = await signImpersonationToken({ ...CLAIMS, secret: SECRET });
    const tampered = token.slice(0, -1) + (token.endsWith('a') ? 'b' : 'a');
    await expect(verifyImpersonationToken(tampered, SECRET)).resolves.toBeNull();
  });

  it('rejects a token signed with the wrong secret', async () => {
    const token = await signImpersonationToken({ ...CLAIMS, secret: SECRET });
    await expect(
      verifyImpersonationToken(token, 'wrong-secret'),
    ).resolves.toBeNull();
  });

  it('rejects an expired token', async () => {
    const expired = await new SignJWT({
      admin_sub: CLAIMS.adminUserId,
      admin_email: CLAIMS.adminEmail,
      mode: CLAIMS.mode,
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject(CLAIMS.workspaceId)
      .setIssuer('musakonttori-accounts')
      .setAudience('musakonttori-products')
      .setIssuedAt()
      .setExpirationTime('-1s')
      .sign(new TextEncoder().encode(SECRET));

    await expect(verifyImpersonationToken(expired, SECRET)).resolves.toBeNull();
  });
});

describe('impersonation cookies', () => {
  it('setImpersonationCookies writes the four-cookie set with correct attributes', async () => {
    const store = makeStore();
    const token = await signImpersonationToken({ ...CLAIMS, secret: SECRET });

    await setImpersonationCookies(store, token, CLAIMS);

    expect(store.get(IMPERSONATION_COOKIE)?.value).toBe(token);
    expect(store.get(IMPERSONATION_TARGET_COOKIE)?.value).toBe('ws_123');
    expect(store.get(IMPERSONATION_TARGET_EMAIL_COOKIE)?.value).toBe(
      'admin@musakonttori.fi',
    );
    expect(store.get(IMPERSONATION_MODE_COOKIE)?.value).toBe('FULL');

    const opts = store.values.get(IMPERSONATION_COOKIE)?.options;
    expect(opts).toMatchObject({
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 3600,
    });
  });

  it('getImpersonationFromCookies reads and verifies the token cookie', async () => {
    process.env.IMPERSONATION_SECRET = SECRET;
    const token = await signImpersonationToken({ ...CLAIMS, secret: SECRET });
    const store = makeStore({ [IMPERSONATION_COOKIE]: token });

    const ctx = await getImpersonationFromCookies(store);

    expect(ctx).not.toBeNull();
    expect(ctx?.isImpersonating).toBe(true);
    expect(ctx?.workspaceId).toBe('ws_123');
  });

  it('getImpersonationFromCookies returns null when no cookie is present', async () => {
    process.env.IMPERSONATION_SECRET = SECRET;
    const store = makeStore();

    await expect(getImpersonationFromCookies(store)).resolves.toBeNull();
  });

  it('clearImpersonationCookies removes the whole set', async () => {
    const store = makeStore({
      [IMPERSONATION_COOKIE]: 't',
      [IMPERSONATION_TARGET_COOKIE]: 'ws',
      [IMPERSONATION_TARGET_EMAIL_COOKIE]: 'e',
      [IMPERSONATION_MODE_COOKIE]: 'm',
    });

    clearImpersonationCookies(store);

    expect(store.values.size).toBe(0);
  });
});
