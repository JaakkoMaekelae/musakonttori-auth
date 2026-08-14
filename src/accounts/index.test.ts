import { afterEach, describe, expect, it, vi } from 'vitest';

import { getSession, type CookieStore } from './index';

function makeStore(initial?: Record<string, string>): CookieStore {
  const values = new Map<string, string>(Object.entries(initial ?? {}));
  return {
    get(name: string) {
      const value = values.get(name);
      return value === undefined ? undefined : { value };
    },
    set(name: string, value: string) {
      values.set(name, value);
    },
    delete(name: string) {
      values.delete(name);
    },
  };
}

interface FetchCall {
  url: string;
  headers: Record<string, string>;
}

function stubFetch(body: unknown, status = 200): FetchCall[] {
  const calls: FetchCall[] = [];
  vi.stubGlobal(
    'fetch',
    (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      calls.push({ url: String(input), headers });
      return Promise.resolve(new Response(JSON.stringify(body), { status }));
    },
  );
  return calls;
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.ACCOUNTS_API_URL;
  delete process.env.ACCOUNTS_SESSION_COOKIE;
  delete process.env.IMPERSONATION_SECRET;
});

describe('getSession', () => {
  it('resolves a normalized session from /api/me', async () => {
    const calls = stubFetch({
      id: 'user_1',
      email: 'anna@musakonttori.fi',
      name: 'Anna Artist',
    });

    const session = await getSession({
      accountsApiUrl: 'https://accounts.example.com/',
      serviceJwtProvider: async () => 'service-jwt',
      cookieStore: makeStore({ 'mk-session': 'user-jwt' }),
    });

    expect(session).not.toBeNull();
    expect(session?.user).toEqual({
      id: 'user_1',
      email: 'anna@musakonttori.fi',
      name: 'Anna Artist',
    });
    expect(session?.isImpersonating).toBe(false);
    expect(session?.activeWorkspaceId).toBeNull();

    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe('https://accounts.example.com/api/me');
    expect(calls[0]?.headers).toMatchObject({
      Authorization: 'Bearer service-jwt',
      'X-User-Token': 'Bearer user-jwt',
    });
  });

  it('returns null when the session cookie is missing', async () => {
    const calls = stubFetch({});

    const session = await getSession({
      accountsApiUrl: 'https://accounts.example.com',
      serviceJwtProvider: async () => 'service-jwt',
      cookieStore: makeStore(),
    });

    expect(session).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it('returns null when /api/me responds with an error', async () => {
    stubFetch(null, 401);

    const session = await getSession({
      accountsApiUrl: 'https://accounts.example.com',
      serviceJwtProvider: async () => 'service-jwt',
      cookieStore: makeStore({ 'mk-session': 'user-jwt' }),
    });

    expect(session).toBeNull();
  });

  it('passes through the active-workspace cookie', async () => {
    stubFetch({ id: 'user_1', email: 'a@b.fi', name: null });

    const session = await getSession({
      accountsApiUrl: 'https://accounts.example.com',
      serviceJwtProvider: async () => 'service-jwt',
      cookieStore: makeStore({
        'mk-session': 'user-jwt',
        mk_active_workspace: 'ws_active',
      }),
    });

    expect(session?.activeWorkspaceId).toBe('ws_active');
  });
});
