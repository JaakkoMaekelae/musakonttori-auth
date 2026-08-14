import { SignJWT, jwtVerify } from 'jose';
export const IMPERSONATION_COOKIE = 'mk_impersonation_token';
export const IMPERSONATION_TARGET_COOKIE = 'mk_impersonation_target';
export const IMPERSONATION_TARGET_EMAIL_COOKIE = 'mk_impersonation_target_email';
export const IMPERSONATION_MODE_COOKIE = 'mk_impersonation_mode';
export const IMPERSONATION_MODES = ['READ_ONLY', 'FULL', 'BREAK_GLASS'];
const AUDIENCE = 'musakonttori-products';
const ISSUER = 'musakonttori-accounts';
const TTL_SECONDS = 300;
const COOKIE_MAX_AGE = 3600;
function encodeSecret(secret) {
    return new TextEncoder().encode(secret);
}
export async function signImpersonationToken(input) {
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
export async function verifyImpersonationToken(token, secret) {
    try {
        const { payload } = await jwtVerify(token, encodeSecret(secret), {
            audience: AUDIENCE,
            issuer: ISSUER,
        });
        if (typeof payload.sub !== 'string')
            return null;
        const mode = payload.mode;
        const resolvedMode = typeof mode === 'string' && IMPERSONATION_MODES.includes(mode)
            ? mode
            : 'READ_ONLY';
        return {
            workspaceId: payload.sub,
            adminUserId: typeof payload.admin_sub === 'string' ? payload.admin_sub : '',
            adminEmail: typeof payload.admin_email === 'string' ? payload.admin_email : '',
            mode: resolvedMode,
        };
    }
    catch {
        return null;
    }
}
function cookieOptions() {
    return {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: COOKIE_MAX_AGE,
    };
}
function impersonationSecret() {
    const secret = process.env.IMPERSONATION_SECRET;
    if (!secret)
        throw new Error('IMPERSONATION_SECRET not set');
    return secret;
}
export async function setImpersonationCookies(store, token, claims) {
    store.set(IMPERSONATION_COOKIE, token, cookieOptions());
    store.set(IMPERSONATION_TARGET_COOKIE, claims.workspaceId, cookieOptions());
    store.set(IMPERSONATION_TARGET_EMAIL_COOKIE, claims.adminEmail, cookieOptions());
    store.set(IMPERSONATION_MODE_COOKIE, claims.mode, cookieOptions());
}
export async function getImpersonationFromCookies(store) {
    const token = store.get(IMPERSONATION_COOKIE)?.value;
    if (!token)
        return null;
    const claims = await verifyImpersonationToken(token, impersonationSecret());
    if (!claims)
        return null;
    return { ...claims, isImpersonating: true };
}
export function clearImpersonationCookies(store) {
    for (const name of [
        IMPERSONATION_COOKIE,
        IMPERSONATION_TARGET_COOKIE,
        IMPERSONATION_TARGET_EMAIL_COOKIE,
        IMPERSONATION_MODE_COOKIE,
    ]) {
        store.delete(name);
    }
}
//# sourceMappingURL=index.js.map