// src/impersonation/index.ts
import { SignJWT, jwtVerify } from "jose";
var IMPERSONATION_COOKIE = "mk_impersonation_token";
var IMPERSONATION_TARGET_COOKIE = "mk_impersonation_target";
var IMPERSONATION_TARGET_EMAIL_COOKIE = "mk_impersonation_target_email";
var IMPERSONATION_MODE_COOKIE = "mk_impersonation_mode";
var IMPERSONATION_MODES = ["READ_ONLY", "FULL", "BREAK_GLASS"];
var AUDIENCE = "musakonttori-products";
var ISSUER = "musakonttori-accounts";
var TTL_SECONDS = 300;
var COOKIE_MAX_AGE = 3600;
function encodeSecret(secret) {
  return new TextEncoder().encode(secret);
}
async function signImpersonationToken(input) {
  return new SignJWT({
    admin_sub: input.adminUserId,
    admin_email: input.adminEmail,
    mode: input.mode
  }).setProtectedHeader({ alg: "HS256" }).setSubject(input.workspaceId).setIssuer(ISSUER).setAudience(AUDIENCE).setIssuedAt().setExpirationTime(`${input.ttlSeconds ?? TTL_SECONDS}s`).sign(encodeSecret(input.secret));
}
async function verifyImpersonationToken(token, secret) {
  try {
    const { payload } = await jwtVerify(token, encodeSecret(secret), {
      audience: AUDIENCE,
      issuer: ISSUER
    });
    if (typeof payload.sub !== "string") return null;
    const mode = payload.mode;
    const resolvedMode = typeof mode === "string" && IMPERSONATION_MODES.includes(mode) ? mode : "READ_ONLY";
    return {
      workspaceId: payload.sub,
      adminUserId: typeof payload.admin_sub === "string" ? payload.admin_sub : "",
      adminEmail: typeof payload.admin_email === "string" ? payload.admin_email : "",
      mode: resolvedMode
    };
  } catch {
    return null;
  }
}
function cookieOptions() {
  return {
    path: "/",
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: COOKIE_MAX_AGE
  };
}
function impersonationSecret() {
  const secret = process.env.IMPERSONATION_SECRET;
  if (!secret) throw new Error("IMPERSONATION_SECRET not set");
  return secret;
}
async function setImpersonationCookies(store, token, claims) {
  store.set(IMPERSONATION_COOKIE, token, cookieOptions());
  store.set(IMPERSONATION_TARGET_COOKIE, claims.workspaceId, cookieOptions());
  store.set(IMPERSONATION_TARGET_EMAIL_COOKIE, claims.adminEmail, cookieOptions());
  store.set(IMPERSONATION_MODE_COOKIE, claims.mode, cookieOptions());
}
async function getImpersonationFromCookies(store) {
  const token = store.get(IMPERSONATION_COOKIE)?.value;
  if (!token) return null;
  const claims = await verifyImpersonationToken(token, impersonationSecret());
  if (!claims) return null;
  return { ...claims, isImpersonating: true };
}
function clearImpersonationCookies(store) {
  for (const name of [
    IMPERSONATION_COOKIE,
    IMPERSONATION_TARGET_COOKIE,
    IMPERSONATION_TARGET_EMAIL_COOKIE,
    IMPERSONATION_MODE_COOKIE
  ]) {
    store.delete(name);
  }
}

export {
  IMPERSONATION_COOKIE,
  IMPERSONATION_TARGET_COOKIE,
  IMPERSONATION_TARGET_EMAIL_COOKIE,
  IMPERSONATION_MODE_COOKIE,
  IMPERSONATION_MODES,
  signImpersonationToken,
  verifyImpersonationToken,
  setImpersonationCookies,
  getImpersonationFromCookies,
  clearImpersonationCookies
};
//# sourceMappingURL=chunk-QAWPRIVS.js.map