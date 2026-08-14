import {
  getImpersonationFromCookies
} from "./chunk-QAWPRIVS.js";

// src/accounts/index.ts
import { SignJWT, importPKCS8 } from "jose";
var ACCOUNTS_ISSUER = "accounts.musakonttori.fi";
var SERVICE_EXPIRY = "5m";
var ACTIVE_WORKSPACE_COOKIE = "mk_active_workspace";
var DEFAULT_SESSION_COOKIE = "mk-session";
async function defaultServiceJwtProvider() {
  const privateKey = process.env.SERVICE_JWT_PRIVATE_KEY;
  if (!privateKey) throw new Error("SERVICE_JWT_PRIVATE_KEY not set");
  const serviceName = process.env.ACCOUNTS_SERVICE_NAME ?? "musakonttori-products";
  const key = await importPKCS8(privateKey, "RS256");
  return new SignJWT({ sub: serviceName }).setProtectedHeader({ alg: "RS256" }).setIssuedAt().setExpirationTime(SERVICE_EXPIRY).setIssuer(serviceName).setAudience(ACCOUNTS_ISSUER).sign(key);
}
async function getSession(options = {}) {
  const store = options.cookieStore;
  if (!store) throw new Error("getSession requires a cookieStore");
  const cookieName = options.cookieName ?? process.env.ACCOUNTS_SESSION_COOKIE ?? DEFAULT_SESSION_COOKIE;
  const token = store.get(cookieName)?.value;
  if (!token) return null;
  const accountsApiUrl = (options.accountsApiUrl ?? process.env.ACCOUNTS_API_URL ?? "").replace(/\/+$/, "");
  const serviceJwtProvider = options.serviceJwtProvider ?? defaultServiceJwtProvider;
  const activeWorkspaceCookieName = options.activeWorkspaceCookieName ?? ACTIVE_WORKSPACE_COOKIE;
  const activeWorkspaceCookieValue = store.get(activeWorkspaceCookieName)?.value ?? null;
  const impersonation = await getImpersonationFromCookies(store);
  try {
    const serviceToken = await serviceJwtProvider();
    const res = await fetch(`${accountsApiUrl}/api/me`, {
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${serviceToken}`,
        "X-User-Token": `Bearer ${token}`
      }
    });
    if (!res.ok) return null;
    const me = await res.json();
    const memberships = (me.memberships ?? []).filter(
      (m) => m.status === "active"
    );
    const activeWorkspaceId = impersonation?.workspaceId ?? activeWorkspaceCookieValue ?? memberships[0]?.workspaceId ?? null;
    const activeMembership = memberships.find((m) => m.workspaceId === activeWorkspaceId) ?? memberships[0] ?? null;
    return {
      user: { id: me.id, email: me.email, name: me.name ?? null },
      memberships,
      activeWorkspaceId,
      role: activeMembership?.role ?? null,
      isImpersonating: impersonation !== null
    };
  } catch {
    return null;
  }
}

export {
  defaultServiceJwtProvider,
  getSession
};
//# sourceMappingURL=chunk-X6A35YYE.js.map