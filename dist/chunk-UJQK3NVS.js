// src/hq-authz/hq-authz-protocol.ts
import { createHash, createHmac } from "crypto";
var HQ_AUTHZ_REQUEST_PATH = "/api/internal/authz/check";
var HQ_AUTHZ_SIGNATURE_PATH = "/internal/authz/check";
function splitPermission(feature, action) {
  if (action) return { feature, action };
  const slashIndex = feature.indexOf("/");
  if (slashIndex === -1) return { feature, action: "read" };
  return {
    feature: feature.slice(0, slashIndex),
    action: feature.slice(slashIndex + 1) || "read"
  };
}
function buildHqAuthzBody(req) {
  const permission = splitPermission(req.feature, req.action);
  return JSON.stringify({
    clerkUserId: req.clerkUserId,
    email: req.email ?? null,
    productSlug: req.productSlug,
    feature: permission.feature,
    action: permission.action
  });
}
function signHqAuthzRequest({
  method,
  path,
  timestamp,
  nonce,
  body,
  clientSecret
}) {
  const bodyHash = createHash("sha256").update(body).digest("hex");
  const canonical = `${method}
${path}
${timestamp}
${nonce}
${bodyHash}`;
  return createHmac("sha256", clientSecret).update(canonical).digest("hex");
}

// src/hq-authz/hq-authz-client.ts
import { randomUUID } from "crypto";
var DEFAULT_HQ_BASE_URL = "https://hq.musakonttori.fi";
var DEFAULT_TIMEOUT_MS = 1e4;
function getHqClientSecret(clientId) {
  const singleSecret = process.env.HQ_CLIENT_SECRET?.trim();
  if (singleSecret) return singleSecret;
  const secretLine = process.env.HQ_CLIENT_SECRETS?.split(/\r?\n/).find(
    (line) => line.trim().startsWith(`${clientId}:`)
  );
  return secretLine?.split(":").slice(1).join(":").trim() || void 0;
}
function getHqBaseUrl() {
  return process.env.HQ_BASE_URL || process.env.NEXT_PUBLIC_HQ_BASE_URL || DEFAULT_HQ_BASE_URL;
}
function getHqTimeoutMs() {
  const raw = Number(process.env.HQ_TIMEOUT_MS);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_TIMEOUT_MS;
}
async function checkHqAuthz(req) {
  const productSlug = req.productSlug ?? process.env.PRODUCT_SLUG;
  if (!productSlug) {
    return { allowed: false, permissions: [], reason: "missing_product_slug" };
  }
  const clientId = process.env.HQ_CLIENT_ID ?? "hq-primary";
  const clientSecret = getHqClientSecret(clientId);
  if (!clientSecret) {
    return { allowed: false, permissions: [], reason: "missing_hq_client_secret" };
  }
  const url = new URL(HQ_AUTHZ_REQUEST_PATH, getHqBaseUrl()).toString();
  const body = buildHqAuthzBody({
    clerkUserId: req.clerkUserId,
    email: req.email,
    productSlug,
    feature: req.feature,
    action: req.action
  });
  const timestamp = Math.floor(Date.now() / 1e3).toString();
  const nonce = randomUUID();
  const signature = signHqAuthzRequest({
    method: "POST",
    path: HQ_AUTHZ_SIGNATURE_PATH,
    timestamp,
    nonce,
    body,
    clientSecret
  });
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-HQ-Client-Id": clientId,
        "X-HQ-Timestamp": timestamp,
        "X-HQ-Nonce": nonce,
        "X-HQ-Signature": signature,
        "X-HQ-Signature-Version": "v1"
      },
      body,
      // musakonttori-hq cold starts + network from local dev regularly take
      // 3-5s (observed in practice) — a too-short timeout intermittently trips
      // and silently bounces signed-in admins (requireSession has no other
      // fallback once this call fails). Default 10s leaves margin; products
      // can tune via HQ_TIMEOUT_MS.
      signal: AbortSignal.timeout(getHqTimeoutMs())
    });
    if (!res.ok) {
      console.error(`[hq-authz] request failed: hq_http_${res.status}`, { feature: req.feature, action: req.action });
      return { allowed: false, permissions: [], reason: `hq_http_${res.status}` };
    }
    const wire = await res.json();
    return {
      allowed: wire.allowed,
      permissions: wire.permissions ?? [],
      reason: wire.reason,
      locale: wire.locale ?? null
    };
  } catch (err) {
    const reason = err instanceof Error && err.name === "TimeoutError" ? "hq_timeout" : "hq_unreachable";
    console.error(`[hq-authz] request failed: ${reason}`, { feature: req.feature, action: req.action, err });
    return { allowed: false, permissions: [], reason };
  }
}
var HQ_CUSTOMER_ACCESS_PATH = "/internal/customer-access";
async function checkCustomerAccess(input) {
  const productSlug = input.productSlug ?? process.env.PRODUCT_SLUG;
  if (!productSlug) {
    return { allowed: false, banned: false, orgOnHold: false, blocked: false, reason: "missing_product_slug" };
  }
  const clientId = process.env.HQ_CLIENT_ID ?? "hq-primary";
  const clientSecret = getHqClientSecret(clientId);
  if (!clientSecret) {
    return { allowed: false, banned: false, orgOnHold: false, blocked: false, reason: "missing_hq_client_secret" };
  }
  const path = `${HQ_CUSTOMER_ACCESS_PATH}?userId=${input.userId}&productSlug=${productSlug}`;
  const timestamp = Math.floor(Date.now() / 1e3).toString();
  const nonce = randomUUID();
  const signature = signHqAuthzRequest({
    method: "GET",
    path,
    timestamp,
    nonce,
    body: "",
    clientSecret
  });
  try {
    const url = new URL(
      `/api${path}`,
      getHqBaseUrl()
    ).toString();
    const res = await fetch(url, {
      method: "GET",
      headers: {
        "X-HQ-Client-Id": clientId,
        "X-HQ-Timestamp": timestamp,
        "X-HQ-Nonce": nonce,
        "X-HQ-Signature": signature
      },
      signal: AbortSignal.timeout(getHqTimeoutMs())
    });
    if (!res.ok) {
      return { allowed: false, banned: false, orgOnHold: false, blocked: false, reason: `hq_http_${res.status}` };
    }
    const wire = await res.json();
    const banned = Boolean(wire.banned);
    const orgOnHold = Boolean(wire.orgOnHold);
    const blocked = Boolean(wire.blocked);
    return { allowed: !banned && !orgOnHold && !blocked, banned, orgOnHold, blocked };
  } catch (err) {
    const reason = err instanceof Error && err.name === "TimeoutError" ? "hq_timeout" : "hq_unreachable";
    return { allowed: false, banned: false, orgOnHold: false, blocked: false, reason };
  }
}

export {
  HQ_AUTHZ_REQUEST_PATH,
  HQ_AUTHZ_SIGNATURE_PATH,
  splitPermission,
  buildHqAuthzBody,
  signHqAuthzRequest,
  getHqClientSecret,
  checkHqAuthz,
  checkCustomerAccess
};
//# sourceMappingURL=chunk-UJQK3NVS.js.map