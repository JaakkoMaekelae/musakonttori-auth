import { randomUUID } from "node:crypto";

import {
  buildHqAuthzBody,
  HQ_AUTHZ_REQUEST_PATH,
  HQ_AUTHZ_SIGNATURE_PATH,
  signHqAuthzRequest,
} from "./hq-authz-protocol";
import type { HqAuthzDecision } from "../types";

export interface CheckHqAuthzInput {
  clerkUserId: string;
  email?: string | null;
  feature: string;
  action?: string;
  productSlug?: string;
}

interface HqAuthzWireResponse {
  allowed: boolean;
  permissions?: string[];
  locale?: string | null;
  clerk_user_id?: string;
  product_slug?: string;
  role?: string | null;
  reason?: string;
}

const DEFAULT_HQ_BASE_URL = "https://hq.musakonttori.fi";
const DEFAULT_TIMEOUT_MS = 10000;

export function getHqClientSecret(clientId: string): string | undefined {
  const singleSecret = process.env.HQ_CLIENT_SECRET?.trim();
  if (singleSecret) return singleSecret;

  const secretLine = process.env.HQ_CLIENT_SECRETS?.split(/\r?\n/).find((line) =>
    line.trim().startsWith(`${clientId}:`),
  );

  return secretLine?.split(":").slice(1).join(":").trim() || undefined;
}

function getHqBaseUrl(): string {
  return (
    process.env.HQ_BASE_URL ||
    process.env.NEXT_PUBLIC_HQ_BASE_URL ||
    DEFAULT_HQ_BASE_URL
  );
}

function getHqTimeoutMs(): number {
  const raw = Number(process.env.HQ_TIMEOUT_MS);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_TIMEOUT_MS;
}

export async function checkHqAuthz(
  req: CheckHqAuthzInput,
): Promise<HqAuthzDecision> {
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
    action: req.action,
  });
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomUUID();
  const signature = signHqAuthzRequest({
    method: "POST",
    path: HQ_AUTHZ_SIGNATURE_PATH,
    timestamp,
    nonce,
    body,
    clientSecret,
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
        "X-HQ-Signature-Version": "v1",
      },
      body,
      // musakonttori-hq cold starts + network from local dev regularly take
      // 3-5s (observed in practice) — a too-short timeout intermittently trips
      // and silently bounces signed-in admins (requireSession has no other
      // fallback once this call fails). Default 10s leaves margin; products
      // can tune via HQ_TIMEOUT_MS.
      signal: AbortSignal.timeout(getHqTimeoutMs()),
    });

    if (!res.ok) {
      console.error(`[hq-authz] request failed: hq_http_${res.status}`, { feature: req.feature, action: req.action });
      return { allowed: false, permissions: [], reason: `hq_http_${res.status}` };
    }

    const wire = (await res.json()) as HqAuthzWireResponse;
    return {
      allowed: wire.allowed,
      permissions: wire.permissions ?? [],
      reason: wire.reason,
      locale: wire.locale ?? null,
    };
  } catch (err) {
    const reason = err instanceof Error && err.name === "TimeoutError" ? "hq_timeout" : "hq_unreachable";
    console.error(`[hq-authz] request failed: ${reason}`, { feature: req.feature, action: req.action, err });
    return { allowed: false, permissions: [], reason };
  }
}

export interface CheckCustomerAccessInput {
  userId: string;
  productSlug?: string;
}

export interface CustomerAccessResult {
  allowed: boolean;
  banned: boolean;
  orgOnHold: boolean;
  blocked: boolean;
  reason?: string;
}

const HQ_CUSTOMER_ACCESS_PATH = "/internal/customer-access";

/**
 * Check a customer's moderation status against HQ (single source of truth):
 * banned user, on-hold organization, or blocked product account. Mirrors
 * checkHqAuthz — same HMAC signing, but a GET with an empty body.
 */
export async function checkCustomerAccess(
  input: CheckCustomerAccessInput,
): Promise<CustomerAccessResult> {
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
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomUUID();
  const signature = signHqAuthzRequest({
    method: "GET",
    path,
    timestamp,
    nonce,
    body: "",
    clientSecret,
  });

  try {
    const url = new URL(
      `/api${path}`,
      getHqBaseUrl(),
    ).toString();
    const res = await fetch(url, {
      method: "GET",
      headers: {
        "X-HQ-Client-Id": clientId,
        "X-HQ-Timestamp": timestamp,
        "X-HQ-Nonce": nonce,
        "X-HQ-Signature": signature,
      },
      signal: AbortSignal.timeout(getHqTimeoutMs()),
    });

    if (!res.ok) {
      return { allowed: false, banned: false, orgOnHold: false, blocked: false, reason: `hq_http_${res.status}` };
    }

    const wire = (await res.json()) as { banned: boolean; orgOnHold: boolean; blocked: boolean };
    const banned = Boolean(wire.banned);
    const orgOnHold = Boolean(wire.orgOnHold);
    const blocked = Boolean(wire.blocked);
    return { allowed: !banned && !orgOnHold && !blocked, banned, orgOnHold, blocked };
  } catch (err) {
    const reason = err instanceof Error && err.name === "TimeoutError" ? "hq_timeout" : "hq_unreachable";
    return { allowed: false, banned: false, orgOnHold: false, blocked: false, reason };
  }
}
