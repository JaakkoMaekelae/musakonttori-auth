import { createHash, createHmac } from "node:crypto";

export const HQ_AUTHZ_REQUEST_PATH = "/api/internal/authz/check";
export const HQ_AUTHZ_SIGNATURE_PATH = "/internal/authz/check";

export interface HqAuthzRequest {
  clerkUserId: string;
  email?: string | null;
  productSlug: string;
  feature: string;
  action?: string;
}

export function splitPermission(feature: string, action?: string): { feature: string; action: string } {
  if (action) return { feature, action };

  const slashIndex = feature.indexOf("/");
  if (slashIndex === -1) return { feature, action: "read" };

  return {
    feature: feature.slice(0, slashIndex),
    action: feature.slice(slashIndex + 1) || "read",
  };
}

export function buildHqAuthzBody(req: HqAuthzRequest): string {
  const permission = splitPermission(req.feature, req.action);

  return JSON.stringify({
    clerkUserId: req.clerkUserId,
    email: req.email ?? null,
    productSlug: req.productSlug,
    feature: permission.feature,
    action: permission.action,
  });
}

export function signHqAuthzRequest({
  method,
  path,
  timestamp,
  nonce,
  body,
  clientSecret,
}: {
  method: string;
  path: string;
  timestamp: string;
  nonce: string;
  body: string;
  clientSecret: string;
}): string {
  const bodyHash = createHash("sha256").update(body).digest("hex");
  const canonical = `${method}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}`;
  return createHmac("sha256", clientSecret).update(canonical).digest("hex");
}
