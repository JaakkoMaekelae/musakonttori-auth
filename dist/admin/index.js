import {
  checkHqAuthz,
  getHqClientSecret
} from "../chunk-UJQK3NVS.js";

// src/admin/index.ts
async function checkAdminAccess(input) {
  const decision = await checkHqAuthz({
    clerkUserId: input.clerkUserId,
    email: input.email,
    feature: input.feature ?? "admin_access",
    action: input.action ?? "read",
    productSlug: input.productSlug
  });
  return {
    isAdmin: decision.allowed,
    permissions: decision.permissions,
    reason: decision.reason,
    locale: decision.locale
  };
}
async function getAdminLocale(clerkUserId) {
  const decision = await checkHqAuthz({
    clerkUserId,
    feature: "locale",
    action: "read"
  });
  return decision.locale ?? null;
}
export {
  checkAdminAccess,
  checkHqAuthz,
  getAdminLocale,
  getHqClientSecret
};
//# sourceMappingURL=index.js.map