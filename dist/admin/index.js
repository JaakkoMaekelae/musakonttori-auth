import {
  checkHqAuthz,
  getHqClientSecret
} from "../chunk-S3LTKEPE.js";

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
export {
  checkAdminAccess,
  checkHqAuthz,
  getHqClientSecret
};
//# sourceMappingURL=index.js.map