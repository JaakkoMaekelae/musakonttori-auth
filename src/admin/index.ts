import { checkHqAuthz } from '../hq-authz/hq-authz-client';

export { checkHqAuthz, getHqClientSecret } from '../hq-authz/hq-authz-client';
export type { CheckHqAuthzInput } from '../hq-authz/hq-authz-client';

export interface AdminAccessInput {
  clerkUserId: string;
  email?: string | null;
  feature?: string;
  action?: string;
  productSlug?: string;
}

export interface AdminAccessDecision {
  isAdmin: boolean;
  permissions: string[];
  reason?: string;
  locale?: string | null;
}

/**
 * Resolve whether an admin (Clerk identity) is allowed a given admin action.
 * Admin permissions are the single source of truth in HQ — products never
 * derive admin rights from the accounts customer role.
 */
export async function checkAdminAccess(
  input: AdminAccessInput,
): Promise<AdminAccessDecision> {
  const decision = await checkHqAuthz({
    clerkUserId: input.clerkUserId,
    email: input.email,
    feature: input.feature ?? 'admin_access',
    action: input.action ?? 'read',
    productSlug: input.productSlug,
  });

  return {
    isAdmin: decision.allowed,
    permissions: decision.permissions,
    reason: decision.reason,
    locale: decision.locale,
  };
}

/**
 * Fetch the default language (locale) for a Clerk admin user from HQ.
 * Returns null for non-admins / unknown users.
 */
export async function getAdminLocale(
  clerkUserId: string,
): Promise<string | null> {
  const decision = await checkHqAuthz({
    clerkUserId,
    feature: 'locale',
    action: 'read',
  });
  return decision.locale ?? null;
}
