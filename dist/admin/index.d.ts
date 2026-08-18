export { a as CheckHqAuthzInput, d as checkHqAuthz, g as getHqClientSecret } from '../hq-authz-client-DozmUbot.js';
import '../types-Ds9VA6-Y.js';

interface AdminAccessInput {
    clerkUserId: string;
    email?: string | null;
    feature?: string;
    action?: string;
    productSlug?: string;
}
interface AdminAccessDecision {
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
declare function checkAdminAccess(input: AdminAccessInput): Promise<AdminAccessDecision>;
/**
 * Fetch the default language (locale) for a Clerk admin user from HQ.
 * Returns null for non-admins / unknown users.
 */
declare function getAdminLocale(clerkUserId: string): Promise<string | null>;

export { type AdminAccessDecision, type AdminAccessInput, checkAdminAccess, getAdminLocale };
