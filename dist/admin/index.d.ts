export { C as CheckHqAuthzInput, c as checkHqAuthz, g as getHqClientSecret } from '../hq-authz-client-XmzSD3Yw.js';
import '../types-VQzFiU4K.js';

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
}
/**
 * Resolve whether an admin (Clerk identity) is allowed a given admin action.
 * Admin permissions are the single source of truth in HQ — products never
 * derive admin rights from the accounts customer role.
 */
declare function checkAdminAccess(input: AdminAccessInput): Promise<AdminAccessDecision>;

export { type AdminAccessDecision, type AdminAccessInput, checkAdminAccess };
