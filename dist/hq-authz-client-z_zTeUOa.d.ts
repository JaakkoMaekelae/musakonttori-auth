import { H as HqAuthzDecision } from './types-Ds9VA6-Y.js';

interface CheckHqAuthzInput {
    clerkUserId: string;
    email?: string | null;
    feature: string;
    action?: string;
    productSlug?: string;
}
declare function getHqClientSecret(clientId: string): string | undefined;
declare function checkHqAuthz(req: CheckHqAuthzInput): Promise<HqAuthzDecision>;
declare function clearHqAuthzCache(): void;
interface CheckCustomerAccessInput {
    email: string;
    productSlug?: string;
}
interface CustomerAccessResult {
    allowed: boolean;
    banned: boolean;
    orgOnHold: boolean;
    blocked: boolean;
    reason?: string;
}
/**
 * Check a customer's moderation status against HQ (single source of truth):
 * banned user, on-hold organization, or blocked product account. Mirrors
 * checkHqAuthz — same HMAC signing, but a GET with an empty body.
 */
declare function checkCustomerAccess(input: CheckCustomerAccessInput): Promise<CustomerAccessResult>;

export { type CheckCustomerAccessInput as C, type CheckHqAuthzInput as a, type CustomerAccessResult as b, checkCustomerAccess as c, checkHqAuthz as d, clearHqAuthzCache as e, getHqClientSecret as g };
