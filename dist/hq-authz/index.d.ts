export { C as CheckCustomerAccessInput, a as CheckHqAuthzInput, b as CustomerAccessResult, c as checkCustomerAccess, d as checkHqAuthz, g as getHqClientSecret } from '../hq-authz-client-DozmUbot.js';
import '../types-Ds9VA6-Y.js';

declare const HQ_AUTHZ_REQUEST_PATH = "/api/internal/authz/check";
declare const HQ_AUTHZ_SIGNATURE_PATH = "/internal/authz/check";
interface HqAuthzRequest {
    clerkUserId: string;
    email?: string | null;
    productSlug: string;
    feature: string;
    action?: string;
}
declare function splitPermission(feature: string, action?: string): {
    feature: string;
    action: string;
};
declare function buildHqAuthzBody(req: HqAuthzRequest): string;
declare function signHqAuthzRequest({ method, path, timestamp, nonce, body, clientSecret, }: {
    method: string;
    path: string;
    timestamp: string;
    nonce: string;
    body: string;
    clientSecret: string;
}): string;

export { HQ_AUTHZ_REQUEST_PATH, HQ_AUTHZ_SIGNATURE_PATH, type HqAuthzRequest, buildHqAuthzBody, signHqAuthzRequest, splitPermission };
