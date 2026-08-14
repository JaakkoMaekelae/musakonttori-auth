import { H as HqAuthzDecision } from '../types-VQzFiU4K.js';

interface CheckHqAuthzInput {
    clerkUserId: string;
    email?: string | null;
    feature: string;
    action?: string;
    productSlug?: string;
}
declare function getHqClientSecret(clientId: string): string | undefined;
declare function checkHqAuthz(req: CheckHqAuthzInput): Promise<HqAuthzDecision>;

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

export { type CheckHqAuthzInput, HQ_AUTHZ_REQUEST_PATH, HQ_AUTHZ_SIGNATURE_PATH, type HqAuthzRequest, buildHqAuthzBody, checkHqAuthz, getHqClientSecret, signHqAuthzRequest, splitPermission };
