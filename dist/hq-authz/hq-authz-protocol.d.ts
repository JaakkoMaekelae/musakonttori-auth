export declare const HQ_AUTHZ_REQUEST_PATH = "/api/internal/authz/check";
export declare const HQ_AUTHZ_SIGNATURE_PATH = "/internal/authz/check";
export interface HqAuthzRequest {
    clerkUserId: string;
    email?: string | null;
    productSlug: string;
    feature: string;
    action?: string;
}
export declare function splitPermission(feature: string, action?: string): {
    feature: string;
    action: string;
};
export declare function buildHqAuthzBody(req: HqAuthzRequest): string;
export declare function signHqAuthzRequest({ method, path, timestamp, nonce, body, clientSecret, }: {
    method: string;
    path: string;
    timestamp: string;
    nonce: string;
    body: string;
    clientSecret: string;
}): string;
//# sourceMappingURL=hq-authz-protocol.d.ts.map