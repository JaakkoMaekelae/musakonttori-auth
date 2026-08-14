import type { HqAuthzDecision } from "../types";
export interface CheckHqAuthzInput {
    clerkUserId: string;
    email?: string | null;
    feature: string;
    action?: string;
    productSlug?: string;
}
export declare function getHqClientSecret(clientId: string): string | undefined;
export declare function checkHqAuthz(req: CheckHqAuthzInput): Promise<HqAuthzDecision>;
//# sourceMappingURL=hq-authz-client.d.ts.map