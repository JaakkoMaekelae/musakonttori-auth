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

export { type CheckHqAuthzInput as C, checkHqAuthz as c, getHqClientSecret as g };
