export type ImpersonationMode = 'READ_ONLY' | 'FULL' | 'BREAK_GLASS';
export interface ImpersonationClaims {
    workspaceId: string;
    adminUserId: string;
    adminEmail: string;
    mode: ImpersonationMode;
}
export interface ImpersonationContext extends ImpersonationClaims {
    isImpersonating: true;
}
export interface AuthUser {
    id: string;
    email: string;
    name: string | null;
}
export interface AuthSession {
    user: AuthUser;
    activeWorkspaceId?: string | null;
    isImpersonating: boolean;
}
export interface HqAuthzDecision {
    allowed: boolean;
    permissions: string[];
    reason?: string;
}
export interface ApiKeyAuthResult {
    valid: boolean;
    tenantId?: string;
    organizationId?: string;
    keyType?: string;
    scopes: string[];
    reason?: string;
}
//# sourceMappingURL=types.d.ts.map