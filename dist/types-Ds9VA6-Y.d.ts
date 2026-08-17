type ImpersonationMode = 'READ_ONLY' | 'FULL' | 'BREAK_GLASS';
interface ImpersonationClaims {
    workspaceId: string;
    adminUserId: string;
    adminEmail: string;
    mode: ImpersonationMode;
}
interface ImpersonationContext extends ImpersonationClaims {
    isImpersonating: true;
}
interface AuthUser {
    id: string;
    email: string;
    name: string | null;
    locale: string | null;
}
interface ProductRole {
    productId: string;
    slug: string;
    name: string;
}
interface WorkspaceMembership {
    workspaceId: string;
    workspaceSlug: string;
    workspaceName: string;
    role: string;
    status: string;
    productRoles: ProductRole[];
}
interface AuthSession {
    user: AuthUser;
    memberships: WorkspaceMembership[];
    activeWorkspaceId?: string | null;
    role?: string | null;
    isImpersonating: boolean;
}
interface HqAuthzDecision {
    allowed: boolean;
    permissions: string[];
    reason?: string;
    locale?: string | null;
}
interface ApiKeyAuthResult {
    valid: boolean;
    tenantId?: string;
    organizationId?: string;
    keyType?: string;
    scopes: string[];
    reason?: string;
}

export type { ApiKeyAuthResult as A, HqAuthzDecision as H, ImpersonationClaims as I, AuthSession as a, AuthUser as b, ImpersonationContext as c, ImpersonationMode as d };
