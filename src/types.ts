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
  locale: string | null;
}

export interface ProductRole {
  productId: string;
  slug: string;
  name: string;
}

export interface WorkspaceMembership {
  workspaceId: string;
  workspaceSlug: string;
  workspaceName: string;
  role: string;
  status: string;
  productRoles: ProductRole[];
}

export interface AuthSession {
  user: AuthUser;
  memberships: WorkspaceMembership[];
  activeWorkspaceId?: string | null;
  role?: string | null;
  isImpersonating: boolean;
}

export interface HqAuthzDecision {
  allowed: boolean;
  permissions: string[];
  reason?: string;
  locale?: string | null;
}

export interface ApiKeyAuthResult {
  valid: boolean;
  tenantId?: string;
  organizationId?: string;
  keyType?: string;
  scopes: string[];
  reason?: string;
}
