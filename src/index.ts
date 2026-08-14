export { checkHqAuthz, getHqClientSecret } from './hq-authz/hq-authz-client';
export type { CheckHqAuthzInput } from './hq-authz/hq-authz-client';
export {
  buildHqAuthzBody,
  HQ_AUTHZ_REQUEST_PATH,
  HQ_AUTHZ_SIGNATURE_PATH,
  signHqAuthzRequest,
  splitPermission,
} from './hq-authz/hq-authz-protocol';
export type { HqAuthzRequest } from './hq-authz/hq-authz-protocol';

export {
  clearImpersonationCookies,
  getImpersonationFromCookies,
  IMPERSONATION_COOKIE,
  IMPERSONATION_MODES,
  IMPERSONATION_MODE_COOKIE,
  IMPERSONATION_TARGET_COOKIE,
  IMPERSONATION_TARGET_EMAIL_COOKIE,
  setImpersonationCookies,
  signImpersonationToken,
  verifyImpersonationToken,
} from './impersonation';
export type { CookieOptions, CookieStore, SignImpersonationTokenInput } from './impersonation';

export { defaultServiceJwtProvider, getSession } from './accounts';
export type { GetSessionOptions, ServiceJwtProvider } from './accounts';

export { hashApiKey, verifyApiKey } from './api-key';
export type { ApiKeyLookup, ApiKeyRecord, VerifyApiKeyOptions } from './api-key';

export type {
  ApiKeyAuthResult,
  AuthSession,
  AuthUser,
  HqAuthzDecision,
  ImpersonationClaims,
  ImpersonationContext,
  ImpersonationMode,
} from './types';
