export {
  MastraAuthProvider,
  isSSOProvider,
  isSessionProvider,
  isUserProvider,
  isCredentialsProvider,
  isOrganizationsProvider,
  isAuthHttpHandler,
  hasAuthInit,
  canClearSession,
  canManageSessions,
} from '@internal/auth/provider';
export type { IMastraAuthProvider, MastraAuthProviderOptions } from '@internal/auth/provider';
export type {
  AuthInitContext,
  IAuthHttpHandler,
  IAuthInit,
  ICredentialsProvider,
  IOrganizationsProvider,
  ISessionClearer,
  ISessionManager,
  ISessionProvider,
  ISSOProvider,
  IUserProvider,
} from '@internal/auth';
