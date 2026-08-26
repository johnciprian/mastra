/**
 * Session object representing an authenticated session.
 */
export interface Session {
  /** Unique session identifier */
  id: string;
  /** User ID this session belongs to */
  userId: string;
  /** When the session expires */
  expiresAt: Date;
  /** When the session was created */
  createdAt: Date;
  /** Additional session metadata */
  metadata?: Record<string, unknown>;
}

/**
 * A provider that can clear the session cookie it owns.
 *
 * The smallest capability in the contract, and it exists on its own because a
 * provider can genuinely have only this one. A hosted-login provider mints its
 * own cookie during `handleCallback` and has to clear it on logout, but it
 * creates no session a host can address by id, so none of the other six
 * `ISessionProvider` members mean anything to it. `@mastra/auth-better-auth`
 * is exactly that shape: it owns its cookie, it is not an `ISSOProvider`
 * either, and before this interface existed it implemented
 * `getClearSessionHeaders` against no declaration at all - a convention hosts
 * read structurally and no interface described.
 *
 * `ISessionProvider` extends this, so every full session provider satisfies
 * `canClearSession` too, and the member is declared in one place.
 *
 * Return `Set-Cookie` values that expire the cookies this provider set. A host
 * sends them on logout alongside clearing anything it owns itself. Several
 * cookies may be joined into one comma-separated value; a host that has to
 * split them back apart has to contend with `Expires` dates containing commas,
 * so prefer returning one cookie where you can.
 */
export interface ISessionClearer {
  getClearSessionHeaders(): Record<string, string>;
}

/**
 * Provider interface for session management.
 */
export interface ISessionProvider<TSession extends Session = Session> extends ISessionClearer {
  createSession(userId: string, metadata?: Record<string, unknown>): Promise<TSession>;
  validateSession(sessionId: string): Promise<TSession | null>;
  destroySession(sessionId: string): Promise<void>;
  refreshSession(sessionId: string): Promise<TSession | null>;
  getSessionIdFromRequest(request: Request): string | null;
  getSessionHeaders(session: TSession): Record<string, string>;
}

export { MemorySessionProvider, type MemorySessionProviderOptions } from './memory';
export { CookieSessionProvider, type CookieSessionProviderOptions } from './cookie';
