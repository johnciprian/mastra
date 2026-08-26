/**
 * The Factory auth conformance suite, run against this provider.
 *
 * Everything here is offline: no network, no identity provider, no environment
 * variables. The provider is handed a real `betterAuth()` instance backed by
 * better-auth's own in-memory adapter, pre-seeded with one user and one
 * unexpired session, so `token` names a session better-auth genuinely accepts
 * rather than one a mock waves through.
 *
 * A fresh instance per `createProvider()` call, because the suite builds one
 * provider per check and `ensureOrganization` writes to the organization tables.
 */
import { describeAuthProvider } from '@mastra/factory-auth/conformance';
import { betterAuth } from 'better-auth';
import type { BetterAuthOptions } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { makeSignature } from 'better-auth/crypto';
import { organization } from 'better-auth/plugins';

import { MastraAuthBetterAuth } from './index';

/** Only ever used to sign the seeded session token. Never leaves this file. */
const SECRET = 'conformance-secret-that-is-at-least-32-chars';

const USER_ID = 'conformance_user';

/** The raw, unsigned session token — the shape `signIn`/`signUp` hand back. */
const TOKEN = 'conformance-session-token';

/**
 * The seed, rebuilt per provider so no check sees another's writes.
 *
 * The organization plugin's three tables are present but empty: obligation 4
 * asks `ensureOrganization` to bootstrap a personal org, and it has to have
 * somewhere to write it.
 */
function seedDatabase() {
  const now = new Date();
  return {
    user: [
      {
        id: USER_ID,
        name: 'Conformance User',
        email: 'conformance@example.test',
        emailVerified: true,
        image: null,
        createdAt: now,
        updatedAt: now,
      },
    ],
    session: [
      {
        id: 'conformance_session',
        token: TOKEN,
        userId: USER_ID,
        expiresAt: new Date(Date.now() + 86_400_000),
        createdAt: now,
        updatedAt: now,
        ipAddress: '',
        userAgent: '',
      },
    ],
    account: [],
    verification: [],
    organization: [],
    member: [],
    invitation: [],
  };
}

/**
 * Bring-your-own-instance mode, which is what the README documents and what a
 * host that owns its better-auth configuration uses.
 *
 * The `BetterAuthOptions` annotation is load-bearing for the typechecker and
 * changes nothing at runtime. `betterAuth()` is generic over the *exact*
 * options object it is handed, so an inline literal produces
 * `Auth<{ baseURL: string; ... }>`, and `Auth<T>` is invariant in `T` —
 * `DBAdapter<T>` sits in both a covariant and a contravariant position. That
 * makes it unassignable to the bare `Auth` that `MastraAuthBetterAuthOptions`
 * declares for its `auth` option. Widening the options first pins `T` to
 * `BetterAuthOptions` and the instance fits.
 *
 * This is the same widening `src/index.ts` already performs on the instance it
 * builds for itself (see the comment above `const options: BetterAuthOptions`
 * in `init()`) — the provider knows about this, it just never applied it to the
 * public `auth` option. So `betterAuth({ ... })` passed straight in, which is
 * what this package's README, both docs pages and the class JSDoc all show,
 * does not typecheck. That is a finding about the provider, recorded here
 * rather than worked around with a cast; fixing it means widening the declared
 * option type, which is a change to a published package's API.
 */
function createProvider(): MastraAuthBetterAuth {
  const options: BetterAuthOptions = {
    baseURL: 'http://localhost:3000',
    basePath: '/auth/api',
    secret: SECRET,
    database: memoryAdapter(seedDatabase()),
    emailAndPassword: { enabled: true },
    plugins: [organization()],
  };
  return new MastraAuthBetterAuth({ auth: betterAuth(options) });
}

/**
 * What a signed-in browser sends.
 *
 * better-auth reads its session from a *signed* cookie — `<token>.<signature>`,
 * percent-encoded — while `signIn`/`signUp` return the raw token. The provider
 * signs a raw bearer token on the way in, but obligation 2 sends an *empty*
 * bearer, so the cookie has to already carry the signature a browser would have
 * been given.
 */
const COOKIE_HEADER = `better-auth.session_token=${encodeURIComponent(`${TOKEN}.${await makeSignature(TOKEN, SECRET)}`)}`;

describeAuthProvider({
  name: '@mastra/auth-better-auth',
  createProvider,
  token: TOKEN,
  userId: USER_ID,
  cookieHeader: COOKIE_HEADER,
});
