import type { IOrganizationsProvider } from '@internal/auth';
import type { MastraAuthProviderOptions } from '@internal/auth/provider';
import { MastraAuthProvider } from '@internal/auth/provider';

import { createClient } from '@supabase/supabase-js';
import type { SupabaseClient, User } from '@supabase/supabase-js';

/**
 * Whether this provider can take somebody from a blank browser to a signed-in
 * session — the Mastra Factory's browser flow.
 *
 * It cannot, and that is a decision rather than an omission. The reasoning is
 * recorded here, in the package, so that a host can read it at runtime and a
 * reader can find it without the audit that produced it.
 *
 * WHAT THE FACTORY BROWSER FLOW NEEDS
 *
 * `ISSOProvider`: `getLoginUrl(redirectUri, state)` has to put the host's
 * opaque `state` into the authorization URL, and `handleCallback(code, state)`
 * has to accept that same `state` back. The `state` is the only value that
 * survives the whole round trip, so the host uses it to carry both a nonce and
 * where the person was going before they were bounced to a login screen.
 *
 * WHY SUPABASE CANNOT SUPPLY THAT FROM THIS PACKAGE
 *
 * 1. **`signInWithOAuth` has no `state`.** Supabase's hosted OAuth goes through
 *    GoTrue's `/authorize`, which mints its own `state` for the handshake with
 *    the upstream identity provider. The SDK exposes no way to substitute the
 *    host's, and the one value Supabase documents as surviving the round trip
 *    is `redirectTo` — whose query string comes back on the callback URL, which
 *    is not the `state` parameter the contract and this repo's callback route
 *    read.
 *
 * 2. **PKCE puts the code verifier somewhere this package does not own.**
 *    Supabase's default flow is PKCE. `exchangeCodeForSession` needs the code
 *    verifier that `signInWithOAuth` generated, and supabase-js keeps it in the
 *    client's `storage` — which in Node is memory private to one client
 *    instance. Login and callback are two separate requests, so a server-side
 *    integration needs a shared, request-scoped store; that is what
 *    `@supabase/ssr` supplies with cookies. It is per-deployment infrastructure,
 *    not something a provider package can decide on your behalf.
 *
 * 3. **Neither fact can be verified without a live project.** Whether GoTrue
 *    echoes a parameter, and whether a verifier survives from one request to the
 *    next, are facts about a running GoTrue and a running deployment — not about
 *    this code. A hosted login written blind would satisfy the conformance
 *    suite's structural checks (a `getLoginUrl` that returns a URL with a
 *    `state` on it passes) and fail on the first real sign-in. A provider that
 *    passes conformance by accident is worse than one that declines in writing.
 *
 * WHAT THIS PROVIDER IS INSTEAD
 *
 * A bearer-token gate, and a complete one: it validates Supabase access tokens,
 * resolves a flat user id, authorizes, and resolves an organization. That is a
 * supported shape — `toAuthDescriptor` reports `signIn.kind: 'none'` for it, and
 * `src/conformance.test.ts` runs the whole suite against it and records exactly
 * which checks are skipped and why.
 *
 * @see {@link https://github.com/mastra-ai/mastra/blob/main/mastracode/factory-auth/README.md#start-here}
 */
export const FACTORY_BROWSER_SIGN_IN = {
  /** Can this provider sign somebody in from a browser? */
  supported: false,

  /** One line, for a log or an error message. The long version is above. */
  reason:
    'Supabase sign-in is browser-centric: signInWithOAuth cannot carry the host OAuth `state`, ' +
    'and its PKCE code verifier lives in the supabase-js client storage rather than in a store ' +
    'shared between the login and callback requests.',

  /** What somebody who wanted a browser sign-in should do. */
  alternative:
    'Use this provider as an API-token gate: issue Supabase access tokens to your clients and send ' +
    'them as `Authorization: Bearer <token>`. For a browser sign-in, configure a provider that owns ' +
    'a server-side hosted login, or wrap Supabase in your own ISSOProvider using @supabase/ssr with ' +
    'a cookie-backed storage adapter, where you control the deployment and can test against your ' +
    'own project.',
} as const;

/**
 * The organization id namespace, matching `@mastra/factory-auth`'s synthetic one.
 *
 * The literal is duplicated rather than imported because `@mastra/factory-auth`
 * is a devDependency here — it is the conformance suite, not a runtime
 * dependency of a provider. `src/conformance.test.ts` asserts that what this
 * class derives is exactly what `syntheticOrganizationId` derives, so the copy
 * cannot drift silently.
 */
const SYNTHETIC_ORGANIZATION_PREFIX = 'user:';

interface MastraAuthSupabaseOptions extends MastraAuthProviderOptions<User> {
  url?: string;
  anonKey?: string;

  /**
   * A Supabase client to use instead of building one from `url` and `anonKey`.
   *
   * Supply your own when you already hold a configured client, and in tests:
   * injecting it is what lets this provider be exercised with no network and no
   * project, which is how `src/conformance.test.ts` runs. When it is set, `url`
   * and `anonKey` are not required.
   */
  client?: SupabaseClient;

  /**
   * Restore the pre-1.2 authorization behaviour: allow only users with a truthy
   * `isAdmin` column in a `users` table.
   *
   * Off by default, and the default changed deliberately. Until 1.2 this was the
   * only behaviour, and it denied every request in any deployment that did not
   * happen to have that table — so a correctly configured Supabase project
   * authenticated a user and then answered 403 to every core `/api/*` call,
   * with nothing in the response naming the missing table. Authorization policy
   * that depends on infrastructure the contract never mentions belongs in the
   * deployment, not in a provider's default.
   *
   * Turn it on if you have that table and want it enforced, or supply your own
   * `authorizeUser` for anything more specific.
   */
  requireAdminRow?: boolean;
}

export class MastraAuthSupabase extends MastraAuthProvider<User> implements IOrganizationsProvider {
  /** See {@link FACTORY_BROWSER_SIGN_IN}. Readable from a provider instance. */
  readonly factoryBrowserSignIn = FACTORY_BROWSER_SIGN_IN;

  protected supabase: SupabaseClient;
  private requireAdminRow: boolean;

  constructor(options?: MastraAuthSupabaseOptions) {
    super({ name: options?.name ?? 'supabase' });

    if (options?.client) {
      this.supabase = options.client;
    } else {
      const supabaseUrl = options?.url ?? process.env.SUPABASE_URL;
      const supabaseAnonKey = options?.anonKey ?? process.env.SUPABASE_ANON_KEY;

      if (!supabaseUrl || !supabaseAnonKey) {
        throw new Error(
          'Supabase URL and anon key are required, please provide them in the options or set the environment variables SUPABASE_URL and SUPABASE_ANON_KEY',
        );
      }

      this.supabase = createClient(supabaseUrl, supabaseAnonKey);
    }

    this.requireAdminRow = options?.requireAdminRow ?? false;

    this.registerOptions(options);
  }

  /**
   * Verify a Supabase access token.
   *
   * An empty token resolves to `null` without a round trip. The host passes the
   * empty string to mean "this request carried no bearer token", and this
   * provider reads no cookie — see {@link FACTORY_BROWSER_SIGN_IN} — so there is
   * nowhere else to look and nothing to ask Supabase about.
   */
  async authenticateToken(token: string): Promise<User | null> {
    if (!token) {
      return null;
    }

    const { data, error } = await this.supabase.auth.getUser(token);

    if (error) {
      return null;
    }

    return data.user;
  }

  /**
   * Authorize a user this provider authenticated.
   *
   * The default allows any payload that names somebody — which is the same
   * answer the host reaches on its own for a provider that implements no
   * authorization at all, and the answer a deployment gating `/api/*` with
   * Supabase tokens expects. It never throws and never touches the network, so a
   * transient Supabase failure cannot turn a denial into a 500.
   *
   * Set `requireAdminRow` to restore the `users.isAdmin` lookup, or pass your own
   * `authorizeUser` for anything else.
   */
  async authorizeUser(user: User): Promise<boolean> {
    if (!this.requireAdminRow) {
      return typeof user?.id === 'string' && user.id.trim() !== '';
    }

    try {
      const { data, error } = await this.supabase.from('users').select('isAdmin').eq('id', user?.id).single();

      if (error) {
        return false;
      }

      return data?.isAdmin === true;
    } catch {
      // A lookup that failed is not an authorization. Denying is the safe
      // direction, and returning rather than throwing keeps the host answering
      // 403 instead of 500.
      return false;
    }
  }

  /**
   * The organization this user's data is stored under: `user:${id}`.
   *
   * Supabase has no organization primitive, so there is nothing to look up and
   * nothing to create. The id is derived — a pure function of the user id, with
   * no store behind it — so two processes agree without talking to each other,
   * and the same user gets the same organization on every call and every deploy.
   *
   * This is the same value `withSyntheticOrganizations` from
   * `@mastra/factory-auth/organizations` would supply. It is implemented here
   * rather than left to that wrapper so that a provider straight out of the box
   * satisfies `isOrganizationsProvider`, instead of resolving no organization
   * until somebody remembers to wrap it. Wrapping it anyway is harmless: the
   * wrapper delegates and only supplies an id when the delegate declines.
   */
  async ensureOrganization(userId: string): Promise<string | undefined> {
    if (typeof userId !== 'string' || userId.trim() === '') {
      return undefined;
    }
    return `${SYNTHETIC_ORGANIZATION_PREFIX}${userId}`;
  }

  /**
   * Whether this user administers this organization.
   *
   * Every organization here is one person's, so the answer is whether the
   * organization is theirs. Nobody administers somebody else's.
   */
  async isOrganizationAdmin(organizationId: string, userId: string): Promise<boolean> {
    return organizationId === (await this.ensureOrganization(userId));
  }
}
