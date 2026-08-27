/**
 * The Factory auth conformance suite, run against this provider.
 *
 * Everything here is offline: no network, no Supabase project, no environment
 * variables. The provider is handed a stand-in `SupabaseClient` whose
 * `auth.getUser` answers the way GoTrue answers — a user for the seeded access
 * token, an `AuthApiError`-shaped rejection for anything else — so `token` names
 * a credential this provider genuinely accepts rather than one a mock waves
 * through.
 *
 * WHY THIS SUITE IS GREEN FOR A PROVIDER THE FACTORY CANNOT SIGN INTO
 *
 * Read the skips, not just the passes. `@mastra/auth-supabase` is a bearer-token
 * validator, deliberately — see `FACTORY_BROWSER_SIGN_IN` in `./index` for the
 * decision and its reasoning — and the suite reports that shape as *skipped
 * checks with reasons*, never as passes. Obligations 2 and 3 do not apply to a
 * provider that cannot put a session in a browser, and the suite says so in the
 * skip text.
 *
 * The second block in this file exists so that the gap is asserted rather than
 * merely absent. It pins the two facts a reader would otherwise have to infer
 * from a skip: that the capability descriptor reports `signIn.kind: 'none'`, and
 * that the package says out loud that it cannot run the browser flow. If
 * somebody later adds a hosted login, both assertions fail and the conformance
 * run starts demanding obligations 2 and 3 — which is the intended way to find
 * out that this file needs rewriting.
 */
import { toAuthDescriptor } from '@mastra/factory-auth/capabilities';
import { describeAuthProvider } from '@mastra/factory-auth/conformance';
import { resolveOrganizationId, syntheticOrganizationId } from '@mastra/factory-auth/organizations';
import type { SupabaseClient, User } from '@supabase/supabase-js';
import { describe, expect, it } from 'vitest';

import { FACTORY_BROWSER_SIGN_IN, MastraAuthSupabase } from './index';

/** A Supabase user id is a uuid. Using a real-shaped one keeps the fixtures honest. */
const USER_ID = '0f3c1b5e-9d24-4a7f-b8c1-2e6a5d0f7431';

/** The access token the stand-in GoTrue accepts. Never leaves this file. */
const TOKEN = 'conformance-supabase-access-token';

const USER: User = {
  id: USER_ID,
  email: 'conformance@example.test',
  aud: 'authenticated',
  role: 'authenticated',
  created_at: '2024-01-01T00:00:00.000Z',
  app_metadata: { provider: 'email', providers: ['email'] },
  user_metadata: {},
};

/**
 * A client that answers the one call this provider makes.
 *
 * `from`/`select`/`eq`/`single` are deliberately absent: the default
 * `authorizeUser` does not touch the database, and a fake that supplied those
 * methods would hide a regression that reintroduced the lookup.
 */
function fakeClient(): SupabaseClient {
  return {
    auth: {
      async getUser(token?: string) {
        if (token === TOKEN) {
          return { data: { user: USER }, error: null };
        }
        return {
          data: { user: null },
          // Shaped like what supabase-js hands back for a bad JWT: a truthy
          // `error`, which is the only property this provider reads.
          error: { name: 'AuthApiError', message: 'invalid claim: missing sub claim', status: 401 },
        };
      },
    },
  } as unknown as SupabaseClient;
}

function createProvider(): MastraAuthSupabase {
  return new MastraAuthSupabase({ client: fakeClient() });
}

describeAuthProvider({
  name: '@mastra/auth-supabase',
  createProvider,
  token: TOKEN,
  userId: USER_ID,
});

describe('@mastra/auth-supabase: the Factory browser flow', () => {
  it('declares that it cannot sign anybody in from a browser', () => {
    expect(FACTORY_BROWSER_SIGN_IN.supported).toBe(false);
    expect(FACTORY_BROWSER_SIGN_IN.reason).not.toBe('');
    expect(FACTORY_BROWSER_SIGN_IN.alternative).not.toBe('');
    expect(createProvider().factoryBrowserSignIn).toBe(FACTORY_BROWSER_SIGN_IN);
  });

  it('reports a descriptor a sign-in screen can render honestly', () => {
    const descriptor = toAuthDescriptor(createProvider());

    // 'none' is the value the kit documents for "validates API tokens, cannot
    // sign you in here". A UI must render the explanation, not an empty form.
    expect(descriptor.signIn.kind).toBe('none');

    // False is what makes obligations 2 and 3 skip: no browser ever holds a
    // session for this provider, so there is no cookie to read and no hosted
    // login to put a `state` into.
    expect(descriptor.features.logout).toBe(false);

    // The one Factory obligation this provider does meet beyond bearer
    // validation, and the reason it is not simply "unsupported" across the board.
    expect(descriptor.features.organizations).toBe(true);
  });
});

describe('@mastra/auth-supabase: the synthetic organization id', () => {
  it('derives exactly what the kit derives', async () => {
    // `./index` spells `user:${id}` itself rather than importing the kit at
    // runtime. This is the assertion that keeps the copy from drifting.
    const provider = createProvider();

    expect(await provider.ensureOrganization(USER_ID)).toBe(syntheticOrganizationId(USER_ID));
    expect(await provider.ensureOrganization(USER_ID)).toBe(resolveOrganizationId({ id: USER_ID }));
  });

  it('makes the user an admin of their own organization and of nobody else’s', async () => {
    const provider = createProvider();
    const organizationId = await provider.ensureOrganization(USER_ID);

    expect(await provider.isOrganizationAdmin(organizationId!, USER_ID)).toBe(true);
    expect(await provider.isOrganizationAdmin(organizationId!, 'someone-else')).toBe(false);
  });
});
