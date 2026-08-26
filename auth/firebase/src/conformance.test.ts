/**
 * The Factory auth conformance suite, run against this provider.
 *
 * Everything here is offline: no network, no Firebase project, no service
 * account, no environment variables. The provider takes a `verifyIdToken`
 * option, and supplying it replaces the Admin SDK outright — no app is
 * initialized and no credential is looked for — so `token` names a credential
 * this provider genuinely accepts along its real code path rather than one a
 * module mock waves through.
 *
 * The verifier here rejects the way `admin.auth().verifyIdToken` rejects, on
 * purpose. `authenticateToken` is required to answer `null` rather than to
 * propagate, and a stub that resolved `null` instead of throwing would not
 * exercise the half of that which used to be broken.
 *
 * WHY THIS SUITE IS GREEN FOR A PROVIDER THE FACTORY CANNOT SIGN INTO
 *
 * Read the skips, not just the passes. `@mastra/auth-firebase` is a bearer-token
 * validator, deliberately — see `FACTORY_BROWSER_SIGN_IN` in `./index` for the
 * decision and its reasoning — and the suite reports that shape as *skipped
 * checks with reasons*, never as passes. Obligations 2 and 3 do not apply to a
 * provider that cannot put a session in a browser, and the suite says so in the
 * skip text.
 *
 * The second block in this file exists so that the gap is asserted rather than
 * merely absent. If somebody later adds a hosted login or auth routes, those
 * assertions fail and the conformance run starts demanding obligations 2 and 3 —
 * which is the intended way to find out that this file needs rewriting.
 */
import { toAuthDescriptor } from '@mastra/factory-auth/capabilities';
import { describeAuthProvider } from '@mastra/factory-auth/conformance';
import { toAuthIdentity } from '@mastra/factory-auth/identity';
import { resolveOrganizationId, syntheticOrganizationId } from '@mastra/factory-auth/organizations';
import { describe, expect, it } from 'vitest';

import { FACTORY_BROWSER_SIGN_IN, MastraAuthFirebase } from './index';
import type { FirebaseUser } from './index';

/** A Firebase uid: 28 characters of base58-ish. Real-shaped, so the fixtures are honest. */
const USER_ID = 'kQ3mZ8vT1nRxW7bLpY0aCdE4fGh2';

/** The ID token the stand-in verifier accepts. Never leaves this file. */
const TOKEN = 'conformance-firebase-id-token';

const NOW = Math.floor(Date.parse('2024-01-01T00:00:00.000Z') / 1000);

/**
 * What `verifyIdToken` resolves to.
 *
 * A `DecodedIdToken` carries `uid` *and* `sub`, holding the same value. That
 * pair is the shape obligation 1 is most easily got wrong on, so it is spelled
 * out here rather than reduced to whichever one the assertion happens to read.
 */
const USER = {
  uid: USER_ID,
  sub: USER_ID,
  email: 'conformance@example.test',
  email_verified: true,
  aud: 'conformance-project',
  auth_time: NOW,
  exp: NOW + 3600,
  iat: NOW,
  iss: 'https://securetoken.google.com/conformance-project',
  firebase: { identities: {}, sign_in_provider: 'password' },
} as unknown as FirebaseUser;

/**
 * A verifier that rejects the way the Admin SDK rejects.
 *
 * `verifyIdToken` throws `FirebaseAuthError` for a token it cannot verify; the
 * contract requires `authenticateToken` to answer `null` instead of letting that
 * out. Modelling the throw is the point — until this release the rejection went
 * straight through to the host.
 */
async function verifyIdToken(token: string): Promise<FirebaseUser> {
  if (token !== TOKEN) {
    throw Object.assign(new Error('Decoding Firebase ID token failed.'), {
      code: 'auth/argument-error',
    });
  }
  return USER;
}

function createProvider(): MastraAuthFirebase {
  return new MastraAuthFirebase({ verifyIdToken });
}

describeAuthProvider({
  name: '@mastra/auth-firebase',
  createProvider,
  token: TOKEN,
  userId: USER_ID,
});

describe('@mastra/auth-firebase: the Factory browser flow', () => {
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

describe('@mastra/auth-firebase: uid is the user id everywhere', () => {
  it('resolves the same id through the identity normalizer and mapUserToResourceId', async () => {
    const provider = createProvider();
    const payload = await provider.authenticateToken(TOKEN);

    // The audit's finding about this package: `DecodedIdToken` exposes `uid`,
    // and a host reading only `id` treats the request as anonymous at every
    // ownership check. These two are the halves that have to agree — memory
    // resources are keyed on the second, everything else on the first.
    expect(toAuthIdentity(payload, provider)?.id).toBe(USER_ID);
    expect(provider.mapUserToResourceId?.(payload!)).toBe(USER_ID);
  });

  it('keeps mapUserToResourceId a function despite the base constructor', () => {
    // `MastraAuthProvider`'s constructor assigns `options?.mapUserToResourceId`
    // unconditionally, so an own `undefined` shadows a prototype method. This
    // pins the workaround: a regression there makes the method vanish rather
    // than misbehave, and the conformance check for it would silently skip.
    expect(typeof createProvider().mapUserToResourceId).toBe('function');
  });

  it('still lets a caller replace it', () => {
    const provider = new MastraAuthFirebase({
      verifyIdToken,
      mapUserToResourceId: () => 'supplied-by-the-host',
    });

    expect(provider.mapUserToResourceId?.(USER)).toBe('supplied-by-the-host');
  });
});

describe('@mastra/auth-firebase: the synthetic organization id', () => {
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
