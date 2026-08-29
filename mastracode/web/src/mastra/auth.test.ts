import { toAuthDescriptor } from '@mastra/factory-auth/capabilities';
import { isAuthDisabled } from '@mastra/factory';
import type { IMastraAuthProvider } from '@mastra/core/server';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AUTH_PROVIDER_IDS, resolveFactoryAuth } from './auth.js';
import type { AuthProviderId } from './auth.js';

/**
 * Unit tests over the selection itself: an injected env object and a captured
 * `warn`, no entry import and no module-registry games.
 *
 * The one thing the injected env cannot cover is that most providers resolve
 * their OWN configuration from `process.env` at construction — only the two
 * values `resolveFactoryAuth` passes explicitly (Okta's redirect URI, Better
 * Auth's secret) come from the injected object. So provider-owned variables are
 * stubbed onto `process.env` as well, and {@link selecting} keeps the two
 * copies from drifting by writing both from one record.
 */

/** Env each provider needs before its constructor will produce an instance. */
const PROVIDER_ENV: Record<AuthProviderId, Record<string, string>> = {
  studio: {},
  workos: { WORKOS_API_KEY: 'sk_test', WORKOS_CLIENT_ID: 'client_test' },
  okta: {
    OKTA_DOMAIN: 'dev-123456.okta.com',
    OKTA_CLIENT_ID: '0oaTest',
    OKTA_CLIENT_SECRET: 'okta-secret',
    OKTA_COOKIE_PASSWORD: 'o'.repeat(32),
  },
  'better-auth': { BETTER_AUTH_SECRET: 'b'.repeat(32) },
  supabase: { SUPABASE_URL: 'https://project.supabase.co', SUPABASE_ANON_KEY: 'anon-key' },
  firebase: {},
  none: {},
};

/**
 * Every variable any test writes. Each one is cleared before a case sets what
 * it needs, so a developer's real `WORKOS_API_KEY` cannot make a
 * missing-env test pass on their machine and fail in CI.
 */
const MANAGED_ENV_KEYS = [
  'MASTRACODE_AUTH_PROVIDER',
  'MASTRACODE_AUTH_DISABLED',
  'MASTRA_SHARED_API_URL',
  'OKTA_REDIRECT_URI',
  'GOOGLE_APPLICATION_CREDENTIALS',
  ...Object.values(PROVIDER_ENV).flatMap(group => Object.keys(group)),
];

interface Selection {
  auth: ReturnType<typeof resolveFactoryAuth>;
  warnings: string[];
}

/** Run one selection with exactly `env` visible, in both copies of the environment. */
function select(env: Record<string, string>, publicUrl?: string): Selection {
  for (const key of MANAGED_ENV_KEYS) vi.stubEnv(key, env[key]);
  const warnings: string[] = [];
  const auth = resolveFactoryAuth({ publicUrl, env, warn: message => warnings.push(message) });
  return { auth, warnings };
}

/** Select `id` by name, with the env that provider needs to construct. */
function selecting(id: AuthProviderId, extra: Record<string, string> = {}): Selection {
  return select({ MASTRACODE_AUTH_PROVIDER: id, ...PROVIDER_ENV[id], ...extra });
}

function expectProvider(selection: Selection): IMastraAuthProvider {
  expect(isAuthDisabled(selection.auth)).toBe(false);
  return selection.auth as IMastraAuthProvider;
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('MASTRACODE_AUTH_PROVIDER', () => {
  it.each(AUTH_PROVIDER_IDS.filter(id => id !== 'none'))('constructs %s', id => {
    const provider = expectProvider(selecting(id));
    expect(typeof provider.authenticateToken).toBe('function');
    expect(typeof provider.authorizeUser).toBe('function');
  });

  it('returns AUTH_DISABLED and warns loudly for none', () => {
    const { auth, warnings } = selecting('none');
    expect(isAuthDisabled(auth)).toBe(true);
    // The open-server warning has to say both halves: the server is open, AND
    // the UI is a dead end, because an operator who only hears the first may
    // reasonably expect to still be able to log in and look around.
    expect(warnings.join('\n')).toMatch(/DISABLED/);
    expect(warnings.join('\n')).toMatch(/auth not configured/);
  });

  it('rejects an unknown value instead of falling back', () => {
    // The whole point: a typo must not quietly select the platform default,
    // which is the failure the required `auth` slot was introduced to remove.
    expect(() => select({ MASTRACODE_AUTH_PROVIDER: 'worksos' })).toThrow(
      /is not a provider this deployment can select/,
    );
    expect(() => select({ MASTRACODE_AUTH_PROVIDER: 'worksos' })).toThrow(
      /studio, workos, okta, better-auth, supabase, firebase, none/,
    );
  });

  it('clamps the echoed value so a pasted secret cannot fill the boot log', () => {
    const pasted = 'x'.repeat(400);
    expect(() => select({ MASTRACODE_AUTH_PROVIDER: pasted })).toThrow(/x{64}'/);
    expect(() => select({ MASTRACODE_AUTH_PROVIDER: pasted })).not.toThrow(/x{65}/);
  });

  it.each(['auth0', 'clerk', 'cloud', 'google', 'neon'])('refuses %s by name, with the reason', id => {
    // Refused rather than merely unknown: "unknown value" reads as a typo and
    // sends the operator hunting for a spelling mistake that isn't there.
    expect(() => select({ MASTRACODE_AUTH_PROVIDER: id })).toThrow(/refuses to select/);
    expect(() => select({ MASTRACODE_AUTH_PROVIDER: id })).toThrow(/conformance/);
    // And it must name the escape hatch, because refusing the selector is not
    // the same as refusing the provider.
    expect(() => select({ MASTRACODE_AUTH_PROVIDER: id })).toThrow(/pass the instance to that slot directly/);
  });

  it('names neon`s extra obligations, which are why it is unusable rather than merely unverified', () => {
    expect(() => select({ MASTRACODE_AUTH_PROVIDER: 'neon' })).toThrow(/obligation\/flatId and obligation\/cookieAuth/);
  });
});

describe('missing provider env', () => {
  // The deliberate asymmetry: the inference ladder falls through a half-set
  // WORKOS_* pair because nobody asked for WorkOS, but once the selector names
  // a provider the same missing env has to fail hard.
  it.each([
    ['workos', /WORKOS_API_KEY/],
    ['okta', /OKTA_DOMAIN/],
    ['supabase', /SUPABASE_URL/],
  ] as const)('throws for %s, naming the selector and the provider`s own complaint', (id, detail) => {
    expect(() => select({ MASTRACODE_AUTH_PROVIDER: id })).toThrow(/MASTRACODE_AUTH_PROVIDER selected/);
    expect(() => select({ MASTRACODE_AUTH_PROVIDER: id })).toThrow(detail);
  });

  it('preserves the provider`s own error as the cause', () => {
    try {
      select({ MASTRACODE_AUTH_PROVIDER: 'workos' });
      expect.unreachable('expected a throw');
    } catch (error) {
      expect((error as Error).cause).toBeInstanceOf(Error);
    }
  });

  it('throws its own error for better-auth, not the provider`s misleading one', () => {
    // The provider's message tells you to pass an `auth` instance, which is not
    // the shape this entry uses — so it would send an operator down the wrong path.
    expect(() => select({ MASTRACODE_AUTH_PROVIDER: 'better-auth' })).toThrow(/BETTER_AUTH_SECRET is required/);
  });

  it('constructs firebase with no env, because the Admin SDK defers credential resolution', () => {
    // Recorded rather than asserted-as-desirable: firebase has no constructor
    // failure to wrap, so a misconfigured deployment surfaces at first token
    // verification instead of at boot.
    expect(isAuthDisabled(select({ MASTRACODE_AUTH_PROVIDER: 'firebase' }).auth)).toBe(false);
  });

  it('warns instead, since a boot that cannot throw is a 401 with no stated cause', () => {
    const { warnings } = select({ MASTRACODE_AUTH_PROVIDER: 'firebase' });
    expect(warnings.join('\n')).toMatch(/neither FIREBASE_SERVICE_ACCOUNT nor GOOGLE_APPLICATION_CREDENTIALS/);
  });

  it.each([['FIREBASE_SERVICE_ACCOUNT'], ['GOOGLE_APPLICATION_CREDENTIALS']])(
    'stays quiet when %s supplies the credential',
    key => {
      // Either variable is enough, and Application Default Credentials can also
      // come from the metadata server — so this warns about an absence, it does
      // not validate what is present.
      const { warnings } = select({ MASTRACODE_AUTH_PROVIDER: 'firebase', [key]: '/path/to/creds.json' });
      expect(warnings.join('\n')).not.toMatch(/GOOGLE_APPLICATION_CREDENTIALS/);
    },
  );
});

describe('signals the selector overrides', () => {
  it('wins over MASTRACODE_AUTH_DISABLED, and says so', () => {
    // Direction matters: the selector winning leaves the server GATED and the
    // operator reads the warning. The flag winning would leave it OPEN.
    const { auth, warnings } = selecting('workos', { MASTRACODE_AUTH_DISABLED: '1' });
    expect(isAuthDisabled(auth)).toBe(false);
    expect(warnings.join('\n')).toMatch(/MASTRACODE_AUTH_DISABLED is set but ignored/);
  });

  it('does not warn when the selector and the deprecated flag agree', () => {
    const { warnings } = selecting('none', { MASTRACODE_AUTH_DISABLED: '1' });
    expect(warnings.join('\n')).not.toMatch(/but ignored/);
  });

  it('wins over MASTRA_SHARED_API_URL, and says so', () => {
    const { warnings } = selecting('workos', { MASTRA_SHARED_API_URL: 'https://platform.mastra.ai/v1' });
    expect(warnings.join('\n')).toMatch(/MASTRA_SHARED_API_URL is set but no longer decides identity/);
  });

  it('does not warn about MASTRA_SHARED_API_URL when studio is what was selected', () => {
    const { warnings } = selecting('studio', { MASTRA_SHARED_API_URL: 'https://platform.mastra.ai/v1' });
    expect(warnings.join('\n')).not.toMatch(/MASTRA_SHARED_API_URL/);
  });

  it('reports an ignored WorkOS pair', () => {
    const { warnings } = selecting('studio', PROVIDER_ENV.workos);
    expect(warnings.join('\n')).toMatch(/WORKOS_API_KEY\/WORKOS_CLIENT_ID are set but ignored/);
  });
});

describe('inference when MASTRACODE_AUTH_PROVIDER is unset', () => {
  it('treats MASTRACODE_AUTH_DISABLED=1 as none, with a deprecation warning', () => {
    const { auth, warnings } = select({ MASTRACODE_AUTH_DISABLED: '1' });
    expect(isAuthDisabled(auth)).toBe(true);
    expect(warnings.join('\n')).toMatch(/MASTRACODE_AUTH_DISABLED is deprecated/);
  });

  it('selects studio from MASTRA_SHARED_API_URL', () => {
    const provider = expectProvider(select({ MASTRA_SHARED_API_URL: 'https://platform.mastra.ai/v1' }));
    expect(provider.name).toBe('mastra-studio');
  });

  it('warns when MASTRA_SHARED_API_URL beats a configured WorkOS pair', () => {
    const { warnings } = select({ MASTRA_SHARED_API_URL: 'https://platform.mastra.ai/v1', ...PROVIDER_ENV.workos });
    expect(warnings.join('\n')).toMatch(/ignored: MASTRA_SHARED_API_URL takes precedence/);
  });

  it('selects workos from a complete pair', () => {
    expect(expectProvider(select(PROVIDER_ENV.workos)).name).toBe('workos');
  });

  it('falls through a half-set WorkOS pair to studio without throwing', () => {
    // Nobody asked for WorkOS here, so a partial group is not an error — this
    // is the soft half of the asymmetry the selector path deliberately breaks.
    expect(expectProvider(select({ WORKOS_API_KEY: 'sk_test' })).name).toBe('mastra-studio');
  });

  it('selects studio when nothing is configured', () => {
    expect(expectProvider(select({})).name).toBe('mastra-studio');
  });
});

describe('browser sign-in capability', () => {
  /**
   * The set of ids that cannot start a sign-in from a browser. Asserted against
   * `toAuthDescriptor` — the canonical computation — rather than restated, so a
   * provider that silently changes category fails here instead of shipping a
   * server nobody can log into (or a warning nobody needs).
   *
   * `@mastra/factory-auth` is imported only from this test. `auth.ts` composes
   * the same answer from `isSSOProvider`/`isCredentialsProvider` in
   * `@mastra/core/server`, because that file is copied verbatim into the
   * `create-factory` scaffold and every dependency the scaffold names has to be
   * a published package — which `@mastra/factory-auth` is not.
   */
  const TOKEN_ONLY_IDS = new Set<AuthProviderId>(['supabase', 'firebase']);

  it.each(AUTH_PROVIDER_IDS.filter(id => id !== 'none'))('%s sign-in category is the expected one', id => {
    const provider = expectProvider(selecting(id));
    const isTokenOnly = toAuthDescriptor(provider).signIn.kind === 'none';
    expect(isTokenOnly).toBe(TOKEN_ONLY_IDS.has(id));
  });

  it.each([...TOKEN_ONLY_IDS])('warns at boot that %s cannot sign anyone in from a browser', id => {
    const { warnings } = selecting(id);
    expect(warnings.join('\n')).toMatch(/cannot sign anyone in from a browser/);
    expect(warnings.join('\n')).toMatch(/Bearer/);
  });

  it.each(AUTH_PROVIDER_IDS.filter(id => id !== 'none' && !TOKEN_ONLY_IDS.has(id)))(
    'does not warn for %s, which owns a sign-in',
    id => {
      expect(selecting(id).warnings.join('\n')).not.toMatch(/cannot sign anyone in from a browser/);
    },
  );
});

describe('okta redirect URI', () => {
  it('derives the callback from publicUrl, matching what the server builds at request time', () => {
    const provider = expectProvider(
      select({ MASTRACODE_AUTH_PROVIDER: 'okta', ...PROVIDER_ENV.okta }, 'https://factory.example.com'),
    );
    // Okta validates `redirectUri` in its constructor and has no `init()` hook,
    // so if this were left to the provider it would throw instead of defaulting.
    expect((provider as unknown as { redirectUri: string }).redirectUri).toBe(
      'https://factory.example.com/auth/callback',
    );
  });

  it('honors an explicit OKTA_REDIRECT_URI', () => {
    const provider = expectProvider(
      select(
        { MASTRACODE_AUTH_PROVIDER: 'okta', ...PROVIDER_ENV.okta, OKTA_REDIRECT_URI: 'https://sso.example.com/cb' },
        'https://factory.example.com',
      ),
    );
    expect((provider as unknown as { redirectUri: string }).redirectUri).toBe('https://sso.example.com/cb');
  });
});
