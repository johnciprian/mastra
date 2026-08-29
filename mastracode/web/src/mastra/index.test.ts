import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Hono } from 'hono';
import type * as factoryModule from '@mastra/factory';
// Safe to import statically despite the `vi.resetModules()` in every hook:
// `isAuthDisabled` reads a property rather than comparing identities, so it
// gives the same answer across module generations.
import { isAuthDisabled } from '@mastra/factory';
import { buildAuthRoutes } from '@mastra/factory/auth';
import { resolveFactoryGithubRule } from '@mastra/factory/rules/resolve';
import type { IMastraAuthProvider } from '@mastra/core/server';

type FactoryConfig = ConstructorParameters<typeof factoryModule.MastraFactory>[0];

const factoryConfigs = vi.hoisted(() => [] as Array<ConstructorParameters<typeof factoryModule.MastraFactory>[0]>);
/**
 * How the next `import('./index.js')` should load the entry.
 *
 * `configOnly` skips `prepare()`/`finalize()` — see {@link captureFactoryConfig}
 * for why a test that only reads the entry's decisions has no use for the boot
 * they perform.
 */
const loadMode = vi.hoisted(() => ({ configOnly: false }));
vi.mock('@mastra/factory', async importOriginal => {
  const actual = await importOriginal<typeof factoryModule>();
  class TrackedMastraFactory extends actual.MastraFactory {
    constructor(config: ConstructorParameters<typeof actual.MastraFactory>[0]) {
      super(config);
      factoryConfigs.push(config);
    }

    async prepare(): Promise<factoryModule.MastraArgs> {
      if (!loadMode.configOnly) return super.prepare();
      // Empty args still satisfy the entry's `new Mastra(...)` literal, so the
      // module body runs to completion and the config above is complete.
      return {};
    }

    async finalize(): Promise<void> {
      if (!loadMode.configOnly) return super.finalize();
      // Nothing was prepared, so there is no controller to start.
    }
  }
  return { ...actual, MastraFactory: TrackedMastraFactory };
});

/**
 * Smoke test for the platform-deployable entry (`src/mastra/index.ts`).
 *
 * The entry does two separable things, and the tests below split along that
 * line:
 *
 * 1. It maps deployment env onto one `MastraFactory` config. That mapping is
 *    the entry's own logic, it finishes in the module body, and the config it
 *    produces is captured by the `TrackedMastraFactory` seam above — no boot
 *    required, and `loadMode.configOnly` skips it.
 * 2. It boots that config via top-level `await factory.prepare()` /
 *    `finalize()` and exports the resulting `mastra`. Tests that assert on the
 *    booted surface — the deployer-facing `apiRoutes`, a wired controller —
 *    pay for a real boot, because that is what they are checking.
 *
 * With no auth env configured the entry names the platform-proxied provider
 * itself — the factory has no default left to install — so the public `/auth/*`
 * routes ride along on `apiRoutes`. The custom `/web/*` routes are always
 * present.
 */
describe('platform entry (src/mastra/index.ts)', () => {
  // Every test in this file imports the real entry, and the entry's auth
  // selection reads MASTRACODE_AUTH_PROVIDER and each provider's own group
  // directly from the environment. Blank them at file scope so a runner with
  // real credentials exported can't flip the entry into a different auth branch
  // (or crash tests that stub a short WORKOS_COOKIE_PASSWORD); each test states
  // its own env on top of this. MASTRACODE_AUTH_PROVIDER matters most: one
  // exported value would override every branch these tests exercise.
  beforeEach(() => {
    for (const name of [
      'MASTRACODE_AUTH_PROVIDER',
      'MASTRACODE_AUTH_DISABLED',
      'WORKOS_API_KEY',
      'WORKOS_CLIENT_ID',
      'WORKOS_COOKIE_PASSWORD',
      'OKTA_DOMAIN',
      'OKTA_CLIENT_ID',
      'OKTA_CLIENT_SECRET',
      'OKTA_REDIRECT_URI',
      'OKTA_COOKIE_PASSWORD',
      'BETTER_AUTH_SECRET',
      'SUPABASE_URL',
      'SUPABASE_ANON_KEY',
      'FIREBASE_SERVICE_ACCOUNT',
      'MASTRA_SHARED_API_URL',
      'MASTRA_PLATFORM_SECRET_KEY',
      'MASTRA_PLATFORM_ACCESS_TOKEN',
      'MASTRACODE_DISPATCH_MAX_IN_FLIGHT',
    ]) {
      vi.stubEnv(name, '');
    }
    factoryConfigs.length = 0;
    loadMode.configOnly = false;
    vi.resetModules();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    loadMode.configOnly = false;
    vi.resetModules();
  });

  // Mount a `/auth/login` route on a throwaway Hono app and return the redirect
  // target. The handlers built by `buildAuthRoutes` are self-contained closures
  // over the provider, so no server context is needed, and `getLoginUrl` only
  // builds a URL — no network involved. Takes the routes rather than a booted
  // module so both a real boot's `apiRoutes` and routes built from a captured
  // config can be driven through the same helper.
  async function loginRedirect(routes: ReadonlyArray<{ path: string }>): Promise<string> {
    const login = routes.find(route => route.path === '/auth/login');
    expect(login, 'expected /auth/login to be registered').toBeDefined();
    const app = new Hono();
    app.get('/auth/login', c => (login as any).handler(c));
    const res = await app.request('/auth/login');
    expect(res.status).toBeGreaterThanOrEqual(300);
    expect(res.status).toBeLessThan(400);
    return res.headers.get('location') ?? '';
  }

  it('exports a booted Mastra with the web apiRoutes folded onto server config', { timeout: 60_000 }, async () => {
    const mod = await import('./index.js');

    expect(mod.mastra).toBeDefined();
    // The deployer imports this named export and generates its Hono server from it.
    expect(typeof mod.mastra.getServer).toBe('function');

    const server = mod.mastra.getServer();
    expect(server).toBeDefined();

    // The custom web surface must ride along on `server.apiRoutes` so the
    // deployer-generated server exposes it. At minimum the fs `/web/*` routes
    // are always assembled (github is fail-soft, auth routes are gated).
    const apiRoutes = server?.apiRoutes ?? [];
    const paths = apiRoutes.map(r => r.path);
    expect(paths.some(p => p.startsWith('/web/'))).toBe(true);

    // No auth env is configured here, so this is also the unset-`auth`-slot
    // branch of the ladder, end to end: the factory installed its
    // platform-backed default and its hosted login rides the shared platform
    // API. Asserted on the one boot this file already pays for, so the ladder
    // tests below need no boot of their own to say where an unset slot lands.
    expect(await loginRedirect(apiRoutes)).toContain('platform.mastra.ai');
  });

  it('forwards the dispatcher concurrency environment setting to the factory', { timeout: 60_000 }, async () => {
    vi.stubEnv('MASTRACODE_DISPATCH_MAX_IN_FLIGHT', '7');
    await import('./index.js');

    expect(factoryConfigs).toHaveLength(1);
    expect(factoryConfigs[0]?.dispatcher).toEqual({ maxInFlight: 7 });
  });

  it('uses the production Factory rules to retriage linked issue updates without moving their stage', async () => {
    const { factoryRules } = await import('./index.js');
    const item = {
      id: 'issue-42',
      source: 'github-issue' as const,
      sourceKey: 'github-issue:42',
      parentWorkItemId: null,
      title: 'Issue 42',
      url: 'https://github.com/acme/repo/issues/42',
      stages: ['planning'],
    };
    const base = {
      tenant: { orgId: 'org-1', projectId: 'project-1' },
      actor: { type: 'github' as const, login: 'contributor', trusted: true, factoryAuthored: false },
      causalChain: [],
      ruleSetVersion: factoryRules.version,
      factory: { createdAt: '2030-01-01T00:00:00.000Z' },
      repository: { id: 10, fullName: 'acme/repo' },
      item,
      board: 'work' as const,
      itemRevision: 3,
    };

    const issueEdited = resolveFactoryGithubRule(factoryRules, 'issueEdited');
    const issueCommentCreated = resolveFactoryGithubRule(factoryRules, 'issueCommentCreated');

    expect(
      issueEdited?.({
        ...base,
        ingress: { type: 'github', id: '7:issue-update' },
        cause: 'github.issueEdited',
        event: 'issueEdited',
        deliveryId: 'issue-update',
        issue: { number: 42, title: 'Issue 42', url: item.url },
        issueChange: { title: false, body: true },
      }),
    ).toMatchObject({
      type: 'invokeSkill',
      idempotencyKey: '7:issue-update:factory-triage',
    });
    expect(
      issueCommentCreated?.({
        ...base,
        ingress: { type: 'github', id: '7:comment-created' },
        cause: 'github.issueCommentCreated',
        event: 'issueCommentCreated',
        deliveryId: 'comment-created',
        issue: { number: 42, title: 'Issue 42', url: item.url },
        issueComment: { id: 100, author: 'contributor', body: 'New lead' },
      }),
    ).toMatchObject({
      type: 'invokeSkill',
      idempotencyKey: '7:comment-created:factory-triage',
    });
    expect(item.stages).toEqual(['planning']);
  });

  // Integration env groups are all-or-nothing: a partial set means the
  // integration stays un-wired, but boot must survive so the diagnostics
  // surface can report exactly which vars are missing.
  describe('integration env groups', () => {
    beforeEach(() => {
      for (const name of [
        'GITHUB_APP_ID',
        'GITHUB_APP_PRIVATE_KEY',
        'GITHUB_APP_CLIENT_ID',
        'GITHUB_APP_CLIENT_SECRET',
        'GITHUB_APP_SLUG',
        'GITHUB_APP_WEBHOOK_SECRET',
        'LINEAR_CLIENT_ID',
        'LINEAR_CLIENT_SECRET',
        'SLACK_APP_SIGNING_SECRET',
      ]) {
        vi.stubEnv(name, '');
      }
      vi.resetModules();
    });

    afterEach(() => {
      vi.unstubAllEnvs();
      vi.resetModules();
    });

    it(
      'boots when the GitHub group is partially configured so diagnostics can report the missing setup',
      { timeout: 60_000 },
      async () => {
        vi.resetModules();
        // The test env may carry a full GitHub config — blank everything but the
        // app id to force the partial state.
        vi.stubEnv('GITHUB_APP_ID', '12345');
        vi.stubEnv('GITHUB_APP_PRIVATE_KEY', '');
        vi.stubEnv('GITHUB_APP_CLIENT_ID', '');
        vi.stubEnv('GITHUB_APP_CLIENT_SECRET', '');
        vi.stubEnv('GITHUB_APP_SLUG', '');
        const mod = await import('./index.js');
        expect(mod.mastra).toBeDefined();
      },
    );

    it(
      'registers the direct GitHub App integration when the full group is configured',
      { timeout: 60_000 },
      async () => {
        vi.resetModules();
        // No platform identity in this env, so the only source of a GitHub
        // connection is the direct GITHUB_APP_* group wired in the entry.
        vi.stubEnv('MASTRA_PLATFORM_SECRET_KEY', '');
        vi.stubEnv('GITHUB_APP_ID', '12345');
        vi.stubEnv('GITHUB_APP_PRIVATE_KEY', 'test-private-key');
        vi.stubEnv('GITHUB_APP_CLIENT_ID', 'Iv1.client');
        vi.stubEnv('GITHUB_APP_CLIENT_SECRET', 'client-secret');
        vi.stubEnv('GITHUB_APP_SLUG', 'test-app');
        vi.stubEnv('GITHUB_APP_WEBHOOK_SECRET', 'webhook-secret');
        const mod = await import('./index.js');
        const paths = mod.mastra.getServer()?.apiRoutes?.map(route => route.path) ?? [];
        // The connect route is registered only by the GithubIntegration, so its
        // presence proves the direct fallback wired the integration onto the factory.
        expect(paths).toContain('/auth/github/connect');
      },
    );

    it(
      'boots when the Linear group is partially configured so diagnostics can report the missing setup',
      { timeout: 60_000 },
      async () => {
        vi.resetModules();
        vi.stubEnv('LINEAR_CLIENT_ID', 'lin_client');
        vi.stubEnv('LINEAR_CLIENT_SECRET', '');
        const mod = await import('./index.js');
        expect(mod.mastra).toBeDefined();
      },
    );

    it('registers the direct Linear integration when the full group is configured', { timeout: 60_000 }, async () => {
      vi.resetModules();
      vi.stubEnv('MASTRA_PLATFORM_SECRET_KEY', '');
      vi.stubEnv('WORKOS_COOKIE_PASSWORD', 'stable-state-secret');
      vi.stubEnv('LINEAR_CLIENT_ID', 'lin_client');
      vi.stubEnv('LINEAR_CLIENT_SECRET', 'linear-secret');
      const mod = await import('./index.js');
      const paths = mod.mastra.getServer()?.apiRoutes?.map(route => route.path) ?? [];
      expect(paths).toContain('/auth/linear/connect');
    });

    it('skips Slack channel wiring when the Slack app env is unset', { timeout: 60_000 }, async () => {
      vi.resetModules();
      // chat's Slack adapter throws at construction without a signingSecret,
      // so an unconfigured env must skip channels instead of crashing boot.
      vi.stubEnv('SLACK_APP_SIGNING_SECRET', '');
      const mod = await import('./index.js');
      const controller = mod.mastra.getAgentController('code');
      expect(controller?.getChannels()).toBeNull();
    });

    it(
      'wires Slack channels onto the controller when the Slack app env is configured',
      { timeout: 60_000 },
      async () => {
        vi.resetModules();
        vi.stubEnv('SLACK_APP_SIGNING_SECRET', 'test-signing-secret');
        // Slack signs the account-link state, so it needs a replica-stable
        // secret like the GitHub and Linear integrations do.
        vi.stubEnv('WORKOS_COOKIE_PASSWORD', 'stable-state-secret');
        const mod = await import('./index.js');
        const controller = mod.mastra.getAgentController('code');
        // Assert the controller first: `controller?.getChannels()` on a missing
        // controller yields `undefined`, which would satisfy `not.toBeNull()`
        // and let the whole Slack wiring disappear silently.
        expect(controller).toBeDefined();
        expect(controller!.getChannels()).toBeDefined(); // sabotage below
      },
    );

    it('registers the Slack connect routes through the integration', { timeout: 60_000 }, async () => {
      vi.resetModules();
      vi.stubEnv('SLACK_APP_SIGNING_SECRET', 'test-signing-secret');
      vi.stubEnv('WORKOS_COOKIE_PASSWORD', 'stable-state-secret');
      const mod = await import('./index.js');
      const paths = mod.mastra.getServer()?.apiRoutes?.map(route => route.path) ?? [];
      // The entry no longer splices these on by hand — their presence proves the
      // factory collected them from the integration's `routes()`.
      expect(paths).toContain('/connect/slack');
    });

    it(
      'boots a Slack-only deployment by signing state with the Slack signing secret',
      { timeout: 60_000 },
      async () => {
        vi.resetModules();
        vi.stubEnv('SLACK_APP_SIGNING_SECRET', 'test-signing-secret');
        // Slack signs OAuth state, so the factory rejects a per-process random
        // signer: a link signed on one replica could not be verified on another.
        // A deployment that configures Slack and nothing else has neither of the
        // other two secrets, so the signing secret is the stable signer and boot
        // must survive on it alone.
        vi.stubEnv('GITHUB_APP_WEBHOOK_SECRET', '');
        vi.stubEnv('WORKOS_COOKIE_PASSWORD', '');
        const mod = await import('./index.js');
        expect(mod.mastra.getAgentController('code')?.getChannels()).toBeDefined();
      },
    );
  });

  /**
   * The entry's auth ladder (`src/mastra/index.ts`): `MASTRACODE_AUTH_DISABLED`,
   * then `MASTRA_SHARED_API_URL`, then the `WORKOS_*` pair, then nothing. It
   * decides exactly one thing — which value lands in `MastraFactory`'s `auth`
   * slot — and it decides it in the entry's module body, before `prepare()` is
   * ever called. So these tests read that value off the capture seam instead of
   * booting a server and inferring the choice back out of the routes it
   * assembled.
   *
   * Each branch's consequence is covered end to end across three suites, one
   * link each: which value the ladder picks, here; `undefined` →
   * `MastraAuthStudio` in `mastracode/factory/src/factory.test.ts`; and which
   * API that provider's login URL targets (`MASTRA_SHARED_API_URL`, else
   * platform.mastra.ai) in `auth/studio/src/index.test.ts`. The first test in
   * this file re-checks the whole chain once on a real boot.
   *
   * THE TIMEOUT IS FOR THE COLD IMPORT, NOT FOR THESE TESTS
   *
   * Each branch here costs about a third of a second in a normal run. The
   * allowance is for the case where this describe is the *first* thing in the
   * file to import the entry — `-t 'auth env ladder'`, an `.only`, a reordering
   * — and one of them therefore pays the one-off transform of the entry's whole
   * module graph, which is several seconds and has nothing to do with what the
   * test asserts. Vitest's 5s default turns that into a red suite that passes
   * again as soon as some other test runs first, and a timed-out import keeps
   * running and pushes a stray config into the capture array, so the failure
   * lands on a later test as well. Do not read this number as the cost of a
   * branch: the reporter's per-test milliseconds are the honest figure.
   */
  describe('auth env ladder', { timeout: 30_000 }, () => {
    /**
     * Load the entry for its decisions rather than its boot, and return the
     * config it handed to `MastraFactory`.
     *
     * `prepare()`/`finalize()` are skipped: they initialize storage, mount a
     * controller and start workers, none of which can change or reveal a choice
     * the module body already made. Paying for them per branch is what made
     * this describe the slowest part of the file.
     */
    async function captureFactoryConfig(): Promise<FactoryConfig> {
      loadMode.configOnly = true;
      try {
        await import('./index.js');
      } finally {
        loadMode.configOnly = false;
      }
      expect(factoryConfigs).toHaveLength(1);
      return factoryConfigs[0]!;
    }

    /**
     * Build the selected provider's public `/auth/*` routes the way a boot
     * does. `buildAuthRoutes` is the same function `MastraFactory.prepare()`
     * calls, so `/auth/login`'s `redirect_uri` is derived from the config's
     * `publicUrl` here exactly as it is in a deployment — rather than the test
     * restating that derivation and passing whatever it restated.
     */
    function authRoutesFor(config: FactoryConfig) {
      // `toBeTruthy()` would pass on AUTH_DISABLED — `{ disabled: true }` is an
      // object — and then hand `buildAuthRoutes` something that is not a
      // provider. Ask the question that actually distinguishes the two.
      expect(isAuthDisabled(config.auth), 'expected the entry to select an auth provider').toBe(false);
      return buildAuthRoutes(config.auth as IMastraAuthProvider, { publicUrl: config.publicUrl });
    }

    /**
     * `MastraAuthWorkos` as the *entry* resolved it. `vi.resetModules()` hands
     * every reload a fresh module registry, so a class imported at the top of
     * this file is a different class object from the one the entry just
     * constructed, and `instanceof` against it fails on a perfectly correct
     * provider. Re-importing inside the same generation asks the question the
     * assertion means to ask.
     */
    async function workosProvider(): Promise<Function> {
      return (await import('@mastra/auth-workos')).MastraAuthWorkos;
    }

    /**
     * Assert the entry selected platform-proxied identity — what omitting
     * `auth` used to get you implicitly, and what `createMastraPlatformAuth()`
     * now returns explicitly.
     *
     * Checked by provider name rather than `instanceof`: `@mastra/auth-studio`
     * is a transitive dependency of `@mastra/factory`, not one this package can
     * import, so there is no class here to compare against. (The SPA bans this
     * literal because branching on provider identity is the defect that gate
     * exists to stop; a test naming which provider was selected is exactly the
     * case the ban is not about, and that ban is scoped to `factory-ui`.)
     */
    function expectPlatformProvider(auth: FactoryConfig['auth']): void {
      expect(isAuthDisabled(auth), 'expected a provider, not AUTH_DISABLED').toBe(false);
      expect((auth as IMastraAuthProvider).name).toBe('mastra-studio');
    }

    const stubWorkosPair = () => {
      vi.stubEnv('WORKOS_API_KEY', 'sk_test_fake');
      vi.stubEnv('WORKOS_CLIENT_ID', 'client_fake');
      vi.stubEnv('WORKOS_COOKIE_PASSWORD', 'a-replica-stable-secret-of-32-plus-chars');
      // The deployment's public origin, which is where the /auth/callback
      // redirect_uri is derived from.
      vi.stubEnv('MASTRACODE_PUBLIC_URL', 'http://localhost:5873');
    };

    it('turns auth off entirely when MASTRACODE_AUTH_DISABLED is set', async () => {
      vi.stubEnv('MASTRACODE_AUTH_DISABLED', '1');
      // The slot has two inhabitants now — a provider, or AUTH_DISABLED — so
      // "off" is a value the entry states rather than the absence of one. The
      // old rule this comment used to teach (null disables, undefined asks for
      // the default) is gone: there is no default to ask for, and an opt-out
      // can no longer be spelled in a way that leaves the server gated.
      expect(isAuthDisabled((await captureFactoryConfig()).auth)).toBe(true);
    });

    it('selects a WorkOS provider when the WORKOS_* pair is configured', async () => {
      stubWorkosPair();
      const warn = vi.spyOn(console, 'warn');
      try {
        const config = await captureFactoryConfig();
        expect(config.auth).toBeInstanceOf(await workosProvider());

        const location = await loginRedirect(authRoutesFor(config));
        // The redirect must target WorkOS, not the platform's shared login —
        // self-hosted deploys have no allowed redirect_uri on platform.mastra.ai.
        expect(location).not.toContain('platform.mastra.ai');
        // Pins that the provider was constructed against this env's WORKOS_*
        // group, not merely that some WorkOS provider was selected.
        expect(location).toContain('client_id=client_fake');
        // WORKOS_REDIRECT_URI is unset here, so this also pins the callback's
        // derivation from the deployment's public URL — a wrong callback still
        // reaches WorkOS but breaks the OAuth return.
        expect(new URL(location).searchParams.get('redirect_uri')).toBe('http://localhost:5873/auth/callback');
        // The precedence warning belongs to the deferral branch only — a
        // healthy WorkOS selection must not claim its own config is ignored.
        expect(warn.mock.calls.some(call => String(call[0]).includes('ignored'))).toBe(false);
      } finally {
        warn.mockRestore();
      }
    });

    it('leaves the auth slot unset when only WORKOS_API_KEY is set', async () => {
      // varlock rejects an API-key-only env at the dev-script level; this
      // guards direct boot paths that bypass it. A half-configured pair must
      // not construct the provider (which would throw on the missing clientId)
      // — the entry falls through to platform-proxied identity and loads
      // without throwing. Note this soft fall-through is only the INFERENCE
      // path: `MASTRACODE_AUTH_PROVIDER=workos` with the same half-set pair is
      // a boot error, because then somebody asked for WorkOS by name.
      vi.stubEnv('WORKOS_API_KEY', 'sk_test_fake');
      expectPlatformProvider((await captureFactoryConfig()).auth);
    });

    it('defers to the platform when MASTRA_SHARED_API_URL is set, warning that WORKOS_* is ignored', async () => {
      stubWorkosPair();
      vi.stubEnv('MASTRA_SHARED_API_URL', 'https://shared.example.com/v1');
      const warn = vi.spyOn(console, 'warn');
      try {
        // Explicit platform deferral is the schema's highest-precedence auth
        // contract short of MASTRACODE_AUTH_PROVIDER: a fully configured
        // WORKOS_* pair still loses to it, and the entry names the
        // platform-proxied provider outright rather than leaving the slot unset.
        expectPlatformProvider((await captureFactoryConfig()).auth);
        expect(
          warn.mock.calls.some(
            call => String(call[0]).includes('WORKOS') && String(call[0]).includes('MASTRA_SHARED_API_URL'),
          ),
        ).toBe(true);
      } finally {
        warn.mockRestore();
      }
    });

    it('keeps WorkOS auth when MASTRA_PLATFORM_SECRET_KEY is set without MASTRA_SHARED_API_URL', async () => {
      // The platform secret key is a compute/integration credential, not an
      // identity signal: a self-hosted deployment can use platform sandboxes
      // for compute while running its own WorkOS sign-in. Explicit identity
      // config must win over the inferred platform association.
      stubWorkosPair();
      vi.stubEnv('MASTRA_PLATFORM_SECRET_KEY', 'sk_platform_fake');
      const config = await captureFactoryConfig();
      expect(config.auth).toBeInstanceOf(await workosProvider());
      const location = await loginRedirect(authRoutesFor(config));
      expect(location).not.toContain('platform.mastra.ai');
      expect(location).toContain('client_id=client_fake');
    });
  });
});
