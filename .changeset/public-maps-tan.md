---
'@mastra/factory-auth': minor
---

`@mastra/factory-auth/capabilities` adds `AuthDescriptor` and `toAuthDescriptor`, so a sign-in screen can branch on what a provider does instead of on its name.

Branching on the name is why an unknown provider currently gets a GitHub logo and a "Continue with GitHub" button: the screen has no other question it knows how to ask.

```ts
import { toAuthDescriptor } from '@mastra/factory-auth';

app.get('/auth/me', c => c.json({ ...session, auth: toAuthDescriptor(provider) }));
// {
//   signIn: { kind: 'hosted', providerHint: 'generic' },
//   features: { logout: true, organizations: false, refresh: false, sessionRevocation: false },
// }
```

The descriptor is derived from the structural guards, so it is pure, synchronous and correct for a provider nobody has heard of. Pass overrides for the two things no guard can answer: `label` and `providerHint`.

**`signIn.kind: 'none'` means the provider cannot sign you in from a browser.** It does not mean auth is off. A `none` provider validates bearer tokens and rejects unauthenticated requests; it just implements neither a hosted login nor a credentials sign-in, which is what the Supabase and Firebase providers are today. A deployment with auth disabled has no provider and no descriptor at all. Render `none` as an explanation and a pointer to whoever issues tokens, not as an empty sign-in box.

**`signIn.providerHint` is a rendering token, not a provider name.** It is a closed union - `'generic' | 'sso' | 'oauth' | 'email'` - defaulting to `'generic'`. A free-form vendor string would put vendor names back into the UI as branch conditions, which is the coupling the descriptor exists to remove.

**`signUpEnabled` answers `true` only for a literal `true`.** `isSignUpEnabled` is declared synchronous, but nothing stops a provider writing `async isSignUpEnabled()` — and an `async` method returns a Promise, which is truthy. A loose reader would show a sign-up link on a deployment that had switched sign-up off, and nothing would look broken to anyone. An absent method still means "sign-up is on", which is the contract's documented default; a method that answers a Promise, a throw, or anything else means `false`. A rejecting Promise is judged without being awaited and without leaving an unhandled rejection behind. Run the conformance suite and `credentials/sign-up-enabled` will tell a provider author about it in a sentence rather than leaving them to notice a missing link.

**`signIn.signUpEnabled` is positive: `true` means sign-up is available.** The wire field a Factory UI reads today is `signUpDisabled`, the opposite way round, and both ride in one payload during the transition. Treat the descriptor as authoritative, and check the polarity at every call site.

**`features.refresh` and `features.sessionRevocation` are checked as methods, not inferred from the session guard.** The guard tests two of `ISessionProvider`'s seven members, so a provider can satisfy it with no `destroySession` at all.

Deliberately smaller than the enterprise capability model: no role-based access control, no fine-grained authorization, no licence gate, no telemetry.
