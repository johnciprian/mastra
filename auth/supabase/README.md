# @mastra/auth-supabase

A Supabase authentication integration for Mastra. It validates Supabase access tokens on your API,
authorizes the users it authenticates, and resolves an organization for them.

## It cannot sign you in from a browser

This is the first thing to know, because the package name suggests otherwise. `@mastra/auth-supabase`
is a **bearer-token validator**. It gates your API. It cannot take somebody from a blank browser to a
signed-in session, so it cannot run the Mastra Factory's browser sign-in flow, and this is a decision
rather than a gap waiting to be filled.

Two reasons, both about Supabase rather than about this package:

- **`signInWithOAuth` cannot carry the host's OAuth `state`.** Supabase's hosted OAuth goes through
  GoTrue's `/authorize`, which mints its own `state` for the handshake with the upstream identity
  provider. The `state` is the value a host uses to carry a nonce and the page the person was heading
  for; without it the callback cannot be tied back to the request that started it.
- **The PKCE code verifier lives in the supabase-js client's storage.** Sign-in and callback are two
  separate HTTP requests, so a server-side integration needs a store shared between them — cookies,
  in practice, which is what `@supabase/ssr` exists to provide. That is per-deployment
  infrastructure, not a decision a provider package can make for you.

**What to do instead.** Use this provider as it is: issue Supabase access tokens to your clients and
send them as `Authorization: Bearer <token>`. If you need a browser sign-in for the Factory, configure
a provider that owns a server-side hosted login, or wrap Supabase in your own `ISSOProvider` built on
`@supabase/ssr` with a cookie-backed storage adapter — in your own deployment, where you can test it
against your project.

The decision, its full reasoning, and a one-line summary you can log are exported as
`FACTORY_BROWSER_SIGN_IN`, and the provider carries it as `provider.factoryBrowserSignIn`.
`src/conformance.test.ts` runs the Factory conformance suite against this package and records exactly
which checks apply, which are skipped, and why.

## Requirements

- Node.js 22.13.0 or later
- Supabase project with authentication enabled
- Supabase URL and anonymous key

## Installation

```bash
npm install @mastra/auth-supabase
# or
yarn add @mastra/auth-supabase
# or
pnpm add @mastra/auth-supabase
```

## Usage

```typescript
import { Mastra } from '@mastra/core/mastra';
import { MastraAuthSupabase } from '@mastra/auth-supabase';

// Initialize with environment variables
const supabaseAuth = new MastraAuthSupabase();

// Or initialize with explicit configuration
const supabaseAuth = new MastraAuthSupabase({
  url: 'your-supabase-url',
  anonKey: 'your-supabase-anon-key',
});

// Enable auth in Mastra
const mastra = new Mastra({
  ...
  server: {
    auth: supabaseAuth,
  },
});
```

## Configuration

The package can be configured in two ways:

1. **Environment Variables**:
   - `SUPABASE_URL`: Your Supabase project URL
   - `SUPABASE_ANON_KEY`: Your Supabase anonymous key

2. **Constructor Options**:

   ```typescript
   interface MastraAuthSupabaseOptions {
     url?: string;
     anonKey?: string;
     /** Use this client instead of building one. Also how tests run offline. */
     client?: SupabaseClient;
     /** Restore the pre-1.2 `users.isAdmin` authorization gate. Off by default. */
     requireAdminRow?: boolean;
   }
   ```

## Features

- **Authentication**: verifies Supabase access tokens and returns the Supabase user
- **Authorization**: allows any authenticated user by default, and is replaceable
- **Organizations**: derives a stable personal organization id, `user:${userId}`
- **Type Safety**: full TypeScript support with proper type definitions
- **Environment Variable Support**: easy configuration through environment variables

## API

### `authenticateToken(token: string)`

Verifies a Supabase access token and returns the Supabase user, or `null`. An empty token returns
`null` without a round trip: it is how the host says the request carried no bearer token, and this
provider reads no cookie.

### `authorizeUser(user: User)`

Returns `true` for any user this provider authenticated, and `false` for a payload that names nobody.
It never throws and never calls out to Supabase.

**This default changed in 1.2, and the change is why it is worth reading.** Previously this method
looked up a `users` table and allowed only rows with a truthy `isAdmin` column. That is authorization
policy resting on infrastructure the Mastra provider contract never mentions, so every deployment
without that exact table authenticated a user and then answered 403 to every core `/api/*` request,
with nothing in the response naming the missing table.

To keep the old behaviour, ask for it:

```typescript
const supabaseAuth = new MastraAuthSupabase({ requireAdminRow: true });
```

Or supply your own policy, which is what most deployments should do:

```typescript
const supabaseAuth = new MastraAuthSupabase({
  authorizeUser: async user => user.app_metadata?.role === 'staff',
});
```

### `ensureOrganization(userId: string)`

Returns `user:${userId}`. Supabase has no organization primitive, so the id is derived rather than
stored: it is a pure function of the user id, identical in every process and every deploy, which is
what the Factory's organization-scoped storage needs. This is the same value
`withSyntheticOrganizations` from `@mastra/factory-auth/organizations` would supply; it is
implemented on the provider so that wrapping is optional rather than required.

### `isOrganizationAdmin(organizationId: string, userId: string)`

Every organization here belongs to one person, so this is true exactly when the organization is
theirs.
