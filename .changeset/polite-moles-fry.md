---
'@mastra/factory-auth': patch
'@mastra/factory': patch
'@mastra/auth-better-auth': patch
'@mastra/server': patch
'@mastra/auth-firebase': patch
'@mastra/auth-supabase': patch
'@mastra/auth-google': patch
'@mastra/auth-studio': patch
'@mastra/auth-workos': patch
'@mastra/auth-auth0': patch
'@mastra/auth-clerk': patch
'@mastra/auth-cloud': patch
'@mastra/auth-neon': patch
'@mastra/auth-okta': patch
---

Declared `IOrganizationsProvider` on `MastraAuthFirebase` and `MastraAuthSupabase`. Both already implemented `ensureOrganization` and `isOrganizationAdmin`, and both passed `isOrganizationsProvider` at run time, but neither said so in its type — so nothing checked the members against the interface. Declaring it is type-only and changes no behavior; it means the compiler now holds these two to the interface they were already satisfying.
