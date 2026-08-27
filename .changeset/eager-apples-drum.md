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

Simplified how the Firebase provider maps a user to a memory resource id. It is now an ordinary `mapUserToResourceId` method rather than a function assigned in the constructor, which was a workaround for a bug in the shared provider base class that has since been fixed.

No behavior change: the resource id is still the Firebase `uid`, and passing your own `mapUserToResourceId` still overrides it.
