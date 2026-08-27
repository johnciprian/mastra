---
'@mastra/auth': patch
---

Fixed the type of `getTokenIssuer`, which asked for the wrong argument.

It was declared as `(decoded: jwt.JwtPayload | null)` but its body reads `decoded.payload`, which only the complete `jwt.Jwt` that `decodeToken` returns carries. Nothing caught it because `JwtPayload` has an index signature, so passing a real payload compiled and then threw `Invalid token payload` at runtime. The parameter is now `jwt.Jwt | null` and the return is `string` instead of `any`.

```typescript
import { decodeToken, getTokenIssuer } from '@mastra/auth';

const decoded = await decodeToken(token);
const issuer = getTokenIssuer(decoded); // now typed `string`
```

Calls that pass the result of `decodeToken` are unaffected. A call that passed a bare payload is now a compile error instead of a runtime throw.
