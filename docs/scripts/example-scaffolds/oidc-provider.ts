/**
 * Context for fragments whose provider verifies a token into OIDC claims
 * rather than into a finished user.
 *
 * Distinct from `provider.ts` because the two model different providers, and
 * conflating them would make a fragment type-check against a shape its own
 * prose never described. Here `verify` answers claims carrying `sub`, which is
 * what the `flatId` examples map onto an identity.
 */
import { MastraAuthProvider } from '@mastra/factory-auth'
import type { MastraAuthRequest } from '@mastra/factory-auth'

export interface OidcClaims {
  sub: string
  email?: string
}

export abstract class OidcScaffoldProvider extends MastraAuthProvider<{ id: string; email?: string }> {
  protected issuer!: string

  /** Verifies a token and answers the claims it carries, or null. */
  protected verify!: (token: string) => Promise<OidcClaims | null>

  authorizeUser(): boolean {
    return true
  }

  protected unusedRequestType(request: MastraAuthRequest): MastraAuthRequest {
    return request
  }
}
