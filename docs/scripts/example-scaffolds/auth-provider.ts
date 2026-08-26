/**
 * Fallback for a page that imports `./auth-provider` without showing it.
 *
 * When a page does show that file, the checker points its relative imports at
 * the composed fixture the page itself built, so the example is checked against
 * the documented provider. This file is only reached when no such fixture
 * exists, which is the case on reference pages that quote a conformance suite
 * to illustrate its shape rather than to build a provider.
 *
 * The exported names have to match what those pages import. A rename on a page
 * fails the check here, which is the intended coupling.
 */
// Imports here are deliberately minimal. A scaffold that imports a kit helper
// collides with a documented block that imports the same helper, and the
// resulting duplicate-identifier error names a line the reader never wrote.
import { MastraAuthProvider } from '@mastra/factory-auth'

/** The claims shape the quoted examples verify a token into. */
export interface ExampleClaims {
  sub: string
  email?: string
}

export class MyProvider extends MastraAuthProvider<ExampleClaims> {
  constructor(private readonly verifier: (token: string) => Promise<ExampleClaims | null> = async () => null) {
    super({ name: 'example' })
  }

  async authenticateToken(token: string): Promise<ExampleClaims | null> {
    return token === '' ? null : this.verifier(token)
  }

  authorizeUser(): boolean {
    return true
  }
}

/** Matches the factory shape the quoted conformance examples call. */
export function createAuth(verify: (token: string) => Promise<ExampleClaims | null>): MyProvider {
  return new MyProvider(verify)
}
