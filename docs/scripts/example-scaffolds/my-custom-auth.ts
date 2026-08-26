/**
 * Fallback for a page that imports `./my-custom-auth` without showing it.
 *
 * `docs/auth/composite-auth.mdx` combines a built-in provider with a custom one
 * to make a point about composition, and sends the reader to
 * `/docs/auth/custom-auth-provider` for the custom provider itself. This stands
 * in for that file so the composition is still checked against the real
 * `CompositeAuth` contract.
 *
 * The exported name and the options the page passes are the coupling: a rename
 * on the page fails the check here, which is intended.
 */
import { MastraAuthProvider } from '@mastra/core/server'
import type { MastraAuthProviderOptions, MastraAuthRequest } from '@mastra/core/server'

export interface MyCustomUser {
  id: string
  name?: string
}

export interface MyCustomAuthOptions extends MastraAuthProviderOptions<MyCustomUser> {
  apiUrl?: string
}

export class MyCustomAuth extends MastraAuthProvider<MyCustomUser> {
  constructor(options?: MyCustomAuthOptions) {
    super({ name: options?.name ?? 'my-custom-auth' })
    this.registerOptions(options)
  }

  async authenticateToken(_token: string, _request: MastraAuthRequest): Promise<MyCustomUser | null> {
    return null
  }

  authorizeUser(): boolean {
    return true
  }
}
