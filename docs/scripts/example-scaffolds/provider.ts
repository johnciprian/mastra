/**
 * Context for documentation fragments that show one method of a provider.
 *
 * Several pages explain an obligation by showing the method that satisfies it,
 * without re-listing the class around it. Those fragments are still worth
 * type-checking: they name real kit APIs, and a wrong import path or a changed
 * signature in one of them is exactly the drift this check exists to catch.
 *
 * So the checker composes a fragment into the class below rather than skipping
 * it. Everything here is scaffolding a page deliberately leaves out, and
 * nothing in this file is documentation. Keep it minimal: a field that only
 * exists here is a field a reader never saw declared, and if a fragment needs
 * one that is a signal the fragment is under-explained on the page.
 *
 * The class is `abstract` so a fragment that supplies `authenticateToken`
 * and one that does not are both valid compositions.
 */
import { MastraAuthProvider } from '@mastra/factory-auth'
import type { IMastraAuthProvider, MastraAuthProviderOptions, MastraAuthRequest } from '@mastra/factory-auth'

export interface ScaffoldUser {
  id: string
  email?: string
  name?: string
}

export interface ScaffoldOptions extends MastraAuthProviderOptions<ScaffoldUser> {
  issuer: string
}

/** Stands in for whatever cookie parser a page's prose tells the reader to write. */
export declare function readMyCookie(header: string): string

/** Stands in for a provider a page already has in hand. */
export declare const provider: IMastraAuthProvider

/** Stands in for a destination a page's surrounding route handler computed. */
export declare const returnTo: string

/** Stands in for a raw query-string value a page's route handler read. */
export declare const raw: string

export abstract class ScaffoldProvider extends MastraAuthProvider<ScaffoldUser> {
  protected issuer!: string
  protected states!: Map<string, { redirectUri: string }>
  protected cookieName!: string

  /** Returns the user shape this provider vouches for. */
  protected verify!: (token: string) => Promise<ScaffoldUser | null>

  authorizeUser(): boolean {
    return true
  }

  protected unusedRequestType(request: MastraAuthRequest): MastraAuthRequest {
    return request
  }
}
