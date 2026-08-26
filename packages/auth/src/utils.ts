import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

export type JwtPayload = jwt.JwtPayload;

export async function decodeToken(accessToken: string) {
  const decoded = jwt.decode(accessToken, { complete: true });
  return decoded;
}

/**
 * Read the `iss` claim off a decoded token.
 *
 * The parameter is the `Jwt` that {@link decodeToken} returns, not a bare
 * payload: the body reads `decoded.payload`, which only the complete `Jwt`
 * carries. It was declared as `jwt.JwtPayload | null` for a long time, and
 * nothing caught it because `JwtPayload` carries an `[key: string]: any` index
 * signature, so `decoded.payload` type-checked as `any` and a `Jwt` argument
 * was assignable to the wrong declaration. The cost was real: a caller who
 * believed the declaration and passed an actual payload compiled cleanly and
 * threw `Invalid token payload` at runtime.
 */
export function getTokenIssuer(decoded: jwt.Jwt | null): string {
  if (!decoded) throw new Error('Invalid token');
  if (!decoded.payload || typeof decoded.payload !== 'object') throw new Error('Invalid token payload');
  if (!decoded.payload.iss) throw new Error('Invalid token header');
  return decoded.payload.iss;
}

export async function verifyHmac(accessToken: string, secret: string) {
  const decoded = jwt.decode(accessToken, { complete: true });

  if (!decoded) throw new Error('Invalid token');

  return jwt.verify(accessToken, secret) as jwt.JwtPayload;
}

export async function verifyJwks(accessToken: string, jwksUri: string) {
  const decoded = jwt.decode(accessToken, { complete: true });

  if (!decoded) throw new Error('Invalid token');

  const client = jwksClient({ jwksUri });
  const key = await client.getSigningKey(decoded.header.kid);
  const signingKey = key.getPublicKey();
  return jwt.verify(accessToken, signingKey) as jwt.JwtPayload;
}
