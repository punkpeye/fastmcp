/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Type declarations for optional 'jose' peer dependency
 * This allows TypeScript to compile without jose installed
 */

declare module "jose" {
  export function createRemoteJWKSet(
    url: URL,
    options?: {
      cacheMaxAge?: number;
      cooldownDuration?: number;
    },
  ): any;

  export function jwtVerify(
    token: string,
    keySet: any,
    options?: {
      [key: string]: any;
      audience?: string | string[];
      issuer?: string | string[];
    },
  ): Promise<{
    payload: {
      [key: string]: any;
      aud?: string | string[];
      exp?: number;
      iat?: number;
      iss?: string;
      jti?: string;
      sub?: string;
    };
    protectedHeader: {
      [key: string]: any;
    };
  }>;
}
