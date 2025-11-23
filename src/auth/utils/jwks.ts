/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * JWKS (JSON Web Key Set) Verifier
 * Provides JWT verification using public keys from JWKS endpoints
 *
 * Requires the 'jose' package as an optional peer dependency.
 * Install with: npm install jose
 */

import type { TokenVerificationResult, TokenVerifier } from "../types.js";
import type { JWTClaims } from "./jwtIssuer.js";

/**
 * Token verification result
 */
export interface JWKSVerificationResult {
  claims?: JWTClaims;
  error?: string;
  valid: boolean;
}

/**
 * JWKS configuration options
 */
export interface JWKSVerifierConfig {
  /**
   * Expected token audience
   */
  audience?: string;

  /**
   * Cache duration for JWKS keys in milliseconds
   * @default 3600000 (1 hour)
   */
  cacheDuration?: number;

  /**
   * Cooldown duration between JWKS refetches in milliseconds
   * @default 30000 (30 seconds)
   */
  cooldownDuration?: number;

  /**
   * Expected token issuer
   */
  issuer?: string;

  /**
   * JWKS endpoint URL (e.g., https://provider.com/.well-known/jwks.json)
   */
  jwksUri: string;
}

/**
 * JWKS Verifier
 * Verifies JWTs using public keys from a JWKS endpoint
 *
 * This class requires the 'jose' package to be installed:
 * ```bash
 * npm install jose
 * ```
 *
 * @example
 * ```typescript
 * const verifier = new JWKSVerifier({
 *   jwksUri: 'https://accounts.google.com/.well-known/jwks.json',
 *   audience: 'your-client-id',
 *   issuer: 'https://accounts.google.com'
 * });
 *
 * const result = await verifier.verify(token);
 * if (result.valid) {
 *   console.log('Token claims:', result.claims);
 * }
 * ```
 */
export class JWKSVerifier implements TokenVerifier {
  private config: Required<JWKSVerifierConfig>;
  private jose: any;
  private joseLoaded = false;
  private jwksCache: any;

  constructor(config: JWKSVerifierConfig) {
    this.config = {
      cacheDuration: 3600000, // 1 hour
      cooldownDuration: 30000, // 30 seconds
      ...config,
      audience: config.audience || "",
      issuer: config.issuer || "",
    };
  }

  /**
   * Get the JWKS URI being used
   */
  getJwksUri(): string {
    return this.config.jwksUri;
  }

  /**
   * Refresh the JWKS cache
   * Useful if you need to force a key refresh
   */
  async refreshKeys(): Promise<void> {
    await this.loadJose();

    // Recreate the JWKS cache to force a refresh
    this.jwksCache = this.jose.createRemoteJWKSet(
      new URL(this.config.jwksUri),
      {
        cacheMaxAge: this.config.cacheDuration,
        cooldownDuration: this.config.cooldownDuration,
      },
    );
  }

  /**
   * Verify a JWT token using JWKS
   *
   * @param token - The JWT token to verify
   * @returns Verification result with claims if valid
   *
   * @example
   * ```typescript
   * const result = await verifier.verify(token);
   * if (result.valid) {
   *   console.log('User:', result.claims?.client_id);
   * } else {
   *   console.error('Invalid token:', result.error);
   * }
   * ```
   */
  async verify(token: string): Promise<TokenVerificationResult> {
    try {
      // Ensure jose is loaded
      await this.loadJose();

      // Verify the token using JWKS
      const verifyOptions: any = {};

      if (this.config.audience) {
        verifyOptions.audience = this.config.audience;
      }

      if (this.config.issuer) {
        verifyOptions.issuer = this.config.issuer;
      }

      const { payload } = await this.jose.jwtVerify(
        token,
        this.jwksCache,
        verifyOptions,
      );

      // Map jose claims to TokenVerificationResult format
      // Store all claims as Record<string, unknown> for compatibility
      const claims: Record<string, unknown> = {
        aud: payload.aud,
        client_id: payload.client_id || payload.sub,
        exp: payload.exp,
        iat: payload.iat,
        iss: payload.iss,
        jti: payload.jti || "",
        scope: this.parseScope(payload.scope),
        ...payload, // Include all other claims
      };

      return {
        claims,
        valid: true,
      };
    } catch (error: any) {
      return {
        error: error.message || "Token verification failed",
        valid: false,
      };
    }
  }

  /**
   * Lazy load the jose library
   * Only loads when verification is first attempted
   */
  private async loadJose(): Promise<void> {
    if (this.joseLoaded) {
      return;
    }

    try {
      this.jose = await import("jose");
      this.joseLoaded = true;

      // Create the JWKS cache with the configured URI
      this.jwksCache = this.jose.createRemoteJWKSet(
        new URL(this.config.jwksUri),
        {
          cacheMaxAge: this.config.cacheDuration,
          cooldownDuration: this.config.cooldownDuration,
        },
      );
    } catch (error: any) {
      throw new Error(
        `JWKS verification requires the 'jose' package.\n` +
          `Install it with: npm install jose\n\n` +
          `If you don't need JWKS support, use HS256 signing instead (default).\n\n` +
          `Original error: ${error.message}`,
      );
    }
  }

  /**
   * Parse scope from token payload
   * Handles both string (space-separated) and array formats
   */
  private parseScope(scope: unknown): string[] {
    if (!scope) {
      return [];
    }

    if (typeof scope === "string") {
      return scope.split(" ").filter(Boolean);
    }

    if (Array.isArray(scope)) {
      return scope;
    }

    return [];
  }
}
