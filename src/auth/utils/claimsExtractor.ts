/**
 * ClaimsExtractor
 * Securely extracts and filters custom claims from upstream OAuth tokens
 */

import type { CustomClaimsPassthroughConfig } from "../types.js";

export class ClaimsExtractor {
  private config: CustomClaimsPassthroughConfig;

  // Claims that MUST NOT be copied from upstream (protect proxy's JWT integrity)
  private readonly PROTECTED_CLAIMS = new Set([
    "aud",
    "client_id",
    "exp",
    "iat",
    "iss",
    "jti",
    "nbf",
  ]);

  constructor(config: boolean | CustomClaimsPassthroughConfig) {
    // Handle boolean shorthand: true = default config, false = disabled
    if (typeof config === "boolean") {
      config = config ? {} : { fromAccessToken: false, fromIdToken: false };
    }

    // Apply defaults
    this.config = {
      allowComplexClaims: config.allowComplexClaims || false,
      allowedClaims: config.allowedClaims,
      blockedClaims: config.blockedClaims || [],
      claimPrefix:
        config.claimPrefix !== undefined ? config.claimPrefix : false, // Default: no prefix
      fromAccessToken: config.fromAccessToken !== false, // Default: true
      fromIdToken: config.fromIdToken !== false, // Default: true
      maxClaimValueSize: config.maxClaimValueSize || 2000,
    };
  }

  /**
   * Extract claims from a token (access token or ID token)
   */
  async extract(
    token: string,
    tokenType: "access" | "id",
  ): Promise<null | Record<string, unknown>> {
    // Check if this token type is enabled
    if (tokenType === "access" && !this.config.fromAccessToken) {
      return null;
    }
    if (tokenType === "id" && !this.config.fromIdToken) {
      return null;
    }

    // Detect if token is JWT format (3 parts separated by dots)
    if (!this.isJWT(token)) {
      // Opaque token - no claims to extract
      return null;
    }

    // Decode JWT payload (base64url decode only, no signature verification)
    // We trust the token because it came from upstream via server-to-server exchange
    const payload = this.decodeJWTPayload(token);
    if (!payload) {
      return null;
    }

    // Filter and validate claims
    const filtered = this.filterClaims(payload);

    // Apply prefix if configured
    return this.applyPrefix(filtered);
  }

  /**
   * Apply prefix to claim names (if configured)
   */
  private applyPrefix(
    claims: Record<string, unknown>,
  ): Record<string, unknown> {
    const prefix = this.config.claimPrefix;

    // No prefix configured or explicitly disabled
    if (prefix === false || prefix === "" || prefix === undefined) {
      return claims;
    }

    // Apply prefix to all claim names
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(claims)) {
      result[`${prefix}${key}`] = value;
    }

    return result;
  }

  /**
   * Decode JWT payload without signature verification
   * Safe because token came from trusted upstream via server-to-server exchange
   */
  private decodeJWTPayload(token: string): null | Record<string, unknown> {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) {
        return null;
      }

      // Decode the payload (middle part)
      const payload = Buffer.from(parts[1], "base64url").toString("utf-8");
      return JSON.parse(payload) as Record<string, unknown>;
    } catch (error) {
      // Invalid JWT format or JSON
      console.warn(`Failed to decode JWT payload: ${error}`);
      return null;
    }
  }

  /**
   * Filter claims based on security rules
   */
  private filterClaims(
    claims: Record<string, unknown>,
  ): Record<string, unknown> {
    const result: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(claims)) {
      // RULE 1: Skip protected claims (ALWAYS enforced)
      if (this.PROTECTED_CLAIMS.has(key)) {
        continue;
      }

      // RULE 2: Skip blocked claims
      if (this.config.blockedClaims?.includes(key)) {
        continue;
      }

      // RULE 3: If allowlist exists, only include allowed claims
      if (
        this.config.allowedClaims &&
        !this.config.allowedClaims.includes(key)
      ) {
        continue;
      }

      // RULE 4: Validate claim value
      if (!this.isValidClaimValue(value)) {
        console.warn(`Skipping claim '${key}' due to invalid value`);
        continue;
      }

      result[key] = value;
    }

    return result;
  }

  /**
   * Check if a token is in JWT format
   */
  private isJWT(token: string): boolean {
    return token.split(".").length === 3;
  }

  /**
   * Validate a claim value (type and size checks)
   */
  private isValidClaimValue(value: unknown): boolean {
    if (value === null || value === undefined) {
      return false;
    }

    const type = typeof value;

    // Primitive types (string, number, boolean) are always allowed
    if (type === "string") {
      const maxSize = this.config.maxClaimValueSize ?? 2000;
      return (value as string).length <= maxSize;
    }

    if (type === "number" || type === "boolean") {
      return true;
    }

    // Arrays and objects only if explicitly allowed
    if (Array.isArray(value) || type === "object") {
      // Complex types not allowed by default (security)
      if (!this.config.allowComplexClaims) {
        return false;
      }

      // Check serialized size
      try {
        const stringified = JSON.stringify(value);
        const maxSize = this.config.maxClaimValueSize ?? 2000;
        return stringified.length <= maxSize;
      } catch {
        // Can't serialize - reject
        return false;
      }
    }

    // Unknown type - reject
    return false;
  }
}
