/**
 * JWT Issuer for OAuth Proxy
 * Issues and validates short-lived JWTs that reference upstream provider tokens
 */

import { createHmac, pbkdf2, randomBytes } from "crypto";
import { promisify } from "util";

const pbkdf2Async = promisify(pbkdf2);

/**
 * JWT Header
 */
interface JWTHeader {
  alg: string;
  typ: string;
}

/**
 * JWT Claims for FastMCP tokens
 */
export interface JWTClaims {
  /** Audience */
  aud: string;
  /** Client ID */
  client_id: string;
  /** Expiration time (seconds since epoch) */
  exp: number;
  /** Issued at time (seconds since epoch) */
  iat: number;
  /** Issuer */
  iss: string;
  /** JWT ID (unique identifier) */
  jti: string;
  /** Scopes */
  scope: string[];
}

/**
 * Token validation result
 */
export interface TokenValidationResult {
  /** Decoded claims if valid */
  claims?: JWTClaims;
  /** Error message if invalid */
  error?: string;
  /** Whether token is valid */
  valid: boolean;
}

/**
 * JWT Issuer configuration
 */
export interface JWTIssuerConfig {
  /** Token expiration in seconds (default: 3600 = 1 hour) */
  accessTokenTtl?: number;
  /** Audience for issued tokens */
  audience: string;
  /** Issuer identifier */
  issuer: string;
  /** Refresh token expiration in seconds (default: 2592000 = 30 days) */
  refreshTokenTtl?: number;
  /** Secret key for signing tokens */
  signingKey: string;
}

/**
 * JWT Issuer
 * Issues and validates HS256-signed JWTs for the OAuth proxy
 */
export class JWTIssuer {
  private accessTokenTtl: number;
  private audience: string;
  private issuer: string;
  private refreshTokenTtl: number;
  private signingKey: Buffer;

  constructor(config: JWTIssuerConfig) {
    this.issuer = config.issuer;
    this.audience = config.audience;
    this.accessTokenTtl = config.accessTokenTtl || 3600; // 1 hour
    this.refreshTokenTtl = config.refreshTokenTtl || 2592000; // 30 days
    this.signingKey = Buffer.from(config.signingKey);
  }

  /**
   * Derive a signing key from a secret
   * Uses PBKDF2 for key derivation
   */
  static async deriveKey(
    secret: string,
    iterations: number = 100000,
  ): Promise<string> {
    const salt = Buffer.from("fastmcp-oauth-proxy");
    const key = await pbkdf2Async(secret, salt, iterations, 32, "sha256");
    return key.toString("base64");
  }

  /**
   * Issue an access token
   */
  issueAccessToken(clientId: string, scope: string[]): string {
    const now = Math.floor(Date.now() / 1000);
    const jti = this.generateJti();

    const claims: JWTClaims = {
      aud: this.audience,
      client_id: clientId,
      exp: now + this.accessTokenTtl,
      iat: now,
      iss: this.issuer,
      jti,
      scope,
    };

    return this.signToken(claims);
  }

  /**
   * Issue a refresh token
   */
  issueRefreshToken(clientId: string, scope: string[]): string {
    const now = Math.floor(Date.now() / 1000);
    const jti = this.generateJti();

    const claims: JWTClaims = {
      aud: this.audience,
      client_id: clientId,
      exp: now + this.refreshTokenTtl,
      iat: now,
      iss: this.issuer,
      jti,
      scope,
    };

    return this.signToken(claims);
  }

  /**
   * Validate a JWT token
   */
  async verify(token: string): Promise<TokenValidationResult> {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) {
        return {
          error: "Invalid token format",
          valid: false,
        };
      }

      const [headerB64, payloadB64, signatureB64] = parts;

      // Verify signature
      const expectedSignature = this.sign(`${headerB64}.${payloadB64}`);
      if (signatureB64 !== expectedSignature) {
        return {
          error: "Invalid signature",
          valid: false,
        };
      }

      // Decode claims
      const claims: JWTClaims = JSON.parse(
        Buffer.from(payloadB64, "base64url").toString("utf-8"),
      );

      // Validate claims
      const now = Math.floor(Date.now() / 1000);

      if (claims.exp <= now) {
        return {
          claims,
          error: "Token expired",
          valid: false,
        };
      }

      if (claims.iss !== this.issuer) {
        return {
          claims,
          error: "Invalid issuer",
          valid: false,
        };
      }

      if (claims.aud !== this.audience) {
        return {
          claims,
          error: "Invalid audience",
          valid: false,
        };
      }

      return {
        claims,
        valid: true,
      };
    } catch (error) {
      return {
        error: error instanceof Error ? error.message : "Validation failed",
        valid: false,
      };
    }
  }

  /**
   * Generate unique JWT ID
   */
  private generateJti(): string {
    return randomBytes(16).toString("base64url");
  }

  /**
   * Sign data with HMAC-SHA256
   */
  private sign(data: string): string {
    const hmac = createHmac("sha256", this.signingKey);
    hmac.update(data);
    return hmac.digest("base64url");
  }

  /**
   * Sign a JWT token
   */
  private signToken(claims: JWTClaims): string {
    const header: JWTHeader = {
      alg: "HS256",
      typ: "JWT",
    };

    const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(claims)).toString(
      "base64url",
    );

    const signature = this.sign(`${headerB64}.${payloadB64}`);

    return `${headerB64}.${payloadB64}.${signature}`;
  }
}
