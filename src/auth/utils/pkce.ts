/**
 * PKCE (Proof Key for Code Exchange) Utilities
 * Implements RFC 7636 for OAuth 2.0 public clients
 */

import { createHash, randomBytes } from "crypto";

import type { PKCEPair } from "../types.js";

/**
 * PKCE utility class for generating and validating code challenges
 */
export class PKCEUtils {
  /**
   * Generate a code challenge from a verifier
   * @param verifier The code verifier
   * @param method Challenge method: 'S256' or 'plain' (default: 'S256')
   * @returns Base64URL-encoded challenge string
   */
  static generateChallenge(
    verifier: string,
    method: "plain" | "S256" = "S256",
  ): string {
    if (method === "plain") {
      return verifier;
    }

    if (method === "S256") {
      const hash = createHash("sha256");
      hash.update(verifier);
      return PKCEUtils.base64URLEncode(hash.digest());
    }

    throw new Error(`Unsupported challenge method: ${method}`);
  }

  /**
   * Generate a complete PKCE pair (verifier + challenge)
   * @param method Challenge method: 'S256' or 'plain' (default: 'S256')
   * @returns Object containing verifier and challenge
   */
  static generatePair(method: "plain" | "S256" = "S256"): PKCEPair {
    const verifier = PKCEUtils.generateVerifier();
    const challenge = PKCEUtils.generateChallenge(verifier, method);

    return {
      challenge,
      verifier,
    };
  }

  /**
   * Generate a cryptographically secure code verifier
   * @param length Length of verifier (43-128 characters, default: 128)
   * @returns Base64URL-encoded verifier string
   */
  static generateVerifier(length: number = 128): string {
    if (length < 43 || length > 128) {
      throw new Error("PKCE verifier length must be between 43 and 128");
    }

    // Generate random bytes and encode as base64url
    // Need more bytes because base64 encoding expands data
    const byteLength = Math.ceil((length * 3) / 4);
    const randomBytesBuffer = randomBytes(byteLength);

    return PKCEUtils.base64URLEncode(randomBytesBuffer).slice(0, length);
  }

  /**
   * Validate a code verifier against a challenge
   * @param verifier The code verifier to validate
   * @param challenge The expected challenge
   * @param method The challenge method used
   * @returns True if verifier matches challenge
   */
  static validateChallenge(
    verifier: string,
    challenge: string,
    method: string,
  ): boolean {
    if (!verifier || !challenge) {
      return false;
    }

    if (method === "plain") {
      return verifier === challenge;
    }

    if (method === "S256") {
      const computedChallenge = PKCEUtils.generateChallenge(verifier, "S256");
      return computedChallenge === challenge;
    }

    // Unknown method
    return false;
  }

  /**
   * Encode a buffer as base64url (RFC 4648)
   * @param buffer Buffer to encode
   * @returns Base64URL-encoded string
   */
  private static base64URLEncode(buffer: Buffer): string {
    return buffer
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }
}
