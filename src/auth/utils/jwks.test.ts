import { describe, expect, it } from "vitest";

import type { JWTClaims } from "./jwtIssuer.js";

import { requireScopes } from "../helpers.js";
import { JWKSVerifier } from "./jwks.js";

/**
 * Drive `JWKSVerifier.verify()` against a stubbed `jose` so the claim-mapping
 * block can be exercised without a live JWKS endpoint.
 */
async function verifyPayload(payload: Record<string, unknown>) {
  const verifier = new JWKSVerifier({
    jwksUri: "https://example.com/.well-known/jwks.json",
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const internals = verifier as any;
  internals.joseLoaded = true;
  internals.jose = {
    jwtVerify: async () => ({ payload }),
  };

  return verifier.verify("header.payload.signature");
}

describe("JWKSVerifier", () => {
  describe("scope normalization", () => {
    it("should parse a space-delimited scope string into an array", async () => {
      const result = await verifyPayload({
        scope: "read:user write:data",
        sub: "user-1",
      });

      expect(result.valid).toBe(true);
      expect(result.claims?.scope).toEqual(["read:user", "write:data"]);
    });

    it("should pass an array scope through unchanged", async () => {
      const result = await verifyPayload({
        scope: ["read:user", "write:data"],
        sub: "user-1",
      });

      expect(result.claims?.scope).toEqual(["read:user", "write:data"]);
    });

    it("should default a missing scope to an empty array", async () => {
      const result = await verifyPayload({ sub: "user-1" });

      expect(result.claims?.scope).toEqual([]);
    });

    it("should always produce the string[] that JWTClaims declares", async () => {
      for (const scope of ["read", ["read"], undefined, "", 42]) {
        const result = await verifyPayload({ scope, sub: "user-1" });

        expect(Array.isArray(result.claims?.scope)).toBe(true);
      }
    });
  });

  describe("scope consumers", () => {
    it("should satisfy requireScopes for a space-delimited upstream scope", async () => {
      // RFC 9068 puts `scope` in an access token as a space-delimited string.
      // A raw string reaching `requireScopes` fails every check, because the
      // Set is built from the string's absence of array-ness.
      const result = await verifyPayload({
        scope: "read:user write:data",
        sub: "user-1",
      });

      const canAccess = requireScopes("read:user");
      expect(canAccess({ scopes: result.claims?.scope } as never)).toBe(true);
    });

    it("should not let a longer scope satisfy a prefix of it", async () => {
      // `"read:userdata".includes("read:user")` is true for a string but false
      // for the correctly-split array, so leaking the string form widens
      // access rather than merely breaking it.
      const result = await verifyPayload({
        scope: "read:userdata",
        sub: "user-1",
      });

      const canAccess = requireScopes("read:user");
      expect(canAccess({ scopes: result.claims?.scope } as never)).toBe(false);
    });

    it("should expose a scope that supports array methods", async () => {
      const result = await verifyPayload({ scope: "read write", sub: "u" });

      const scope = (result.claims as unknown as JWTClaims).scope;
      expect(scope.join(" ")).toBe("read write");
      expect(scope.includes("read")).toBe(true);
    });
  });

  describe("claim mapping", () => {
    it("should preserve custom claims from the payload", async () => {
      const result = await verifyPayload({
        email: "user@example.com",
        role: "admin",
        scope: "read",
        sub: "user-1",
      });

      expect(result.claims?.email).toBe("user@example.com");
      expect(result.claims?.role).toBe("admin");
      expect(result.claims?.sub).toBe("user-1");
    });

    it("should copy the standard claims through", async () => {
      const result = await verifyPayload({
        aud: "https://mcp.example.com",
        exp: 2000,
        iat: 1000,
        iss: "https://issuer.example.com",
        jti: "token-id",
        sub: "user-1",
      });

      expect(result.claims?.aud).toBe("https://mcp.example.com");
      expect(result.claims?.exp).toBe(2000);
      expect(result.claims?.iat).toBe(1000);
      expect(result.claims?.iss).toBe("https://issuer.example.com");
      expect(result.claims?.jti).toBe("token-id");
    });

    it("should fall back to sub for a missing client_id", async () => {
      const result = await verifyPayload({ sub: "user-42" });

      expect(result.claims?.client_id).toBe("user-42");
    });

    it("should keep an explicit client_id over sub", async () => {
      const result = await verifyPayload({
        client_id: "client-abc",
        sub: "user-42",
      });

      expect(result.claims?.client_id).toBe("client-abc");
    });

    it("should default a missing jti to an empty string", async () => {
      const result = await verifyPayload({ sub: "user-1" });

      expect(result.claims?.jti).toBe("");
    });
  });

  describe("verify failures", () => {
    it("should report the error when jose rejects the token", async () => {
      const verifier = new JWKSVerifier({
        jwksUri: "https://example.com/.well-known/jwks.json",
      });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const internals = verifier as any;
      internals.joseLoaded = true;
      internals.jose = {
        jwtVerify: async () => {
          throw new Error("signature verification failed");
        },
      };

      const result = await verifier.verify("bad.token.here");

      expect(result.valid).toBe(false);
      expect(result.error).toBe("signature verification failed");
      expect(result.claims).toBeUndefined();
    });
  });

  describe("getJwksUri", () => {
    it("should return the configured URI", () => {
      const verifier = new JWKSVerifier({
        jwksUri: "https://example.com/.well-known/jwks.json",
      });

      expect(verifier.getJwksUri()).toBe(
        "https://example.com/.well-known/jwks.json",
      );
    });
  });
});
