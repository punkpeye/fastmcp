import { describe, expect, it } from "vitest";

import { JWTIssuer } from "./jwtIssuer.js";

describe("JWTIssuer", () => {
  const issuer = new JWTIssuer({
    accessTokenTtl: 3600,
    audience: "https://example.com",
    issuer: "https://oauth.example.com",
    refreshTokenTtl: 86400,
    signingKey: "test-secret-key",
  });

  describe("issueAccessToken", () => {
    it("should issue a valid access token", async () => {
      const token = issuer.issueAccessToken("client-123", [
        "read",
        "write",
      ]);

      expect(token).toBeTruthy();
      expect(token.split(".")).toHaveLength(3);

      const result = await issuer.verify(token);
      expect(result.valid).toBe(true);
      expect(result.claims?.client_id).toBe("client-123");
      expect(result.claims?.scope).toEqual(["read", "write"]);
      expect(result.claims?.iss).toBe("https://oauth.example.com");
      expect(result.claims?.aud).toBe("https://example.com");
    });

    it("should include unique JTI in each token", async () => {
      const token1 = issuer.issueAccessToken("client-123", ["read"]);
      const token2 = issuer.issueAccessToken("client-123", ["read"]);

      const result1 = await issuer.verify(token1);
      const result2 = await issuer.verify(token2);

      expect(result1.claims?.jti).toBeTruthy();
      expect(result2.claims?.jti).toBeTruthy();
      expect(result1.claims?.jti).not.toBe(result2.claims?.jti);
    });

    it("should set correct expiration time", async () => {
      const token = issuer.issueAccessToken("client-123", ["read"]);
      const result = await issuer.verify(token);

      const now = Math.floor(Date.now() / 1000);
      expect(result.claims?.exp).toBeGreaterThan(now);
      expect(result.claims?.exp).toBeLessThanOrEqual(now + 3601); // Allow 1s tolerance
    });
  });

  describe("issueRefreshToken", () => {
    it("should issue a valid refresh token", async () => {
      const token = issuer.issueRefreshToken("client-123", ["read", "write"]);

      expect(token).toBeTruthy();
      expect(token.split(".")).toHaveLength(3);

      const result = await issuer.verify(token);
      expect(result.valid).toBe(true);
      expect(result.claims?.client_id).toBe("client-123");
      expect(result.claims?.scope).toEqual(["read", "write"]);
    });

    it("should have longer TTL than access token", async () => {
      const accessToken = issuer.issueAccessToken("client-123", ["read"]);
      const refreshToken = issuer.issueRefreshToken("client-123", ["read"]);

      const accessResult = await issuer.verify(accessToken);
      const refreshResult = await issuer.verify(refreshToken);

      expect(refreshResult.claims?.exp).toBeGreaterThan(
        accessResult.claims?.exp || 0,
      );
    });
  });

  describe("verify", () => {
    it("should validate a valid token", async () => {
      const token = issuer.issueAccessToken("client-123", ["read"]);
      const result = await issuer.verify(token);

      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
      expect(result.claims).toBeTruthy();
    });

    it("should reject tokens with invalid signature", async () => {
      const token = issuer.issueAccessToken("client-123", ["read"]);
      const [header, payload] = token.split(".");
      const tamperedToken = `${header}.${payload}.invalid-signature`;

      const result = await issuer.verify(tamperedToken);

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid signature");
    });

    it("should reject tokens with tampered payload", async () => {
      const token = issuer.issueAccessToken("client-123", ["read"]);
      const [header, , signature] = token.split(".");

      // Create tampered payload
      const tamperedClaims = {
        aud: "https://example.com",
        client_id: "client-456",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "https://oauth.example.com",
        jti: "tampered",
        scope: ["admin"],
      };
      const tamperedPayload = Buffer.from(
        JSON.stringify(tamperedClaims),
      ).toString("base64url");
      const tamperedToken = `${header}.${tamperedPayload}.${signature}`;

      const result = await issuer.verify(tamperedToken);

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid signature");
    });

    it("should reject expired tokens", async () => {
      const shortLivedIssuer = new JWTIssuer({
        accessTokenTtl: 1, // 1 second
        audience: "https://example.com",
        issuer: "https://oauth.example.com",
        signingKey: "test-secret-key",
      });

      const token = shortLivedIssuer.issueAccessToken("client-123", ["read"]);

      // Wait for token to expire
      await new Promise((resolve) => setTimeout(resolve, 1100));

      const result = await shortLivedIssuer.verify(token);

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Token expired");
      expect(result.claims).toBeTruthy(); // Claims should still be decoded
    });

    it("should reject tokens with wrong issuer", async () => {
      const otherIssuer = new JWTIssuer({
        audience: "https://example.com",
        issuer: "https://other-issuer.com",
        signingKey: "test-secret-key",
      });

      const token = otherIssuer.issueAccessToken("client-123", ["read"]);
      const result = await issuer.verify(token);

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid issuer");
    });

    it("should reject tokens with wrong audience", async () => {
      const otherAudienceIssuer = new JWTIssuer({
        audience: "https://other-audience.com",
        issuer: "https://oauth.example.com",
        signingKey: "test-secret-key",
      });

      const token = otherAudienceIssuer.issueAccessToken("client-123", [
        "read",
      ]);
      const result = await issuer.verify(token);

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid audience");
    });

    it("should reject malformed tokens", async () => {
      const results = await Promise.all([
        issuer.verify("not-a-jwt"),
        issuer.verify("only.two.parts"),
        issuer.verify(""),
        issuer.verify("too.many.parts.here.now"),
      ]);

      for (const result of results) {
        expect(result.valid).toBe(false);
        expect(result.error).toBeTruthy();
      }
    });
  });

  describe("deriveKey", () => {
    it("should derive a key from a secret", async () => {
      const key = await JWTIssuer.deriveKey("my-secret");

      expect(key).toBeTruthy();
      expect(typeof key).toBe("string");
      expect(key.length).toBeGreaterThan(0);
    });

    it("should derive consistent keys from same secret", async () => {
      const key1 = await JWTIssuer.deriveKey("my-secret");
      const key2 = await JWTIssuer.deriveKey("my-secret");

      expect(key1).toBe(key2);
    });

    it("should derive different keys from different secrets", async () => {
      const key1 = await JWTIssuer.deriveKey("secret-1");
      const key2 = await JWTIssuer.deriveKey("secret-2");

      expect(key1).not.toBe(key2);
    });

    it("should support custom iteration count", async () => {
      const key1 = await JWTIssuer.deriveKey("my-secret", 10000);
      const key2 = await JWTIssuer.deriveKey("my-secret", 100000);

      // Different iterations should produce different keys
      expect(key1).not.toBe(key2);
    });
  });

  describe("token format", () => {
    it("should produce RFC 7519 compliant JWT structure", async () => {
      const token = issuer.issueAccessToken("client-123", ["read"]);
      const [headerB64, payloadB64, signatureB64] = token.split(".");

      // Decode header
      const header = JSON.parse(
        Buffer.from(headerB64, "base64url").toString("utf-8"),
      );
      expect(header.alg).toBe("HS256");
      expect(header.typ).toBe("JWT");

      // Decode payload
      const payload = JSON.parse(
        Buffer.from(payloadB64, "base64url").toString("utf-8"),
      );
      expect(payload.iss).toBeTruthy();
      expect(payload.aud).toBeTruthy();
      expect(payload.exp).toBeTruthy();
      expect(payload.iat).toBeTruthy();
      expect(payload.jti).toBeTruthy();
      expect(payload.client_id).toBeTruthy();
      expect(payload.scope).toBeTruthy();

      // Signature should be base64url encoded
      expect(signatureB64).toMatch(/^[A-Za-z0-9_-]+$/);
    });
  });
});
