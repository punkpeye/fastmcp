/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, expect, it } from "vitest";

import type { TokenRequest, UpstreamTokenSet } from "./types.js";

import { OAuthProxy } from "./OAuthProxy.js";
import { JWTIssuer } from "./utils/jwtIssuer.js";
import { PKCEUtils } from "./utils/pkce.js";
import { MemoryTokenStorage } from "./utils/tokenStore.js";

describe("OAuthProxy - Token Swap Pattern", () => {
  const baseConfig = {
    baseUrl: "https://proxy.example.com",
    consentRequired: false,
    upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
    upstreamClientId: "upstream-client-id",
    upstreamClientSecret: "upstream-client-secret",
    upstreamTokenEndpoint: "https://provider.com/oauth/token",
  };

  describe("Token Swap Enabled", () => {
    it("should auto-generate jwtSigningKey when not provided", () => {
      // Should not throw - jwtSigningKey is now auto-generated
      expect(() => {
        new OAuthProxy({
          ...baseConfig,
          enableTokenSwap: true,
          // Missing jwtSigningKey - will be auto-generated
        });
      }).not.toThrow();
    });

    it("should issue JWT tokens instead of upstream tokens", async () => {
      const proxy = new OAuthProxy({
        ...baseConfig,
        enableTokenSwap: true,
        jwtSigningKey: "test-signing-key",
      });

      // Simulate authorization code exchange
      const upstreamTokens: UpstreamTokenSet = {
        accessToken: "upstream-access-token",
        expiresIn: 3600,
        issuedAt: new Date(),
        refreshToken: "upstream-refresh-token",
        scope: ["read", "write"],
        tokenType: "Bearer",
      };

      // Register a client
      await proxy.registerClient({
        redirect_uris: ["https://client.example.com/callback"],
      });

      // Generate proper PKCE pair
      const pkce = PKCEUtils.generatePair("S256");

      // Create a transaction and authorization code manually
      const transaction = await (proxy as any).createTransaction({
        client_id: "upstream-client-id",
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
        redirect_uri: "https://client.example.com/callback",
        response_type: "code",
        scope: "read write",
      });

      const authCode = await (proxy as any).generateAuthorizationCode(
        transaction,
        upstreamTokens,
      );

      // Exchange authorization code
      const tokenRequest: TokenRequest = {
        client_id: "upstream-client-id",
        code: authCode,
        code_verifier: pkce.verifier,
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      const response = await proxy.exchangeAuthorizationCode(tokenRequest);

      // Verify we got JWT tokens, not upstream tokens
      expect(response.access_token).not.toBe("upstream-access-token");
      expect(response.refresh_token).not.toBe("upstream-refresh-token");

      // Verify tokens are valid JWTs
      expect(response.access_token.split(".")).toHaveLength(3);
      expect(response.refresh_token?.split(".")).toHaveLength(3);

      proxy.destroy();
    });

    it("should store upstream tokens and create mappings", async () => {
      const tokenStorage = new MemoryTokenStorage();
      const proxy = new OAuthProxy({
        ...baseConfig,
        enableTokenSwap: true,
        jwtSigningKey: "test-signing-key",
        tokenStorage,
      });

      const upstreamTokens: UpstreamTokenSet = {
        accessToken: "upstream-access-token",
        expiresIn: 3600,
        issuedAt: new Date(),
        refreshToken: "upstream-refresh-token",
        scope: ["read", "write"],
        tokenType: "Bearer",
      };

      await proxy.registerClient({
        redirect_uris: ["https://client.example.com/callback"],
      });

      const pkce = PKCEUtils.generatePair("S256");

      const transaction = await (proxy as any).createTransaction({
        client_id: "upstream-client-id",
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
        redirect_uri: "https://client.example.com/callback",
        response_type: "code",
        scope: "read write",
      });

      const authCode = await (proxy as any).generateAuthorizationCode(
        transaction,
        upstreamTokens,
      );

      const response = await proxy.exchangeAuthorizationCode({
        client_id: "upstream-client-id",
        code: authCode,
        code_verifier: pkce.verifier,
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      });

      // Verify storage has entries
      expect(tokenStorage.size()).toBeGreaterThan(0);

      // Verify we can load upstream tokens from FastMCP JWT
      const loadedTokens = await proxy.loadUpstreamTokens(
        response.access_token,
      );
      expect(loadedTokens).not.toBeNull();
      expect(loadedTokens?.accessToken).toBe("upstream-access-token");
      expect(loadedTokens?.refreshToken).toBe("upstream-refresh-token");

      proxy.destroy();
    });

    it("should validate FastMCP JWT and return upstream tokens", async () => {
      const jwtIssuer = new JWTIssuer({
        audience: "https://proxy.example.com",
        issuer: "https://proxy.example.com",
        signingKey: "test-signing-key",
      });

      const tokenStorage = new MemoryTokenStorage();
      const proxy = new OAuthProxy({
        ...baseConfig,
        enableTokenSwap: true,
        encryptionKey: false, // Disable encryption for easier testing
        jwtSigningKey: "test-signing-key",
        tokenStorage,
      });

      const upstreamTokens: UpstreamTokenSet = {
        accessToken: "upstream-access-token",
        expiresIn: 3600,
        issuedAt: new Date(),
        scope: ["read", "write"],
        tokenType: "Bearer",
      };

      await proxy.registerClient({
        redirect_uris: ["https://client.example.com/callback"],
      });

      const pkce = PKCEUtils.generatePair("S256");

      const transaction = await (proxy as any).createTransaction({
        client_id: "upstream-client-id",
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
        redirect_uri: "https://client.example.com/callback",
        response_type: "code",
        scope: "read write",
      });

      const authCode = await (proxy as any).generateAuthorizationCode(
        transaction,
        upstreamTokens,
      );

      const response = await proxy.exchangeAuthorizationCode({
        client_id: "upstream-client-id",
        code: authCode,
        code_verifier: pkce.verifier,
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      });

      // Verify JWT is valid
      const validation = await jwtIssuer.verify(response.access_token);
      expect(validation.valid).toBe(true);
      expect(validation.claims?.client_id).toBe("upstream-client-id");
      expect(validation.claims?.scope).toEqual(["read", "write"]);

      // Load upstream tokens
      const loadedTokens = await proxy.loadUpstreamTokens(
        response.access_token,
      );
      expect(loadedTokens).toEqual(upstreamTokens);

      proxy.destroy();
    });

    it("should return null for invalid FastMCP JWT", async () => {
      const proxy = new OAuthProxy({
        ...baseConfig,
        enableTokenSwap: true,
        jwtSigningKey: "test-signing-key",
      });

      const invalidToken = "invalid.jwt.token";
      const result = await proxy.loadUpstreamTokens(invalidToken);

      expect(result).toBeNull();

      proxy.destroy();
    });

    it("should return null for JWT with no mapping", async () => {
      const jwtIssuer = new JWTIssuer({
        audience: "https://proxy.example.com",
        issuer: "https://proxy.example.com",
        signingKey: "test-signing-key",
      });

      const proxy = new OAuthProxy({
        ...baseConfig,
        enableTokenSwap: true,
        jwtSigningKey: "test-signing-key",
      });

      // Create a valid JWT but without any mapping
      const token = jwtIssuer.issueAccessToken("client-123", ["read"]);
      const result = await proxy.loadUpstreamTokens(token);

      expect(result).toBeNull();

      proxy.destroy();
    });
  });

  describe("Token Swap Disabled (Passthrough)", () => {
    it("should pass through upstream tokens when explicitly disabled", async () => {
      const proxy = new OAuthProxy({
        ...baseConfig,
        enableTokenSwap: false, // Explicitly disable
      });

      const upstreamTokens: UpstreamTokenSet = {
        accessToken: "upstream-access-token",
        expiresIn: 3600,
        idToken: "upstream-id-token",
        issuedAt: new Date(),
        refreshToken: "upstream-refresh-token",
        scope: ["read", "write"],
        tokenType: "Bearer",
      };

      await proxy.registerClient({
        redirect_uris: ["https://client.example.com/callback"],
      });

      const pkce = PKCEUtils.generatePair("S256");

      const transaction = await (proxy as any).createTransaction({
        client_id: "upstream-client-id",
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
        redirect_uri: "https://client.example.com/callback",
        response_type: "code",
        scope: "read write",
      });

      const authCode = await (proxy as any).generateAuthorizationCode(
        transaction,
        upstreamTokens,
      );

      const response = await proxy.exchangeAuthorizationCode({
        client_id: "upstream-client-id",
        code: authCode,
        code_verifier: pkce.verifier,
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      });

      // Verify we got upstream tokens directly
      expect(response.access_token).toBe("upstream-access-token");
      expect(response.refresh_token).toBe("upstream-refresh-token");
      expect(response.id_token).toBe("upstream-id-token");
      expect(response.token_type).toBe("Bearer");
      expect(response.scope).toBe("read write");

      proxy.destroy();
    });

    it("should return null when loading tokens without token swap", async () => {
      const proxy = new OAuthProxy({
        ...baseConfig,
        enableTokenSwap: false, // Explicitly disable
      });

      const result = await proxy.loadUpstreamTokens("any-token");

      expect(result).toBeNull();

      proxy.destroy();
    });
  });
});
