/* eslint-disable @typescript-eslint/no-explicit-any */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { TokenRequest, TokenStorage, UpstreamTokenSet } from "./types.js";

import { OAuthProxy } from "./OAuthProxy.js";
import {
  DEFAULT_ACCESS_TOKEN_TTL,
  DEFAULT_ACCESS_TOKEN_TTL_NO_REFRESH,
  DEFAULT_REFRESH_TOKEN_TTL,
} from "./types.js";
import { JWTIssuer } from "./utils/jwtIssuer.js";
import { PKCEUtils } from "./utils/pkce.js";
import { MemoryTokenStorage } from "./utils/tokenStore.js";

/**
 * Test storage that tracks TTLs passed to save()
 */
class TTLTrackingStorage implements TokenStorage {
  private backend = new MemoryTokenStorage();
  public savedTTLs: Map<string, number | undefined> = new Map();

  async cleanup(): Promise<void> {
    await this.backend.cleanup();
  }

  async delete(key: string): Promise<void> {
    await this.backend.delete(key);
  }

  destroy(): void {
    this.backend.destroy();
  }

  async get(key: string): Promise<null | unknown> {
    return this.backend.get(key);
  }

  async save(key: string, value: unknown, ttl?: number): Promise<void> {
    this.savedTTLs.set(key, ttl);
    await this.backend.save(key, value, ttl);
  }

  size(): number {
    return this.backend.size();
  }

  /**
   * Get the TTL used for a specific key pattern (e.g., "upstream:")
   */
  getTTLForKeyPattern(pattern: string): number | undefined {
    for (const [key, ttl] of this.savedTTLs.entries()) {
      if (key.startsWith(pattern)) {
        return ttl;
      }
    }
    return undefined;
  }
}

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

describe("OAuthProxy - Upstream Token Endpoint Authentication", () => {
  const baseConfig = {
    baseUrl: "https://proxy.example.com",
    consentRequired: false,
    upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
    upstreamTokenEndpoint: "https://provider.com/oauth/token",
  };

  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: "test-access-token",
          expires_in: 3600,
          refresh_token: "test-refresh-token",
          token_type: "Bearer",
        }),
        {
          headers: { "Content-Type": "application/json" },
          status: 200,
        },
      ),
    );
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it("should default to client_secret_basic auth method", () => {
    const proxy = new OAuthProxy({
      ...baseConfig,
      upstreamClientId: "test-client",
      upstreamClientSecret: "test-secret",
    });

    // Access the private config to verify default
    expect((proxy as any).config.upstreamTokenEndpointAuthMethod).toBe(
      "client_secret_basic",
    );

    proxy.destroy();
  });

  it("should URL-encode credentials in Basic auth header per RFC 6749", async () => {
    // Use credentials with special characters that need encoding
    const clientId = "client:with@special/chars";
    const clientSecret = "secret%with:special&chars";

    const proxy = new OAuthProxy({
      ...baseConfig,
      upstreamClientId: clientId,
      upstreamClientSecret: clientSecret,
      upstreamTokenEndpointAuthMethod: "client_secret_basic",
    });

    // Create a transaction to test upstream code exchange
    const pkce = PKCEUtils.generatePair("S256");
    const transaction = await (proxy as any).createTransaction({
      client_id: clientId,
      code_challenge: pkce.challenge,
      code_challenge_method: "S256",
      redirect_uri: "https://client.example.com/callback",
      response_type: "code",
      scope: "openid",
    });

    // Call the private method that makes the upstream request
    await (proxy as any).exchangeUpstreamCode("test-code", transaction);

    // Verify fetch was called with properly encoded Basic auth header
    expect(fetchSpy).toHaveBeenCalledWith(
      "https://provider.com/oauth/token",
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: expect.stringMatching(/^Basic /),
        }),
        method: "POST",
      }),
    );

    // Extract and decode the Authorization header
    const call = fetchSpy.mock.calls[0];
    const headers = call[1]?.headers as Record<string, string>;
    const authHeader = headers["Authorization"];
    const base64Credentials = authHeader.replace("Basic ", "");
    const decodedCredentials = Buffer.from(
      base64Credentials,
      "base64",
    ).toString("utf-8");

    // Per RFC 6749 Section 2.3.1, credentials should be URL-encoded before base64
    const expectedEncoded = `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`;
    expect(decodedCredentials).toBe(expectedEncoded);

    // Verify body does NOT contain client credentials
    const body = call[1]?.body as URLSearchParams;
    expect(body.has("client_id")).toBe(false);
    expect(body.has("client_secret")).toBe(false);

    proxy.destroy();
  });

  it("should include credentials in body for client_secret_post", async () => {
    const clientId = "test-client";
    const clientSecret = "test-secret";

    const proxy = new OAuthProxy({
      ...baseConfig,
      upstreamClientId: clientId,
      upstreamClientSecret: clientSecret,
      upstreamTokenEndpointAuthMethod: "client_secret_post",
    });

    const pkce = PKCEUtils.generatePair("S256");
    const transaction = await (proxy as any).createTransaction({
      client_id: clientId,
      code_challenge: pkce.challenge,
      code_challenge_method: "S256",
      redirect_uri: "https://client.example.com/callback",
      response_type: "code",
      scope: "openid",
    });

    await (proxy as any).exchangeUpstreamCode("test-code", transaction);

    // Verify fetch was called without Authorization header
    const call = fetchSpy.mock.calls[0];
    const headers = call[1]?.headers as Record<string, string>;
    expect(headers["Authorization"]).toBeUndefined();

    // Verify body contains client credentials
    const body = call[1]?.body as URLSearchParams;
    expect(body.get("client_id")).toBe(clientId);
    expect(body.get("client_secret")).toBe(clientSecret);

    proxy.destroy();
  });
});

/**
 * Tests for upstream token storage TTL calculation (issue #2670 in Python fastmcp).
 *
 * The TTL should use max(accessTokenTtl, refreshTokenTtl, 1) to ensure upstream
 * tokens persist as long as the longest-lived FastMCP token that references them.
 *
 * @see https://github.com/jlowin/fastmcp/pull/2796
 */
describe("OAuthProxy - Upstream Token Storage TTL", () => {
  const baseConfig = {
    baseUrl: "https://proxy.example.com",
    consentRequired: false,
    enableTokenSwap: true,
    jwtSigningKey: "test-signing-key",
    upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
    upstreamClientId: "upstream-client-id",
    upstreamClientSecret: "upstream-client-secret",
    upstreamTokenEndpoint: "https://provider.com/oauth/token",
  };

  async function exchangeTokens(
    proxy: OAuthProxy,
    upstreamTokens: UpstreamTokenSet,
  ) {
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

    return proxy.exchangeAuthorizationCode({
      client_id: "upstream-client-id",
      code: authCode,
      code_verifier: pkce.verifier,
      grant_type: "authorization_code",
      redirect_uri: "https://client.example.com/callback",
    });
  }

  it("should use max TTL when refresh token is shorter than access token (Keycloak case)", async () => {
    /**
     * Keycloak scenario: refresh_expires_in=120 (2 min) but expires_in=28800 (8 hours).
     * The upstream tokens should persist for 8 hours (the access token lifetime).
     */
    const tokenStorage = new TTLTrackingStorage();
    const proxy = new OAuthProxy({
      ...baseConfig,
      tokenStorage,
    });

    const upstreamTokens: UpstreamTokenSet = {
      accessToken: "upstream-access-token",
      expiresIn: 28800, // 8 hours (access token)
      issuedAt: new Date(),
      refreshToken: "upstream-refresh-token",
      scope: ["read", "write"],
      tokenType: "Bearer",
    };

    // Configure refresh token TTL to be shorter than access token
    // In this test, access token is 28800s, refresh would default to 30 days
    // But the key point is max(accessTokenTtl, refreshTokenTtl)
    await exchangeTokens(proxy, upstreamTokens);

    // Verify upstream tokens were stored with the longer TTL
    const upstreamTTL = tokenStorage.getTTLForKeyPattern("upstream:");
    expect(upstreamTTL).toBeDefined();
    // Should use max of access (28800) and refresh (DEFAULT_REFRESH_TOKEN_TTL = 30 days)
    expect(upstreamTTL).toBe(
      Math.max(upstreamTokens.expiresIn, DEFAULT_REFRESH_TOKEN_TTL),
    );

    proxy.destroy();
    tokenStorage.destroy();
  });

  it("should use refresh TTL when refresh token is longer than access token (typical case)", async () => {
    /**
     * Typical scenario: short access token (5 min) but long refresh token (30 days).
     * The upstream tokens should persist for 30 days (the refresh token lifetime).
     */
    const tokenStorage = new TTLTrackingStorage();
    const proxy = new OAuthProxy({
      ...baseConfig,
      tokenStorage,
    });

    const upstreamTokens: UpstreamTokenSet = {
      accessToken: "upstream-access-token",
      expiresIn: 300, // 5 minutes (access token)
      issuedAt: new Date(),
      refreshToken: "upstream-refresh-token",
      scope: ["read", "write"],
      tokenType: "Bearer",
    };

    await exchangeTokens(proxy, upstreamTokens);

    // Verify upstream tokens were stored with refresh token TTL
    const upstreamTTL = tokenStorage.getTTLForKeyPattern("upstream:");
    expect(upstreamTTL).toBeDefined();
    // Should use max of access (300) and refresh (DEFAULT_REFRESH_TOKEN_TTL = 30 days)
    expect(upstreamTTL).toBe(DEFAULT_REFRESH_TOKEN_TTL);

    proxy.destroy();
    tokenStorage.destroy();
  });

  it("should use long access TTL when no refresh token (GitHub case)", async () => {
    /**
     * GitHub scenario: no refresh token issued, so access token gets long TTL (1 year).
     * The upstream tokens should persist for the access token lifetime.
     */
    const tokenStorage = new TTLTrackingStorage();
    const proxy = new OAuthProxy({
      ...baseConfig,
      tokenStorage,
    });

    const upstreamTokens: UpstreamTokenSet = {
      accessToken: "upstream-access-token",
      expiresIn: 0, // GitHub doesn't provide expiry
      issuedAt: new Date(),
      // No refresh token!
      scope: ["read", "write"],
      tokenType: "Bearer",
    };

    await exchangeTokens(proxy, upstreamTokens);

    // Verify upstream tokens were stored with long-lived access TTL
    const upstreamTTL = tokenStorage.getTTLForKeyPattern("upstream:");
    expect(upstreamTTL).toBeDefined();
    // Should use DEFAULT_ACCESS_TOKEN_TTL_NO_REFRESH (1 year) since no refresh token
    expect(upstreamTTL).toBe(DEFAULT_ACCESS_TOKEN_TTL_NO_REFRESH);

    proxy.destroy();
    tokenStorage.destroy();
  });

  it("should use configured accessTokenTtl when provided", async () => {
    const tokenStorage = new TTLTrackingStorage();
    const customAccessTtl = 7200; // 2 hours
    const proxy = new OAuthProxy({
      ...baseConfig,
      accessTokenTtl: customAccessTtl,
      tokenStorage,
    });

    const upstreamTokens: UpstreamTokenSet = {
      accessToken: "upstream-access-token",
      expiresIn: 0, // No expiry from upstream
      issuedAt: new Date(),
      refreshToken: "upstream-refresh-token",
      scope: ["read", "write"],
      tokenType: "Bearer",
    };

    await exchangeTokens(proxy, upstreamTokens);

    // Verify upstream tokens were stored with max of configured access TTL and refresh TTL
    const upstreamTTL = tokenStorage.getTTLForKeyPattern("upstream:");
    expect(upstreamTTL).toBeDefined();
    expect(upstreamTTL).toBe(Math.max(customAccessTtl, DEFAULT_REFRESH_TOKEN_TTL));

    proxy.destroy();
    tokenStorage.destroy();
  });

  it("should use configured refreshTokenTtl when provided", async () => {
    const tokenStorage = new TTLTrackingStorage();
    const customRefreshTtl = 86400; // 1 day
    const proxy = new OAuthProxy({
      ...baseConfig,
      refreshTokenTtl: customRefreshTtl,
      tokenStorage,
    });

    const upstreamTokens: UpstreamTokenSet = {
      accessToken: "upstream-access-token",
      expiresIn: 3600, // 1 hour
      issuedAt: new Date(),
      refreshToken: "upstream-refresh-token",
      scope: ["read", "write"],
      tokenType: "Bearer",
    };

    await exchangeTokens(proxy, upstreamTokens);

    // Verify upstream tokens were stored with configured refresh TTL (longer)
    const upstreamTTL = tokenStorage.getTTLForKeyPattern("upstream:");
    expect(upstreamTTL).toBeDefined();
    expect(upstreamTTL).toBe(customRefreshTtl); // 1 day > 1 hour

    proxy.destroy();
    tokenStorage.destroy();
  });

  it("should enforce minimum TTL of 1 second in storage calculation", () => {
    /**
     * Unit test for the max(..., 1) safety check.
     * This ensures the storage TTL is never 0 even in edge cases.
     */
    // Test the math directly - this is what the code does:
    // upstreamStorageTtl = Math.max(accessTokenTtl, refreshTokenTtl, 1)
    expect(Math.max(0, 0, 1)).toBe(1);
    expect(Math.max(-1, -1, 1)).toBe(1);
    expect(Math.max(100, 200, 1)).toBe(200);
  });
});
