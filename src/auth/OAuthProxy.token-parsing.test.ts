/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, expect, it } from "vitest";

import { OAuthProxy } from "./OAuthProxy.js";

describe("OAuthProxy - Token Response Parsing", () => {
  const baseConfig = {
    baseUrl: "https://proxy.example.com",
    consentRequired: false,
    upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
    upstreamClientId: "upstream-client-id",
    upstreamClientSecret: "upstream-client-secret",
    upstreamTokenEndpoint: "https://provider.com/oauth/token",
  };

  describe("parseTokenResponse", () => {
    it("should parse JSON token response (standard OAuth providers)", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        JSON.stringify({
          access_token: "test_access_token",
          expires_in: 3600,
          id_token: "test_id_token",
          refresh_token: "test_refresh_token",
          scope: "read write",
          token_type: "Bearer",
        }),
        {
          headers: { "Content-Type": "application/json" },
          status: 200,
        },
      );

      const tokens = await (proxy as any).parseTokenResponse(mockResponse);

      expect(tokens.access_token).toBe("test_access_token");
      expect(tokens.expires_in).toBe(3600);
      expect(tokens.id_token).toBe("test_id_token");
      expect(tokens.refresh_token).toBe("test_refresh_token");
      expect(tokens.scope).toBe("read write");
      expect(tokens.token_type).toBe("Bearer");

      proxy.destroy();
    });

    it("should parse URL-encoded token response (GitHub Apps format)", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        "access_token=ghu_redacted&expires_in=28800&refresh_token=ghr_redacted&refresh_token_expires_in=15724800&scope=&token_type=bearer",
        {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          status: 200,
        },
      );

      const tokens = await (proxy as any).parseTokenResponse(mockResponse);

      expect(tokens.access_token).toBe("ghu_redacted");
      expect(tokens.expires_in).toBe(28800);
      expect(tokens.refresh_token).toBe("ghr_redacted");
      expect(tokens.scope).toBeUndefined(); // Empty string is treated as undefined
      expect(tokens.token_type).toBe("bearer");

      proxy.destroy();
    });

    it("should handle URL-encoded response without optional fields", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        "access_token=ghu_test&token_type=bearer",
        {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          status: 200,
        },
      );

      const tokens = await (proxy as any).parseTokenResponse(mockResponse);

      expect(tokens.access_token).toBe("ghu_test");
      expect(tokens.token_type).toBe("bearer");
      expect(tokens.expires_in).toBeUndefined();
      expect(tokens.refresh_token).toBeUndefined();
      expect(tokens.scope).toBeUndefined();
      expect(tokens.id_token).toBeUndefined();

      proxy.destroy();
    });

    it("should fallback to JSON when Content-Type is missing", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        JSON.stringify({
          access_token: "test_token",
          expires_in: 3600,
          token_type: "Bearer",
        }),
        {
          status: 200,
          // No Content-Type header
        },
      );

      const tokens = await (proxy as any).parseTokenResponse(mockResponse);

      expect(tokens.access_token).toBe("test_token");
      expect(tokens.expires_in).toBe(3600);
      expect(tokens.token_type).toBe("Bearer");

      proxy.destroy();
    });

    it("should handle Content-Type with charset parameter", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        "access_token=test&expires_in=3600&token_type=bearer",
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
          },
          status: 200,
        },
      );

      const tokens = await (proxy as any).parseTokenResponse(mockResponse);

      expect(tokens.access_token).toBe("test");
      expect(tokens.expires_in).toBe(3600);
      expect(tokens.token_type).toBe("bearer");

      proxy.destroy();
    });

    it("should parse expires_in as number from URL-encoded format", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        "access_token=test&expires_in=28800&token_type=bearer",
        {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          status: 200,
        },
      );

      const tokens = await (proxy as any).parseTokenResponse(mockResponse);

      expect(tokens.expires_in).toBe(28800);
      expect(typeof tokens.expires_in).toBe("number");

      proxy.destroy();
    });

    it("should handle URL-encoded response with empty scope", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        "access_token=test&scope=&token_type=bearer",
        {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          status: 200,
        },
      );

      const tokens = await (proxy as any).parseTokenResponse(mockResponse);

      expect(tokens.access_token).toBe("test");
      expect(tokens.scope).toBeUndefined(); // Empty string is treated as undefined
      expect(tokens.token_type).toBe("bearer");

      proxy.destroy();
    });

    it("should handle JSON response with all optional fields present", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        JSON.stringify({
          access_token: "access_123",
          expires_in: 7200,
          id_token: "id_token_xyz",
          refresh_token: "refresh_456",
          scope: "openid profile email",
          token_type: "Bearer",
        }),
        {
          headers: { "Content-Type": "application/json; charset=utf-8" },
          status: 200,
        },
      );

      const tokens = await (proxy as any).parseTokenResponse(mockResponse);

      expect(tokens.access_token).toBe("access_123");
      expect(tokens.expires_in).toBe(7200);
      expect(tokens.id_token).toBe("id_token_xyz");
      expect(tokens.refresh_token).toBe("refresh_456");
      expect(tokens.scope).toBe("openid profile email");
      expect(tokens.token_type).toBe("Bearer");

      proxy.destroy();
    });

    it("should throw validation error for missing access_token in JSON", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        JSON.stringify({
          expires_in: 3600,
          token_type: "Bearer",
          // missing access_token
        }),
        {
          headers: { "Content-Type": "application/json" },
          status: 200,
        },
      );

      await expect(
        (proxy as any).parseTokenResponse(mockResponse),
      ).rejects.toThrow();

      proxy.destroy();
    });

    it("should throw validation error for invalid expires_in type in URL-encoded", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        "access_token=test&expires_in=invalid&token_type=bearer",
        {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          status: 200,
        },
      );

      await expect(
        (proxy as any).parseTokenResponse(mockResponse),
      ).rejects.toThrow();

      proxy.destroy();
    });

    it("should throw validation error for negative expires_in", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        JSON.stringify({
          access_token: "test",
          expires_in: -100,
          token_type: "Bearer",
        }),
        {
          headers: { "Content-Type": "application/json" },
          status: 200,
        },
      );

      await expect(
        (proxy as any).parseTokenResponse(mockResponse),
      ).rejects.toThrow();

      proxy.destroy();
    });

    it("should throw validation error for missing access_token in URL-encoded", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response("expires_in=3600&token_type=bearer", {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        status: 200,
      });

      await expect(
        (proxy as any).parseTokenResponse(mockResponse),
      ).rejects.toThrow();

      proxy.destroy();
    });

    it("should throw validation error for non-integer expires_in", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        JSON.stringify({
          access_token: "test",
          expires_in: 3600.5, // float instead of integer
          token_type: "Bearer",
        }),
        {
          headers: { "Content-Type": "application/json" },
          status: 200,
        },
      );

      await expect(
        (proxy as any).parseTokenResponse(mockResponse),
      ).rejects.toThrow();

      proxy.destroy();
    });

    it("should throw validation error for zero expires_in", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        JSON.stringify({
          access_token: "test",
          expires_in: 0, // zero is not positive
          token_type: "Bearer",
        }),
        {
          headers: { "Content-Type": "application/json" },
          status: 200,
        },
      );

      await expect(
        (proxy as any).parseTokenResponse(mockResponse),
      ).rejects.toThrow();

      proxy.destroy();
    });

    it("should handle URL-encoded response with id_token", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        "access_token=test&id_token=eyJhbGc&expires_in=3600&token_type=bearer",
        {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          status: 200,
        },
      );

      const tokens = await (proxy as any).parseTokenResponse(mockResponse);

      expect(tokens.access_token).toBe("test");
      expect(tokens.id_token).toBe("eyJhbGc");
      expect(tokens.expires_in).toBe(3600);
      expect(tokens.token_type).toBe("bearer");

      proxy.destroy();
    });

    it("should handle JSON response with only required field", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        JSON.stringify({
          access_token: "minimal_token",
          // all other fields optional
        }),
        {
          headers: { "Content-Type": "application/json" },
          status: 200,
        },
      );

      const tokens = await (proxy as any).parseTokenResponse(mockResponse);

      expect(tokens.access_token).toBe("minimal_token");
      expect(tokens.expires_in).toBeUndefined();
      expect(tokens.id_token).toBeUndefined();
      expect(tokens.refresh_token).toBeUndefined();
      expect(tokens.scope).toBeUndefined();
      expect(tokens.token_type).toBeUndefined();

      proxy.destroy();
    });

    it("should throw validation error for wrong type of access_token", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        JSON.stringify({
          access_token: 12345, // number instead of string
          token_type: "Bearer",
        }),
        {
          headers: { "Content-Type": "application/json" },
          status: 200,
        },
      );

      await expect(
        (proxy as any).parseTokenResponse(mockResponse),
      ).rejects.toThrow();

      proxy.destroy();
    });

    it("should handle mixed case Content-Type header", async () => {
      const proxy = new OAuthProxy(baseConfig);

      const mockResponse = new Response(
        "access_token=test&expires_in=3600&token_type=bearer",
        {
          headers: {
            "Content-Type": "Application/X-Www-Form-Urlencoded",
          },
          status: 200,
        },
      );

      const tokens = await (proxy as any).parseTokenResponse(mockResponse);

      expect(tokens.access_token).toBe("test");
      expect(tokens.expires_in).toBe(3600);

      proxy.destroy();
    });
  });
});
