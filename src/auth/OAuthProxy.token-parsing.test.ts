/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, expect, it, vi } from "vitest";

import { FastMCP } from "../FastMCP.js";
import { getTestPort } from "../getTestPort.js";
import { OAuthProxy } from "./OAuthProxy.js";
import { PKCEUtils } from "./utils/pkce.js";

const registerTransaction = async (proxy: OAuthProxy) => {
  const redirectUri = "http://localhost:3000/callback";
  const dcr = await proxy.registerClient({ redirect_uris: [redirectUri] });
  const pkce = PKCEUtils.generatePair("S256");
  const transaction = await (proxy as any).createTransaction({
    client_id: dcr.client_id,
    code_challenge: pkce.challenge,
    code_challenge_method: "S256",
    redirect_uri: redirectUri,
    response_type: "code",
  });
  return { dcr, pkce, redirectUri, transaction };
};

// Issue a client-bound refresh token without contacting the upstream.
const issueRefreshRequest = async (proxy: OAuthProxy, refreshToken: string) => {
  const { dcr, pkce, redirectUri, transaction } =
    await registerTransaction(proxy);
  const code = await (proxy as any).generateAuthorizationCode(transaction, {
    accessToken: "upstream-access-token",
    expiresIn: 3600,
    issuedAt: new Date(),
    refreshToken,
    scope: [],
    tokenType: "Bearer",
  });

  const tokens = await proxy.exchangeAuthorizationCode({
    client_id: dcr.client_id,
    client_secret: dcr.client_secret,
    code,
    code_verifier: pkce.verifier,
    grant_type: "authorization_code",
    redirect_uri: redirectUri,
  });

  return {
    client_id: dcr.client_id,
    client_secret: dcr.client_secret!,
    grant_type: "refresh_token" as const,
    refresh_token: tokens.refresh_token!,
  };
};

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

  describe("upstream error response handling", () => {
    it.each([
      "authorization-code exchange",
      "passthrough refresh",
      "token-swap refresh",
    ])(
      "returns the same HTTP error for form and JSON during %s",
      async (path) => {
        const port = await getTestPort();
        const baseUrl = `http://localhost:${port}`;
        const proxy = new OAuthProxy({
          ...baseConfig,
          baseUrl,
          enableTokenSwap: path === "token-swap refresh",
        });
        const server = new FastMCP({
          name: "test",
          oauth: {
            authorizationServer: proxy.getAuthorizationServerMetadata(),
            enabled: true,
            proxy,
          },
          version: "1.0.0",
        });
        const clientFetch = globalThis.fetch;
        const send = async () => {
          if (path === "authorization-code exchange") {
            const { transaction } = await registerTransaction(proxy);
            return clientFetch(
              `${baseUrl}/oauth/callback?code=test&state=${transaction.id}`,
              { redirect: "manual" },
            );
          }
          const request = await issueRefreshRequest(proxy, "upstream-refresh");
          return clientFetch(`${baseUrl}/oauth/token`, {
            body: new URLSearchParams(request),
            method: "POST",
          });
        };
        const error = {
          error: "bad_verification_code",
          error_description: "Grant rejected + expired.",
        };
        const payload = { ...error, error_uri: "https://provider.com/docs" };
        const upstream = vi.spyOn(globalThis, "fetch");
        try {
          await server.start({
            httpStream: { port },
            transportType: "httpStream",
          });
          for (const body of [
            Response.json(payload, { status: 400 }),
            new Response(new URLSearchParams(payload), { status: 400 }),
          ]) {
            upstream.mockResolvedValue(body);
            const response = await send();
            expect(response.status).toBe(400);
            expect(await response.text()).toBe(JSON.stringify(error));
          }
        } finally {
          upstream.mockRestore();
          proxy.destroy();
          await server.stop();
        }
      },
    );

    it("should handle non-JSON error from upstream token endpoint without crashing", async () => {
      // Disable token swap so exchangeRefreshToken goes through handlePassthroughRefresh
      const proxy = new OAuthProxy({
        ...baseConfig,
        enableTokenSwap: false,
      });

      const request = await issueRefreshRequest(proxy, "test-refresh-token");

      // Mock global fetch to return an HTML error page (e.g. load balancer 502)
      const originalFetch = globalThis.fetch;
      globalThis.fetch = async () =>
        new Response(
          '<a href="/help?status=502&error=busy&retry=1">Bad Gateway</a>',
          {
            headers: {
              "Content-Type":
                'text/html; profile="application/x-www-form-urlencoded"',
            },
            status: 502,
            statusText: "Bad Gateway",
          },
        );

      try {
        await expect(proxy.exchangeRefreshToken(request)).rejects.toMatchObject(
          {
            code: "invalid_grant",
            description: "Upstream returned HTTP 502 Bad Gateway",
            name: "OAuthProxyError",
            statusCode: 400,
          },
        );
      } finally {
        globalThis.fetch = originalFetch;
        proxy.destroy();
      }
    });

    it("should still parse JSON error bodies from upstream when available", async () => {
      const proxy = new OAuthProxy({
        ...baseConfig,
        enableTokenSwap: false,
      });

      const request = await issueRefreshRequest(proxy, "expired-token");

      const originalFetch = globalThis.fetch;
      globalThis.fetch = async () =>
        new Response(
          JSON.stringify({
            error: "invalid_grant",
            error_description: "Refresh token expired",
          }),
          {
            headers: { "Content-Type": "application/json" },
            status: 400,
            statusText: "Bad Request",
          },
        );

      try {
        const err = await proxy
          .exchangeRefreshToken(request)
          .catch((e: any) => e);

        expect(err.name).toBe("OAuthProxyError");
        expect(err.code).toBe("invalid_grant");
        expect(err.description).toBe("Refresh token expired");
      } finally {
        globalThis.fetch = originalFetch;
        proxy.destroy();
      }
    });
  });
});
