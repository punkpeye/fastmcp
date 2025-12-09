/**
 * OAuth Proxy Integration Tests
 * Tests the seamless integration of OAuth Proxy with FastMCP HTTP transport
 */

import { getRandomPort } from "get-port-please";
import { describe, expect, it, vi } from "vitest";

import { OAuthProxy } from "./auth/OAuthProxy.js";
import { FastMCP } from "./FastMCP.js";

describe("FastMCP OAuth Proxy Integration", () => {
  it("should automatically register OAuth endpoints when proxy is provided", async () => {
    const port = await getRandomPort();

    // Create OAuth Proxy
    const authProxy = new OAuthProxy({
      baseUrl: `http://localhost:${port}`,
      scopes: ["openid", "profile"],
      upstreamAuthorizationEndpoint: "https://example.com/oauth/authorize",
      upstreamClientId: "test-client-id",
      upstreamClientSecret: "test-client-secret",
      upstreamTokenEndpoint: "https://example.com/oauth/token",
    });

    // Create FastMCP server with proxy
    const server = new FastMCP({
      name: "Test Server",
      oauth: {
        authorizationServer: authProxy.getAuthorizationServerMetadata(),
        enabled: true,
        proxy: authProxy,
      },
      version: "1.0.0",
    });

    await server.start({
      httpStream: { port },
      transportType: "httpStream",
    });

    try {
      // Test DCR endpoint
      const dcrResponse = await fetch(
        `http://localhost:${port}/oauth/register`,
        {
          body: JSON.stringify({
            redirect_uris: ["https://client.example.com/callback"],
          }),
          headers: { "Content-Type": "application/json" },
          method: "POST",
        },
      );

      expect(dcrResponse.status).toBe(201);
      const dcrData = await dcrResponse.json();
      expect(dcrData).toHaveProperty("client_id");
      expect(dcrData).toHaveProperty("client_secret");

      // Test authorization server metadata endpoint
      const metadataResponse = await fetch(
        `http://localhost:${port}/.well-known/oauth-authorization-server`,
      );

      expect(metadataResponse.status).toBe(200);
      const metadata = await metadataResponse.json();
      expect(metadata).toHaveProperty("issuer");
      expect(metadata).toHaveProperty("authorization_endpoint");
      expect(metadata).toHaveProperty("token_endpoint");
      expect(metadata).toHaveProperty("registration_endpoint");
    } finally {
      await server.stop();
    }
  });

  it("should not register OAuth endpoints when proxy is not provided", async () => {
    const port = await getRandomPort();

    const server = new FastMCP({
      name: "Test Server Without Proxy",
      oauth: {
        authorizationServer: {
          authorizationEndpoint: "https://example.com/authorize",
          issuer: "https://example.com",
          responseTypesSupported: ["code"],
          tokenEndpoint: "https://example.com/token",
        },
        enabled: true,
        // No proxy provided
      },
      version: "1.0.0",
    });

    await server.start({
      httpStream: { port },
      transportType: "httpStream",
    });

    try {
      // DCR endpoint should 404 without proxy
      const dcrResponse = await fetch(
        `http://localhost:${port}/oauth/register`,
        {
          body: JSON.stringify({
            redirect_uris: ["https://client.example.com/callback"],
          }),
          headers: { "Content-Type": "application/json" },
          method: "POST",
        },
      );

      expect(dcrResponse.status).toBe(404);

      // But metadata endpoint should still work
      const metadataResponse = await fetch(
        `http://localhost:${port}/.well-known/oauth-authorization-server`,
      );

      expect(metadataResponse.status).toBe(200);
    } finally {
      await server.stop();
    }
  });

  it("should handle authorization endpoint", async () => {
    const port = await getRandomPort();

    const authProxy = new OAuthProxy({
      baseUrl: `http://localhost:${port}`,
      consentRequired: false, // Disable consent for testing
      scopes: ["openid"],
      upstreamAuthorizationEndpoint: "https://example.com/oauth/authorize",
      upstreamClientId: "test-client-id",
      upstreamClientSecret: "test-client-secret",
      upstreamTokenEndpoint: "https://example.com/oauth/token",
    });

    const server = new FastMCP({
      name: "Test Server",
      oauth: {
        authorizationServer: authProxy.getAuthorizationServerMetadata(),
        enabled: true,
        proxy: authProxy,
      },
      version: "1.0.0",
    });

    await server.start({
      httpStream: { port },
      transportType: "httpStream",
    });

    try {
      // First register a client
      await fetch(`http://localhost:${port}/oauth/register`, {
        body: JSON.stringify({
          redirect_uris: ["https://client.example.com/callback"],
        }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });

      // Test authorization endpoint - should redirect
      const authParams = new URLSearchParams({
        client_id: "test-client-id",
        code_challenge: "test-challenge",
        code_challenge_method: "S256",
        redirect_uri: "https://client.example.com/callback",
        response_type: "code",
        state: "test-state",
      });

      const authResponse = await fetch(
        `http://localhost:${port}/oauth/authorize?${authParams}`,
        {
          redirect: "manual", // Don't follow redirects
        },
      );

      // Should get a redirect response (302 or 303)
      expect([302, 303]).toContain(authResponse.status);
      expect(authResponse.headers.get("Location")).toBeTruthy();
    } finally {
      await server.stop();
    }
  });
});

describe("OAuth Token Endpoint Basic Auth", () => {
  it("should accept Basic auth header for client credentials", async () => {
    const port = await getRandomPort();
    const authProxy = new OAuthProxy({
      baseUrl: `http://localhost:${port}`,
      scopes: ["openid"],
      upstreamAuthorizationEndpoint: "https://example.com/oauth/authorize",
      upstreamClientId: "test-client-id",
      upstreamClientSecret: "test-client-secret",
      upstreamTokenEndpoint: "https://example.com/oauth/token",
    });

    // Spy on exchangeAuthorizationCode to capture the parameters
    const spy = vi.spyOn(authProxy, "exchangeAuthorizationCode");

    const server = new FastMCP({
      name: "Test Server",
      oauth: {
        authorizationServer: authProxy.getAuthorizationServerMetadata(),
        enabled: true,
        proxy: authProxy,
      },
      version: "1.0.0",
    });

    await server.start({
      httpStream: { port },
      transportType: "httpStream",
    });

    try {
      // Encode Basic auth header (RFC 6749 Section 2.3.1)
      const credentials = Buffer.from("test-client:test-secret").toString(
        "base64",
      );

      // Note: NO client_id or client_secret in body - only in Authorization header
      await fetch(`http://localhost:${port}/oauth/token`, {
        body: new URLSearchParams({
          code: "any-code",
          grant_type: "authorization_code",
          redirect_uri: "https://client.example.com/callback",
        }).toString(),
        headers: {
          Authorization: `Basic ${credentials}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        method: "POST",
      });

      // Verify spy was called with credentials from Basic auth header
      expect(spy).toHaveBeenCalledWith(
        expect.objectContaining({
          client_id: "test-client",
          client_secret: "test-secret",
        }),
      );
    } finally {
      spy.mockRestore();
      await server.stop();
    }
  });

  it("should fall back to POST body credentials when no Basic auth header", async () => {
    const port = await getRandomPort();
    const authProxy = new OAuthProxy({
      baseUrl: `http://localhost:${port}`,
      scopes: ["openid"],
      upstreamAuthorizationEndpoint: "https://example.com/oauth/authorize",
      upstreamClientId: "test-client-id",
      upstreamClientSecret: "test-client-secret",
      upstreamTokenEndpoint: "https://example.com/oauth/token",
    });

    // Spy on exchangeAuthorizationCode to capture the parameters
    const spy = vi.spyOn(authProxy, "exchangeAuthorizationCode");

    const server = new FastMCP({
      name: "Test Server",
      oauth: {
        authorizationServer: authProxy.getAuthorizationServerMetadata(),
        enabled: true,
        proxy: authProxy,
      },
      version: "1.0.0",
    });

    await server.start({
      httpStream: { port },
      transportType: "httpStream",
    });

    try {
      // No Authorization header - credentials in POST body
      await fetch(`http://localhost:${port}/oauth/token`, {
        body: new URLSearchParams({
          client_id: "body-client",
          client_secret: "body-secret",
          code: "any-code",
          grant_type: "authorization_code",
          redirect_uri: "https://client.example.com/callback",
        }).toString(),
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        method: "POST",
      });

      // Verify spy was called with credentials from POST body
      expect(spy).toHaveBeenCalledWith(
        expect.objectContaining({
          client_id: "body-client",
          client_secret: "body-secret",
        }),
      );
    } finally {
      spy.mockRestore();
      await server.stop();
    }
  });

  it("should accept Basic auth with empty client_secret", async () => {
    const port = await getRandomPort();
    const authProxy = new OAuthProxy({
      baseUrl: `http://localhost:${port}`,
      scopes: ["openid"],
      upstreamAuthorizationEndpoint: "https://example.com/oauth/authorize",
      upstreamClientId: "test-client-id",
      upstreamClientSecret: "test-client-secret",
      upstreamTokenEndpoint: "https://example.com/oauth/token",
    });

    // Spy on exchangeAuthorizationCode to capture the parameters
    const spy = vi.spyOn(authProxy, "exchangeAuthorizationCode");

    const server = new FastMCP({
      name: "Test Server",
      oauth: {
        authorizationServer: authProxy.getAuthorizationServerMetadata(),
        enabled: true,
        proxy: authProxy,
      },
      version: "1.0.0",
    });

    await server.start({
      httpStream: { port },
      transportType: "httpStream",
    });

    try {
      // Per RFC 6749, client_secret can be empty (public clients)
      // Format: "client_id:" (note the colon with empty secret)
      const credentials = Buffer.from("public-client:").toString("base64");

      // Note: NO client_id or client_secret in body - only in Authorization header
      await fetch(`http://localhost:${port}/oauth/token`, {
        body: new URLSearchParams({
          code: "any-code",
          grant_type: "authorization_code",
          redirect_uri: "https://client.example.com/callback",
        }).toString(),
        headers: {
          Authorization: `Basic ${credentials}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        method: "POST",
      });

      // Verify spy was called with credentials from Basic auth header
      // Empty client_secret should be passed as empty string
      expect(spy).toHaveBeenCalledWith(
        expect.objectContaining({
          client_id: "public-client",
          client_secret: "",
        }),
      );
    } finally {
      spy.mockRestore();
      await server.stop();
    }
  });
});
