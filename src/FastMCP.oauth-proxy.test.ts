/**
 * OAuth Proxy Integration Tests
 * Tests the seamless integration of OAuth Proxy with FastMCP HTTP transport
 */

import { getRandomPort } from "get-port-please";
import { describe, expect, it } from "vitest";

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
