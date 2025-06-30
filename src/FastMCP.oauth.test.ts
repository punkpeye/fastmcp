import { getRandomPort } from "get-port-please";
import { describe, expect, it } from "vitest";

import { FastMCP } from "./FastMCP.js";

describe("FastMCP OAuth Support", () => {
  it("should serve OAuth authorization server metadata", async () => {
    const port = await getRandomPort();

    const server = new FastMCP({
      name: "Test Server",
      oauth: {
        authorizationServer: {
          authorizationEndpoint: "https://auth.example.com/oauth/authorize",
          dpopSigningAlgValuesSupported: ["ES256", "RS256"],
          grantTypesSupported: ["authorization_code", "refresh_token"],
          issuer: "https://auth.example.com",
          jwksUri: "https://auth.example.com/.well-known/jwks.json",
          responseTypesSupported: ["code"],
          scopesSupported: ["read", "write"],
          tokenEndpoint: "https://auth.example.com/oauth/token",
        },
        enabled: true,
      },
      version: "1.0.0",
    });

    await server.start({
      httpStream: { port },
      transportType: "httpStream",
    });

    try {
      // Test the OAuth authorization server endpoint
      const response = await fetch(
        `http://localhost:${port}/.well-known/oauth-authorization-server`,
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("application/json");

      const metadata = (await response.json()) as Record<string, unknown>;

      // Check that camelCase was converted to snake_case
      expect(metadata.issuer).toBe("https://auth.example.com");
      expect(metadata.authorization_endpoint).toBe(
        "https://auth.example.com/oauth/authorize",
      );
      expect(metadata.token_endpoint).toBe(
        "https://auth.example.com/oauth/token",
      );
      expect(metadata.response_types_supported).toEqual(["code"]);
      expect(metadata.jwks_uri).toBe(
        "https://auth.example.com/.well-known/jwks.json",
      );
      expect(metadata.scopes_supported).toEqual(["read", "write"]);
      expect(metadata.grant_types_supported).toEqual([
        "authorization_code",
        "refresh_token",
      ]);
      expect(metadata.dpop_signing_alg_values_supported).toEqual([
        "ES256",
        "RS256",
      ]);
    } finally {
      await server.stop();
    }
  });

  it("should serve OAuth protected resource metadata", async () => {
    const port = await getRandomPort();

    const server = new FastMCP({
      name: "Test Server",
      oauth: {
        enabled: true,
        protectedResource: {
          authorizationServers: ["https://auth.example.com"],
          bearerMethodsSupported: ["header"],
          jwksUri: "https://test-server.example.com/.well-known/jwks.json",
          resource: "mcp://test-server",
          resourceDocumentation: "https://docs.example.com/api",
        },
      },
      version: "1.0.0",
    });

    await server.start({
      httpStream: { port },
      transportType: "httpStream",
    });

    try {
      const response = await fetch(
        `http://localhost:${port}/.well-known/oauth-protected-resource`,
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("application/json");

      const metadata = (await response.json()) as Record<string, unknown>;

      // Check that camelCase was converted to snake_case
      expect(metadata.resource).toBe("mcp://test-server");
      expect(metadata.authorization_servers).toEqual([
        "https://auth.example.com",
      ]);
      expect(metadata.jwks_uri).toBe(
        "https://test-server.example.com/.well-known/jwks.json",
      );
      expect(metadata.bearer_methods_supported).toEqual(["header"]);
      expect(metadata.resource_documentation).toBe(
        "https://docs.example.com/api",
      );
    } finally {
      await server.stop();
    }
  });

  it("should return 404 for OAuth endpoints when disabled", async () => {
    const port = await getRandomPort();

    const server = new FastMCP({
      name: "Test Server",
      oauth: {
        enabled: false,
      },
      version: "1.0.0",
    });

    await server.start({
      httpStream: { port },
      transportType: "httpStream",
    });

    try {
      const authServerResponse = await fetch(
        `http://localhost:${port}/.well-known/oauth-authorization-server`,
      );
      expect(authServerResponse.status).toBe(404);

      const protectedResourceResponse = await fetch(
        `http://localhost:${port}/.well-known/oauth-protected-resource`,
      );
      expect(protectedResourceResponse.status).toBe(404);
    } finally {
      await server.stop();
    }
  });

  it("should return 404 for OAuth endpoints when not configured", async () => {
    const port = await getRandomPort();

    const server = new FastMCP({
      name: "Test Server",
      version: "1.0.0",
      // No oauth configuration
    });

    await server.start({
      httpStream: { port },
      transportType: "httpStream",
    });

    try {
      const authServerResponse = await fetch(
        `http://localhost:${port}/.well-known/oauth-authorization-server`,
      );
      expect(authServerResponse.status).toBe(404);

      const protectedResourceResponse = await fetch(
        `http://localhost:${port}/.well-known/oauth-protected-resource`,
      );
      expect(protectedResourceResponse.status).toBe(404);
    } finally {
      await server.stop();
    }
  });
});
