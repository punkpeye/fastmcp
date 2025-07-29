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
          authorizationDetailsTypesSupported: ["payment_initiation"],
          authorizationServers: ["https://auth.example.com"],
          bearerMethodsSupported: ["header"],
          dpopBoundAccessTokensRequired: true,
          dpopSigningAlgValuesSupported: ["ES256", "RS256"],
          jwksUri: "https://test-server.example.com/.well-known/jwks.json",
          resource: "mcp://test-server",
          resourceDocumentation: "https://docs.example.com/api",
          resourceName: "Test API",
          resourcePolicyUri: "https://test-server.example.com/policy",
          resourceSigningAlgValuesSupported: ["RS256"],
          resourceTosUri: "https://test-server.example.com/tos",
          scopesSupported: ["read", "write", "admin"],
          serviceDocumentation: "https://developer.example.com/api",
          tlsClientCertificateBoundAccessTokens: false,
          vendorPrefix_complexObject: {
            nestedArray: [1, 2, 3],
            nestedProperty: "nested value",
          },
          // Vendor extensions (dynamic properties)
          vendorPrefix_customField: "custom value",
          x_api_version: "2.0",
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

      // New fields added for RFC 9728 compliance
      expect(metadata.authorization_details_types_supported).toEqual([
        "payment_initiation",
      ]);
      expect(metadata.dpop_bound_access_tokens_required).toBe(true);
      expect(metadata.dpop_signing_alg_values_supported).toEqual([
        "ES256",
        "RS256",
      ]);
      expect(metadata.resource_name).toBe("Test API");
      expect(metadata.resource_policy_uri).toBe(
        "https://test-server.example.com/policy",
      );
      expect(metadata.resource_signing_alg_values_supported).toEqual(["RS256"]);
      expect(metadata.resource_tos_uri).toBe(
        "https://test-server.example.com/tos",
      );
      expect(metadata.scopes_supported).toEqual(["read", "write", "admin"]);
      expect(metadata.service_documentation).toBe(
        "https://developer.example.com/api",
      );
      expect(metadata.tls_client_certificate_bound_access_tokens).toBe(false);

      // Vendor extensions (dynamic properties)
      expect(metadata.vendor_prefix_custom_field).toBe("custom value");
      expect(metadata.vendor_prefix_complex_object).toEqual({
        nestedArray: [1, 2, 3],
        nestedProperty: "nested value",
      });
      expect(metadata.x_api_version).toBe("2.0");
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
