/**
 * The token and dynamic-registration endpoints hand back credentials, so their
 * responses must not be storable. RFC 6749 §5.1 requires `Cache-Control:
 * no-store` and `Pragma: no-cache` on token responses, and RFC 7591 §3.2.1
 * requires the same for a registration response carrying `client_secret`.
 */

import { getRandomPort } from "get-port-please";
import { describe, expect, it } from "vitest";

import { OAuthProxy } from "./auth/OAuthProxy.js";
import { FastMCP } from "./FastMCP.js";

describe("OAuth credential responses are not storable", () => {
  it("sets no-store on the registration and token endpoints", async () => {
    const port = await getRandomPort();

    const authProxy = new OAuthProxy({
      allowedRedirectUriPatterns: ["https://client.example.com/*"],
      baseUrl: `http://localhost:${port}`,
      scopes: ["openid", "profile"],
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
      // Dynamic client registration returns client_secret.
      const dcr = await fetch(`http://localhost:${port}/oauth/register`, {
        body: JSON.stringify({
          redirect_uris: ["https://client.example.com/callback"],
        }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });

      expect(dcr.headers.get("cache-control")).toBe("no-store");
      expect(dcr.headers.get("pragma")).toBe("no-cache");

      // The token endpoint returns access_token and refresh_token. This request
      // is rejected, and that is the point: an error response from the token
      // endpoint must not be the one an intermediary caches either.
      const token = await fetch(`http://localhost:${port}/oauth/token`, {
        body: new URLSearchParams({
          client_id: "unknown-client",
          code: "irrelevant",
          grant_type: "authorization_code",
        }).toString(),
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        method: "POST",
      });

      expect(token.headers.get("cache-control")).toBe("no-store");
      expect(token.headers.get("pragma")).toBe("no-cache");
    } finally {
      await server.stop();
    }
  });
});
