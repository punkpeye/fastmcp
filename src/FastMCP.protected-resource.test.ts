/**
 * RFC 9728: the protected resource is the MCP endpoint clients connect to.
 * Metadata served at `/.well-known/oauth-protected-resource<endpoint>` must
 * name that resource, and a client that follows `resource_metadata` from a
 * 401 must find a document whose `resource` matches the URL it requested.
 */

import { describe, expect, it } from "vitest";

import { OAuthProvider } from "./auth/providers/OAuthProvider.js";
import { FastMCP } from "./FastMCP.js";
import { getTestPort } from "./getTestPort.js";

const provider = (baseUrl: string) =>
  new OAuthProvider({
    allowedRedirectUriPatterns: ["https://client.example.com/*"],
    authorizationEndpoint: "https://auth.example.com/authorize",
    baseUrl,
    clientId: "test-client-id",
    clientSecret: "test-client-secret",
    tokenEndpoint: "https://auth.example.com/token",
  });

const metadataAt = async (url: string) =>
  (await (await fetch(url)).json()) as Record<string, unknown>;

/** The 401 challenge's `resource_metadata` URL for an unauthenticated POST. */
const challengeUrl = async (endpoint: string) => {
  const response = await fetch(endpoint, {
    body: "{}",
    headers: { "Content-Type": "application/json" },
    method: "POST",
  });
  expect(response.status).toBe(401);
  return /resource_metadata="([^"]+)"/.exec(
    response.headers.get("WWW-Authenticate") ?? "",
  )?.[1];
};

describe("protected resource metadata", () => {
  it("names the MCP endpoint when an auth provider supplies the config", async () => {
    const port = await getTestPort();
    const origin = `http://localhost:${port}`;
    const server = new FastMCP({
      auth: provider(origin),
      name: "Test Server",
      version: "1.0.0",
    });
    await server.start({ httpStream: { port }, transportType: "httpStream" });

    try {
      for (const path of [
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-protected-resource",
      ]) {
        const metadata = await metadataAt(`${origin}${path}`);
        expect(metadata.resource).toBe(`${origin}/mcp`);
        expect(metadata.authorization_servers).toEqual([origin]);
      }

      const url = await challengeUrl(`${origin}/mcp`);
      expect(url).toBe(`${origin}/.well-known/oauth-protected-resource/mcp`);
      expect((await metadataAt(url!)).resource).toBe(`${origin}/mcp`);
    } finally {
      await server.stop();
    }
  });

  it("includes the issuer path and a custom endpoint", async () => {
    const port = await getTestPort();
    const origin = `http://localhost:${port}`;
    const server = new FastMCP({
      auth: provider(`${origin}/issuer1`),
      name: "Test Server",
      version: "1.0.0",
    });
    await server.start({
      httpStream: { basePath: "/issuer1", endpoint: "/api/mcp", port },
      transportType: "httpStream",
    });

    try {
      const metadata = await metadataAt(
        `${origin}/.well-known/oauth-protected-resource/issuer1/api/mcp`,
      );
      expect(metadata.resource).toBe(`${origin}/issuer1/api/mcp`);
    } finally {
      await server.stop();
    }
  });

  it("leaves an explicitly configured resource as it is", async () => {
    const port = await getTestPort();
    const origin = `http://localhost:${port}`;
    const oauth = provider(origin).getOAuthConfig();
    const server = new FastMCP({
      name: "Test Server",
      oauth: {
        ...oauth,
        protectedResource: {
          ...oauth.protectedResource,
          resource: "https://resource.example.com",
        },
      },
      version: "1.0.0",
    });
    await server.start({ httpStream: { port }, transportType: "httpStream" });

    try {
      const metadata = await metadataAt(
        `${origin}/.well-known/oauth-protected-resource`,
      );
      expect(metadata.resource).toBe("https://resource.example.com");
    } finally {
      await server.stop();
    }
  });
});
