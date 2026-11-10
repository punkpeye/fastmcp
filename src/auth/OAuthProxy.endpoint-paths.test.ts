import { registerClient } from "@modelcontextprotocol/sdk/client/auth.js";
import { Hono } from "hono";
import { afterEach, describe, expect, it, vi } from "vitest";

import { OAuthProxy } from "./OAuthProxy.js";
import { PKCEUtils } from "./utils/pkce.js";

const CALLBACK = "https://client.example.com/callback";

describe("OAuthProxy endpoint paths", () => {
  const proxies: OAuthProxy[] = [];
  afterEach(() => {
    for (const proxy of proxies.splice(0)) proxy.destroy();
    vi.restoreAllMocks();
  });

  it.each(["", "/issuer", "/tenant/team"])(
    "accepts a trailing slash on baseUrl (%s)",
    async (path) => {
      const baseUrl = `https://proxy.example.com${path}/`;
      const proxy = new OAuthProxy({
        allowedRedirectUriPatterns: ["https://client.example.com/*"],
        baseUrl,
        consentRequired: false,
        upstreamAuthorizationEndpoint: "https://provider.example.com/authorize",
        upstreamClientId: "upstream-client",
        upstreamClientSecret: "upstream-secret",
        upstreamTokenEndpoint: "https://provider.example.com/token",
      });
      proxies.push(proxy);
      const metadata = proxy.getAuthorizationServerMetadata();
      const app = new Hono();
      app.post(`${path}/oauth/register`, async (c) =>
        c.json(await proxy.registerClient(await c.req.json()), 201),
      );
      const client = await registerClient(baseUrl, {
        clientMetadata: { redirect_uris: [CALLBACK] },
        fetchFn: async (input, init) => app.fetch(new Request(input, init)),
        metadata: {
          authorization_endpoint: metadata.authorizationEndpoint,
          issuer: metadata.issuer,
          registration_endpoint: metadata.registrationEndpoint,
          response_types_supported: ["code"],
          token_endpoint: metadata.tokenEndpoint,
        },
      });
      expect(metadata.issuer).toBe(baseUrl);
      expect(metadata.authorizationEndpoint).toBe(`${baseUrl}oauth/authorize`);
      expect(metadata.tokenEndpoint).toBe(`${baseUrl}oauth/token`);

      const pkce = PKCEUtils.generatePair("S256");
      const authorization = await proxy.authorize({
        client_id: client.client_id,
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
        redirect_uri: CALLBACK,
        response_type: "code",
      });
      const upstreamUrl = new URL(authorization.headers.get("Location")!);
      expect(upstreamUrl.searchParams.get("redirect_uri")).toBe(
        `${baseUrl}oauth/callback`,
      );
      const upstream = vi.spyOn(globalThis, "fetch").mockResolvedValue(
        Response.json({
          access_token: "upstream-access",
          token_type: "Bearer",
        }),
      );
      const callback = await proxy.handleCallback(
        new Request(
          `${baseUrl}oauth/callback?${new URLSearchParams({
            code: "upstream-code",
            state: upstreamUrl.searchParams.get("state")!,
          })}`,
        ),
      );
      expect(callback.status).toBe(302);
      const sent = new URLSearchParams(
        upstream.mock.calls[0][1]?.body as string,
      );
      expect(sent.get("redirect_uri")).toBe(`${baseUrl}oauth/callback`);
    },
  );
});
