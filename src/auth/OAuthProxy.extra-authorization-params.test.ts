/**
 * Tests for `extraAuthorizationParams` (issue #276).
 *
 * Providers like Google only issue a refresh_token when the authorization
 * request carries provider-specific parameters (`access_type=offline`,
 * `prompt=consent`). `OAuthProxy` must be able to append such parameters to
 * the upstream authorization URL, while never letting them override the
 * core OAuth parameters the proxy controls (client_id, redirect_uri, ...).
 */

import { afterEach, describe, expect, it } from "vitest";

import type { AuthorizationParams, OAuthProxyConfig } from "./types.js";

import { OAuthProxy } from "./OAuthProxy.js";

const CLIENT_REDIRECT = "https://client.example.com/callback";

const baseConfig: OAuthProxyConfig = {
  allowedRedirectUriPatterns: ["https://client.example.com/*"],
  baseUrl: "http://localhost:4200",
  consentRequired: false,
  scopes: ["openid", "email"],
  upstreamAuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
  upstreamClientId: "upstream-client-id",
  upstreamClientSecret: "upstream-client-secret",
  upstreamTokenEndpoint: "https://oauth2.googleapis.com/token",
};

/**
 * Register a client via DCR, run authorize(), and return the parsed
 * upstream authorization URL from the redirect Location header.
 */
async function getUpstreamAuthorizationUrl(proxy: OAuthProxy): Promise<URL> {
  const dcr = await proxy.registerClient({
    redirect_uris: [CLIENT_REDIRECT],
  });

  const response = await proxy.authorize({
    client_id: dcr.client_id,
    redirect_uri: CLIENT_REDIRECT,
    response_type: "code",
    state: "client-state",
  } as AuthorizationParams);

  expect(response.status).toBe(302);
  const location = response.headers.get("Location");
  expect(location).toBeTruthy();
  return new URL(location!);
}

describe("OAuthProxy extraAuthorizationParams", () => {
  let proxy: OAuthProxy;

  afterEach(() => {
    proxy.destroy();
  });

  it("appends configured extra params to the upstream authorization URL", async () => {
    proxy = new OAuthProxy({
      ...baseConfig,
      extraAuthorizationParams: {
        access_type: "offline",
        prompt: "consent",
      },
    });

    const authUrl = await getUpstreamAuthorizationUrl(proxy);

    expect(authUrl.searchParams.get("access_type")).toBe("offline");
    expect(authUrl.searchParams.get("prompt")).toBe("consent");
  });

  it("leaves the authorization URL unchanged when not configured", async () => {
    proxy = new OAuthProxy(baseConfig);

    const authUrl = await getUpstreamAuthorizationUrl(proxy);

    expect([...authUrl.searchParams.keys()].sort()).toEqual([
      "client_id",
      "code_challenge",
      "code_challenge_method",
      "redirect_uri",
      "response_type",
      "scope",
      "state",
    ]);
  });

  it("does not let extra params override core OAuth parameters", async () => {
    proxy = new OAuthProxy({
      ...baseConfig,
      extraAuthorizationParams: {
        access_type: "offline",
        client_id: "attacker-client-id",
        code_challenge: "attacker-challenge",
        code_challenge_method: "plain",
        redirect_uri: "https://evil.example.com/steal",
        response_type: "token",
        scope: "attacker-scope",
        state: "attacker-state",
      },
    });

    const authUrl = await getUpstreamAuthorizationUrl(proxy);

    // The benign extra param still goes through...
    expect(authUrl.searchParams.get("access_type")).toBe("offline");

    // ...but every proxy-controlled parameter keeps its original value.
    expect(authUrl.searchParams.get("client_id")).toBe("upstream-client-id");
    expect(authUrl.searchParams.get("redirect_uri")).toBe(
      "http://localhost:4200/oauth/callback",
    );
    expect(authUrl.searchParams.get("response_type")).toBe("code");
    expect(authUrl.searchParams.get("state")).not.toBe("attacker-state");
    expect(authUrl.searchParams.get("scope")).not.toBe("attacker-scope");
    expect(authUrl.searchParams.get("code_challenge")).not.toBe(
      "attacker-challenge",
    );
    expect(authUrl.searchParams.get("code_challenge_method")).toBe("S256");
  });

  it("keeps proxy PKCE intact even when forwardPkce is false and extras try to inject a challenge", async () => {
    proxy = new OAuthProxy({
      ...baseConfig,
      extraAuthorizationParams: {
        code_challenge: "attacker-challenge",
      },
      forwardPkce: false,
    });

    const authUrl = await getUpstreamAuthorizationUrl(proxy);

    expect(authUrl.searchParams.get("code_challenge")).not.toBe(
      "attacker-challenge",
    );
    expect(authUrl.searchParams.get("code_challenge_method")).toBe("S256");
  });
});
