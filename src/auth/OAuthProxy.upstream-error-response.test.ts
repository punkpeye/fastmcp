/**
 * An OAuth provider is allowed to report a failed token request in the body of
 * a 200 response: RFC 6749 §5.2 only says the error fields are present, and
 * GitHub's `/login/oauth/access_token` answers every failure — wrong code,
 * redirect_uri mismatch, denied authorization — that way, in the
 * `application/x-www-form-urlencoded` body its own `parseTokenResponse` branch
 * exists to read.
 *
 * The proxy has to pass that error through as the OAuth error it is,
 * otherwise the failure surfaces as a raw ZodError: `/oauth/callback` then
 * answers the browser with `{"error":"server_error"}` and `/oauth/token`
 * answers a client with `{"error":"invalid_request"}`, so the client is told
 * its own request was malformed when the authorization code it presented was
 * simply rejected upstream.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { afterEach, describe, expect, it, vi } from "vitest";

import { OAuthProxy } from "./OAuthProxy.js";

const baseConfig = {
  baseUrl: "https://proxy.example.com",
  consentRequired: false,
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamClientId: "upstream-client-id",
  upstreamClientSecret: "upstream-client-secret",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
};

const transaction = {
  clientCallbackUrl: "https://client.example.com/callback",
  clientCodeChallenge: "client-challenge",
  clientCodeChallengeMethod: "S256",
  clientId: "client-id",
  createdAt: new Date(),
  expiresAt: new Date(Date.now() + 600000),
  id: "transaction-id",
  proxyCodeChallenge: "proxy-challenge",
  proxyCodeVerifier: "proxy-verifier",
  scope: ["read"],
  state: "state",
};

const mockUpstream = (body: string, contentType: string) => {
  const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
    new Response(body, {
      headers: { "Content-Type": contentType },
      status: 200,
    }),
  );

  return fetchSpy;
};

describe("OAuthProxy - upstream error reported with HTTP 200", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("passes a form-urlencoded upstream error through instead of failing a schema parse", async () => {
    const proxy = new OAuthProxy({
      ...baseConfig,
      enableTokenSwap: false,
    });
    const fetchSpy = mockUpstream(
      "error=bad_verification_code&error_description=The+code+passed+is+incorrect+or+expired.&error_uri=https%3A%2F%2Fprovider.com%2Fdocs",
      "application/x-www-form-urlencoded",
    );

    await expect(
      (proxy as any).exchangeUpstreamCode("auth-code", transaction),
    ).rejects.toMatchObject({
      code: "bad_verification_code",
      description: "The code passed is incorrect or expired.",
      name: "OAuthProxyError",
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);

    proxy.destroy();
  });

  it("passes a JSON upstream error through instead of failing a schema parse", async () => {
    const proxy = new OAuthProxy({
      ...baseConfig,
      enableTokenSwap: false,
    });
    mockUpstream(
      JSON.stringify({
        error: "invalid_grant",
        error_description: "Authorization code expired",
      }),
      "application/json",
    );

    await expect(
      (proxy as any).exchangeUpstreamCode("auth-code", transaction),
    ).rejects.toMatchObject({
      code: "invalid_grant",
      description: "Authorization code expired",
      name: "OAuthProxyError",
    });

    proxy.destroy();
  });

  it("keeps an upstream error with no description", async () => {
    const proxy = new OAuthProxy({
      ...baseConfig,
      enableTokenSwap: false,
    });
    mockUpstream(
      JSON.stringify({ error: "invalid_client" }),
      "application/json",
    );

    await expect(
      (proxy as any).exchangeUpstreamCode("auth-code", transaction),
    ).rejects.toMatchObject({
      code: "invalid_client",
      description: undefined,
      name: "OAuthProxyError",
    });

    proxy.destroy();
  });
});
