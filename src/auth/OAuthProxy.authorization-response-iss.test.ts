/**
 * RFC 9207: authorization responses carry `iss` (the metadata issuer), and
 * the metadata advertises it, unless `authorizationResponseIss` is false.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import type { OAuthProxyConfig } from "./types.js";

import { OAuthProxy } from "./OAuthProxy.js";
import { PKCEUtils } from "./utils/pkce.js";
import { MemoryTokenStorage } from "./utils/tokenStore.js";

const CALLBACK_URL = "https://client.example.com/callback";

const baseConfig = {
  allowedRedirectUriPatterns: ["https://client.example.com/*"],
  baseUrl: "https://proxy.example.com",
  consentRequired: false,
  enableTokenSwap: false,
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamClientId: "upstream-client-id",
  upstreamClientSecret: "upstream-client-secret",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
};

const location = (response: Response) =>
  new URL(response.headers.get("Location")!);

describe("OAuthProxy authorizationResponseIss", () => {
  const proxies: OAuthProxy[] = [];

  afterEach(() => {
    for (const proxy of proxies) proxy.destroy();
    proxies.length = 0;
    vi.unstubAllGlobals();
  });

  const createProxy = (config: Partial<OAuthProxyConfig> = {}) => {
    const proxy = new OAuthProxy({
      ...baseConfig,
      tokenStorage: new MemoryTokenStorage(),
      ...config,
    });
    proxies.push(proxy);
    return proxy;
  };

  const authorize = async (proxy: OAuthProxy) => {
    const { client_id } = await proxy.registerClient({
      redirect_uris: [CALLBACK_URL],
    });
    return proxy.authorize({
      client_id,
      code_challenge: PKCEUtils.generateChallenge(
        PKCEUtils.generateVerifier(),
        "S256",
      ),
      code_challenge_method: "S256",
      redirect_uri: CALLBACK_URL,
      response_type: "code",
      state: "client-state",
    });
  };

  /** Completes /oauth/callback against a stubbed upstream token endpoint. */
  const callback = async (proxy: OAuthProxy) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({ access_token: "upstream", token_type: "Bearer" }),
      ),
    );
    const state = location(await authorize(proxy)).searchParams.get("state")!;
    return location(
      await proxy.handleCallback(
        new Request(
          `${baseConfig.baseUrl}/oauth/callback?code=upstream-code&state=${state}`,
        ),
      ),
    );
  };

  it("is on by default: advertised, and sent on the success redirect", async () => {
    const proxy = createProxy();

    expect(
      proxy.getAuthorizationServerMetadata()
        .authorizationResponseIssParameterSupported,
    ).toBe(true);
    const redirect = await callback(proxy);
    expect(redirect.searchParams.get("code")).toBeTruthy();
    expect(redirect.searchParams.get("iss")).toBe(
      proxy.getAuthorizationServerMetadata().issuer,
    );
  });

  it("is sent on the error redirect when consent is denied", async () => {
    const proxy = createProxy({ consentRequired: true });
    const transactionId = /name="transaction_id" value="([^"]+)"/.exec(
      await (await authorize(proxy)).text(),
    )![1];

    const redirect = location(
      await proxy.handleConsent(
        new Request(`${baseConfig.baseUrl}/oauth/consent`, {
          body: new URLSearchParams({
            action: "deny",
            transaction_id: transactionId,
          }),
          method: "POST",
        }),
      ),
    );

    expect(redirect.searchParams.get("error")).toBe("access_denied");
    expect(redirect.searchParams.get("iss")).toBe(baseConfig.baseUrl);
  });

  it("is neither advertised nor sent when turned off", async () => {
    const proxy = createProxy({ authorizationResponseIss: false });

    expect(proxy.getAuthorizationServerMetadata()).not.toHaveProperty(
      "authorizationResponseIssParameterSupported",
    );
    expect((await callback(proxy)).searchParams.has("iss")).toBe(false);
  });
});
