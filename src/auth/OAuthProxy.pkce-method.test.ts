/**
 * RFC 7636 §4.4.1: when the server does not support the requested
 * `code_challenge_method`, the authorization endpoint MUST answer
 * `invalid_request`. A code issued under such a method can never be redeemed,
 * because the token endpoint knows no transformation to check it with, so the
 * user would be sent through upstream consent for nothing.
 */

import { afterEach, describe, expect, it } from "vitest";

import type { AuthorizationParams } from "./types.js";

import { OAuthProxy } from "./OAuthProxy.js";

const CALLBACK_URL = "https://client.example.com/callback";

const authParams = (
  clientId: string,
  overrides: Partial<AuthorizationParams> = {},
): AuthorizationParams => ({
  client_id: clientId,
  redirect_uri: CALLBACK_URL,
  response_type: "code",
  state: "client-state",
  ...overrides,
});

describe("OAuthProxy authorize() code_challenge_method", () => {
  const proxies: OAuthProxy[] = [];

  afterEach(() => {
    for (const proxy of proxies) {
      proxy.destroy();
    }
    proxies.length = 0;
  });

  const createProxy = (): OAuthProxy => {
    const proxy = new OAuthProxy({
      allowedRedirectUriPatterns: ["https://client.example.com/*"],
      baseUrl: "https://proxy.example.com",
      consentRequired: false,
      enableTokenSwap: false,
      encryptionKey: "test-encryption-key",
      upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
      upstreamClientId: "upstream-client-id",
      upstreamClientSecret: "upstream-client-secret",
      upstreamTokenEndpoint: "https://provider.com/oauth/token",
    });
    proxies.push(proxy);
    return proxy;
  };

  it.each(["S512", "s256", "sha256"])(
    "rejects code_challenge_method %j with invalid_request",
    async (method) => {
      const proxy = createProxy();
      const dcr = await proxy.registerClient({ redirect_uris: [CALLBACK_URL] });

      await expect(
        proxy.authorize(
          authParams(dcr.client_id, {
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            code_challenge_method: method,
          }),
        ),
      ).rejects.toMatchObject({
        code: "invalid_request",
        name: "OAuthProxyError",
      });
    },
  );

  it("still accepts S256, and plain while it is allowed", async () => {
    const proxy = createProxy();
    const dcr = await proxy.registerClient({ redirect_uris: [CALLBACK_URL] });

    for (const method of ["S256", "plain"]) {
      const response = await proxy.authorize(
        authParams(dcr.client_id, {
          code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
          code_challenge_method: method,
        }),
      );

      expect(response.status).toBe(302);
    }
  });
});
