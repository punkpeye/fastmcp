/**
 * `allowPlainPkce` lets a deployment refuse PKCE `plain`.
 *
 * With `plain` the code challenge *is* the verifier (RFC 7636 §4.2), so it
 * travels in the authorization request in the clear and anyone who observes
 * that request can redeem a stolen authorization code. RFC 7636 §7.2 says to
 * prefer S256; OAuth 2.1 §7.5.2 and the MCP authorization spec require it.
 *
 * The option defaults to `true` — refusing `plain` outright would break
 * clients that still ask for it — so these tests pin both halves: the default
 * keeps working, and opting out closes every way in.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import type { AuthorizationParams } from "./types.js";

import { OAuthProxy, OAuthProxyError } from "./OAuthProxy.js";
import { PKCEUtils } from "./utils/pkce.js";
import { MemoryTokenStorage } from "./utils/tokenStore.js";

const CALLBACK_URL = "https://client.example.com/callback";

const baseConfig = {
  allowedRedirectUriPatterns: ["https://client.example.com/*"],
  baseUrl: "https://proxy.example.com",
  consentRequired: false,
  enableTokenSwap: false,
  encryptionKey: "shared-encryption-key",
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamClientId: "upstream-client-id",
  upstreamClientSecret: "upstream-client-secret",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
};

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

const getRequiredLocation = (response: Response): string => {
  const location = response.headers.get("Location");

  if (!location) {
    throw new Error("Expected response to include a Location header");
  }

  return location;
};

const getRequiredSearchParam = (url: URL, name: string): string => {
  const value = url.searchParams.get(name);

  if (!value) {
    throw new Error(`Expected URL to include ${name}`);
  }

  return value;
};

const mockUpstreamTokenEndpoint = (): void => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            access_token: "upstream-access-token",
            expires_in: 3600,
            scope: "read",
            token_type: "Bearer",
          }),
          {
            headers: { "Content-Type": "application/json" },
            status: 200,
          },
        ),
    ),
  );
};

describe("OAuthProxy allowPlainPkce", () => {
  const proxies: OAuthProxy[] = [];
  const storages: MemoryTokenStorage[] = [];

  afterEach(() => {
    for (const proxy of proxies) {
      proxy.destroy();
    }
    proxies.length = 0;

    for (const storage of storages) {
      storage.destroy();
    }
    storages.length = 0;

    vi.unstubAllGlobals();
  });

  const createStorage = (): MemoryTokenStorage => {
    const storage = new MemoryTokenStorage();
    storages.push(storage);
    return storage;
  };

  const createProxy = (
    overrides: { allowPlainPkce?: boolean } & Partial<typeof baseConfig> = {},
    tokenStorage?: MemoryTokenStorage,
  ): OAuthProxy => {
    const proxy = new OAuthProxy({
      ...baseConfig,
      ...overrides,
      ...(tokenStorage ? { tokenStorage } : {}),
    });
    proxies.push(proxy);
    return proxy;
  };

  describe("discovery metadata", () => {
    it("advertises plain by default", () => {
      const metadata = createProxy().getAuthorizationServerMetadata();

      expect(metadata.codeChallengeMethodsSupported).toEqual(["S256", "plain"]);
    });

    it("advertises only S256 when plain is disabled", () => {
      const metadata = createProxy({
        allowPlainPkce: false,
      }).getAuthorizationServerMetadata();

      expect(metadata.codeChallengeMethodsSupported).toEqual(["S256"]);
    });
  });

  describe("authorize()", () => {
    it("accepts plain by default", async () => {
      const proxy = createProxy();
      const dcr = await proxy.registerClient({
        redirect_uris: [CALLBACK_URL],
      });
      const verifier = PKCEUtils.generateVerifier();

      const response = await proxy.authorize(
        authParams(dcr.client_id, {
          code_challenge: verifier,
          code_challenge_method: "plain",
        }),
      );

      expect(response.status).toBe(302);
    });

    it("rejects plain when disabled", async () => {
      const proxy = createProxy({ allowPlainPkce: false });
      const dcr = await proxy.registerClient({
        redirect_uris: [CALLBACK_URL],
      });
      const verifier = PKCEUtils.generateVerifier();

      // Rejected here rather than at the token endpoint, so the client fails
      // before a user is walked through an upstream consent screen.
      await expect(
        proxy.authorize(
          authParams(dcr.client_id, {
            code_challenge: verifier,
            code_challenge_method: "plain",
          }),
        ),
      ).rejects.toMatchObject({
        code: "invalid_request",
        name: "OAuthProxyError",
      });
    });

    it("still accepts S256 when plain is disabled", async () => {
      const proxy = createProxy({ allowPlainPkce: false });
      const dcr = await proxy.registerClient({
        redirect_uris: [CALLBACK_URL],
      });
      const verifier = PKCEUtils.generateVerifier();

      const response = await proxy.authorize(
        authParams(dcr.client_id, {
          code_challenge: PKCEUtils.generateChallenge(verifier, "S256"),
          code_challenge_method: "S256",
        }),
      );

      expect(response.status).toBe(302);
    });
  });

  describe("token exchange", () => {
    it("refuses a plain code issued before plain was disabled", async () => {
      // Authorization codes are persisted, so one minted while plain was still
      // allowed can outlive the config change. Sharing storage between two
      // proxies reproduces that without faking a restart.
      const tokenStorage = createStorage();
      const permissive = createProxy({}, tokenStorage);
      const strict = createProxy({ allowPlainPkce: false }, tokenStorage);
      mockUpstreamTokenEndpoint();

      const dcr = await permissive.registerClient({
        redirect_uris: [CALLBACK_URL],
      });
      const verifier = PKCEUtils.generateVerifier();

      const authResponse = await permissive.authorize(
        authParams(dcr.client_id, {
          code_challenge: verifier,
          code_challenge_method: "plain",
        }),
      );
      const transactionId = getRequiredSearchParam(
        new URL(getRequiredLocation(authResponse)),
        "state",
      );
      const callbackResponse = await permissive.handleCallback(
        new Request(
          `${baseConfig.baseUrl}/oauth/callback?code=upstream-code&state=${encodeURIComponent(
            transactionId,
          )}`,
        ),
      );
      const code = getRequiredSearchParam(
        new URL(getRequiredLocation(callbackResponse)),
        "code",
      );

      // The correct verifier is presented; it is the method that is refused.
      await expect(
        strict.exchangeAuthorizationCode({
          client_id: dcr.client_id,
          code,
          code_verifier: verifier,
          grant_type: "authorization_code",
          redirect_uri: CALLBACK_URL,
        }),
      ).rejects.toBeInstanceOf(OAuthProxyError);
    });

    it("still redeems a plain code while plain is allowed", async () => {
      const tokenStorage = createStorage();
      const proxy = createProxy({}, tokenStorage);
      mockUpstreamTokenEndpoint();

      const dcr = await proxy.registerClient({
        redirect_uris: [CALLBACK_URL],
      });
      const verifier = PKCEUtils.generateVerifier();

      const authResponse = await proxy.authorize(
        authParams(dcr.client_id, {
          code_challenge: verifier,
          code_challenge_method: "plain",
        }),
      );
      const transactionId = getRequiredSearchParam(
        new URL(getRequiredLocation(authResponse)),
        "state",
      );
      const callbackResponse = await proxy.handleCallback(
        new Request(
          `${baseConfig.baseUrl}/oauth/callback?code=upstream-code&state=${encodeURIComponent(
            transactionId,
          )}`,
        ),
      );
      const code = getRequiredSearchParam(
        new URL(getRequiredLocation(callbackResponse)),
        "code",
      );

      const tokenResponse = await proxy.exchangeAuthorizationCode({
        client_id: dcr.client_id,
        code,
        code_verifier: verifier,
        grant_type: "authorization_code",
        redirect_uri: CALLBACK_URL,
      });

      expect(tokenResponse).toMatchObject({
        access_token: "upstream-access-token",
        token_type: "Bearer",
      });
    });
  });
});
