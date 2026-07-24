import { afterEach, describe, expect, it, vi } from "vitest";

import type { AuthorizationParams } from "./types.js";

import { OAuthProxy } from "./OAuthProxy.js";
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

const authParams = (clientId: string): AuthorizationParams => ({
  client_id: clientId,
  redirect_uri: CALLBACK_URL,
  response_type: "code",
  state: "client-state",
});

const getRequiredLocation = (response: Response): string => {
  const location = response.headers.get("Location");
  expect(location).toBeTruthy();

  if (!location) {
    throw new Error("Expected response to include a Location header");
  }

  return location;
};

const getRequiredSearchParam = (url: URL, name: string): string => {
  const value = url.searchParams.get(name);
  expect(value).toBeTruthy();

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
            refresh_token: "upstream-refresh-token",
            scope: "read write",
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

describe("OAuthProxy TokenStorage persistence", () => {
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

  const createProxy = (tokenStorage: MemoryTokenStorage): OAuthProxy => {
    const proxy = new OAuthProxy({
      ...baseConfig,
      tokenStorage,
    });
    proxies.push(proxy);
    return proxy;
  };

  it("loads registered DCR clients from shared TokenStorage", async () => {
    // Given a client registered by one proxy instance.
    const tokenStorage = createStorage();
    const registrationProxy = createProxy(tokenStorage);
    const authorizationProxy = createProxy(tokenStorage);

    const dcr = await registrationProxy.registerClient({
      redirect_uris: [CALLBACK_URL],
    });

    // When a different proxy instance handles the authorization request.
    const response = await authorizationProxy.authorize(
      authParams(dcr.client_id),
    );

    // Then it recognizes the persisted client registration.
    expect(response.status).toBe(302);
    const upstreamUrl = new URL(getRequiredLocation(response));
    expect(upstreamUrl.searchParams.get("client_id")).toBe(
      baseConfig.upstreamClientId,
    );
  });

  it("completes authorize to callback to token exchange across shared-storage instances", async () => {
    // Given separate instances that share one TokenStorage backend.
    const tokenStorage = createStorage();
    const registrationProxy = createProxy(tokenStorage);
    const authorizationProxy = createProxy(tokenStorage);
    const callbackProxy = createProxy(tokenStorage);
    const tokenProxy = createProxy(tokenStorage);
    mockUpstreamTokenEndpoint();

    const dcr = await registrationProxy.registerClient({
      redirect_uris: [CALLBACK_URL],
    });

    // When authorization starts on one instance and callback lands on another.
    const authResponse = await authorizationProxy.authorize(
      authParams(dcr.client_id),
    );
    const upstreamUrl = new URL(getRequiredLocation(authResponse));
    const transactionId = getRequiredSearchParam(upstreamUrl, "state");
    const callbackResponse = await callbackProxy.handleCallback(
      new Request(
        `${baseConfig.baseUrl}/oauth/callback?code=upstream-code&state=${encodeURIComponent(
          transactionId,
        )}`,
      ),
    );

    // Then a third instance can exchange the client authorization code.
    const clientRedirectUrl = new URL(getRequiredLocation(callbackResponse));
    const authorizationCode = getRequiredSearchParam(clientRedirectUrl, "code");
    const tokenResponse = await tokenProxy.exchangeAuthorizationCode({
      client_id: dcr.client_id,
      code: authorizationCode,
      grant_type: "authorization_code",
      redirect_uri: CALLBACK_URL,
    });

    expect(tokenResponse).toMatchObject({
      access_token: "upstream-access-token",
      refresh_token: "upstream-refresh-token",
      scope: "read write",
      token_type: "Bearer",
    });
  });

  it("carries a consent-gated flow across instances", async () => {
    // Consent is the one flow that reads a transaction without consuming it:
    // the approving instance has to hand the same transaction to the upstream
    // redirect, and a later instance still has to be able to use it.
    const tokenStorage = createStorage();
    mockUpstreamTokenEndpoint();

    const consentConfig = { ...baseConfig, consentRequired: true };
    const consentProxies = [0, 1, 2].map(() => {
      const proxy = new OAuthProxy({ ...consentConfig, tokenStorage });
      proxies.push(proxy);
      return proxy;
    });

    const dcr = await consentProxies[0].registerClient({
      redirect_uris: [CALLBACK_URL],
    });

    // Authorization renders the consent screen instead of redirecting.
    const consentResponse = await consentProxies[0].authorize(
      authParams(dcr.client_id),
    );
    expect(consentResponse.status).toBe(200);

    const transactionId = /name="transaction_id" value="([^"]+)"/.exec(
      await consentResponse.text(),
    )?.[1];
    expect(transactionId).toBeTruthy();

    // A second instance handles the approval and redirects upstream.
    const approvalResponse = await consentProxies[1].handleConsent(
      new Request(`${baseConfig.baseUrl}/oauth/consent`, {
        body: new URLSearchParams({
          action: "approve",
          transaction_id: transactionId!,
        }).toString(),
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        method: "POST",
      }),
    );

    expect(approvalResponse.status).toBe(302);
    const upstreamUrl = new URL(getRequiredLocation(approvalResponse));
    expect(upstreamUrl.origin + upstreamUrl.pathname).toBe(
      baseConfig.upstreamAuthorizationEndpoint,
    );

    // And a third instance can still complete the callback for it.
    const callbackResponse = await consentProxies[2].handleCallback(
      new Request(
        `${baseConfig.baseUrl}/oauth/callback?code=upstream-code&state=${encodeURIComponent(
          getRequiredSearchParam(upstreamUrl, "state"),
        )}`,
      ),
    );

    expect(callbackResponse.status).toBe(302);
    expect(
      getRequiredSearchParam(
        new URL(getRequiredLocation(callbackResponse)),
        "code",
      ),
    ).toBeTruthy();
  });

  describe("single use is enforced across instances", () => {
    /**
     * Drives authorize -> callback and returns everything needed to redeem the
     * resulting authorization code.
     */
    const issueAuthorizationCode = async (tokenStorage: MemoryTokenStorage) => {
      const registrationProxy = createProxy(tokenStorage);
      const dcr = await registrationProxy.registerClient({
        redirect_uris: [CALLBACK_URL],
      });

      const authResponse = await createProxy(tokenStorage).authorize(
        authParams(dcr.client_id),
      );
      const transactionId = getRequiredSearchParam(
        new URL(getRequiredLocation(authResponse)),
        "state",
      );

      const callbackResponse = await createProxy(tokenStorage).handleCallback(
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

      return {
        request: {
          client_id: dcr.client_id,
          code,
          grant_type: "authorization_code" as const,
          redirect_uri: CALLBACK_URL,
        },
        transactionId,
      };
    };

    it("redeems an authorization code exactly once when two instances race", async () => {
      // Given a code issued into shared storage.
      const tokenStorage = createStorage();
      mockUpstreamTokenEndpoint();
      const { request } = await issueAuthorizationCode(tokenStorage);

      // When two instances that have never seen the code redeem it at once,
      // as a load balancer fanning out a retried request would produce.
      const results = await Promise.allSettled([
        createProxy(tokenStorage).exchangeAuthorizationCode(request),
        createProxy(tokenStorage).exchangeAuthorizationCode(request),
      ]);

      // Then exactly one succeeds (RFC 6749 §4.1.2).
      const fulfilled = results.filter((r) => r.status === "fulfilled");
      expect(fulfilled).toHaveLength(1);
    });

    it("rejects a code that another instance already redeemed", async () => {
      const tokenStorage = createStorage();
      mockUpstreamTokenEndpoint();
      const { request } = await issueAuthorizationCode(tokenStorage);

      await createProxy(tokenStorage).exchangeAuthorizationCode(request);

      await expect(
        createProxy(tokenStorage).exchangeAuthorizationCode(request),
      ).rejects.toMatchObject({ code: "invalid_grant" });
    });

    it("rejects a callback whose transaction another instance already consumed", async () => {
      // Given an authorization started on one instance...
      const tokenStorage = createStorage();
      mockUpstreamTokenEndpoint();
      const authorizationProxy = createProxy(tokenStorage);
      const dcr = await createProxy(tokenStorage).registerClient({
        redirect_uris: [CALLBACK_URL],
      });

      const authResponse = await authorizationProxy.authorize(
        authParams(dcr.client_id),
      );
      const transactionId = getRequiredSearchParam(
        new URL(getRequiredLocation(authResponse)),
        "state",
      );
      const callbackRequest = () =>
        new Request(
          `${baseConfig.baseUrl}/oauth/callback?code=upstream-code&state=${encodeURIComponent(
            transactionId,
          )}`,
        );

      // ...and consumed by a *different* instance.
      await createProxy(tokenStorage).handleCallback(callbackRequest());

      // Then replaying it against the instance that started the flow — which
      // is the one most likely to hold stale local state — must not mint a
      // second authorization code.
      await expect(
        authorizationProxy.handleCallback(callbackRequest()),
      ).rejects.toMatchObject({ code: "invalid_request" });
    });
  });
});
