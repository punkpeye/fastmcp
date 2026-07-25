/**
 * The consent endpoint is the only place a user's explicit approval is
 * recorded, so it has to fail closed: an submission that does not clearly say
 * "approve" must not be treated as one.
 */

import { afterEach, describe, expect, it } from "vitest";

import { OAuthProxy, OAuthProxyError } from "./OAuthProxy.js";
import { MemoryTokenStorage } from "./utils/tokenStore.js";

const CALLBACK_URL = "https://client.example.com/callback";

const baseConfig = {
  allowedRedirectUriPatterns: ["https://client.example.com/*"],
  baseUrl: "https://proxy.example.com",
  consentRequired: true,
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamClientId: "upstream-client-id",
  upstreamClientSecret: "upstream-client-secret",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
};

describe("OAuthProxy consent action handling", () => {
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
  });

  /** Drives authorize() up to the consent screen and returns its transaction. */
  const startConsentFlow = async () => {
    const tokenStorage = new MemoryTokenStorage();
    storages.push(tokenStorage);

    const proxy = new OAuthProxy({ ...baseConfig, tokenStorage });
    proxies.push(proxy);

    const dcr = await proxy.registerClient({ redirect_uris: [CALLBACK_URL] });
    const response = await proxy.authorize({
      client_id: dcr.client_id,
      redirect_uri: CALLBACK_URL,
      response_type: "code",
      state: "client-state",
    });
    expect(response.status).toBe(200);

    const transactionId = /name="transaction_id" value="([^"]+)"/.exec(
      await response.text(),
    )?.[1];
    expect(transactionId).toBeTruthy();

    return { proxy, transactionId: transactionId! };
  };

  const submitConsent = (
    proxy: OAuthProxy,
    body: Record<string, string>,
  ): Promise<Response> =>
    proxy.handleConsent(
      new Request(`${baseConfig.baseUrl}/oauth/consent`, {
        body: new URLSearchParams(body).toString(),
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        method: "POST",
      }),
    );

  it.each([
    ["omitted", {}],
    ["empty", { action: "" }],
    ["unrecognised", { action: "maybe" }],
    ["approve with different casing", { action: "Approve" }],
  ])("rejects a submission whose action is %s", async (_label, fields) => {
    const { proxy, transactionId } = await startConsentFlow();

    // Any of these used to fall through to the approve branch and redirect the
    // user upstream without them having agreed to anything.
    await expect(
      submitConsent(proxy, { ...fields, transaction_id: transactionId }),
    ).rejects.toMatchObject({
      code: "invalid_request",
      description: "action must be 'approve' or 'deny'",
    });
  });

  it("rejects an unrecognised action before looking up the transaction", async () => {
    const { proxy } = await startConsentFlow();

    // A bad action is rejected on its own terms, so the response cannot be
    // used to probe which transaction ids exist.
    await expect(
      submitConsent(proxy, {
        action: "maybe",
        transaction_id: "not-a-real-transaction",
      }),
    ).rejects.toMatchObject({
      code: "invalid_request",
      description: "action must be 'approve' or 'deny'",
    });
  });

  it("redirects upstream on approve", async () => {
    const { proxy, transactionId } = await startConsentFlow();

    const response = await submitConsent(proxy, {
      action: "approve",
      transaction_id: transactionId,
    });

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("Location") ?? "");
    expect(location.origin + location.pathname).toBe(
      baseConfig.upstreamAuthorizationEndpoint,
    );
  });

  it("redirects back to the client with access_denied on deny", async () => {
    const { proxy, transactionId } = await startConsentFlow();

    const response = await submitConsent(proxy, {
      action: "deny",
      transaction_id: transactionId,
    });

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("Location") ?? "");
    expect(location.origin + location.pathname).toBe(CALLBACK_URL);
    expect(location.searchParams.get("error")).toBe("access_denied");

    // The transaction is gone, so the denial cannot be re-submitted as an
    // approval.
    await expect(
      submitConsent(proxy, {
        action: "approve",
        transaction_id: transactionId,
      }),
    ).rejects.toBeInstanceOf(OAuthProxyError);
  });
});
