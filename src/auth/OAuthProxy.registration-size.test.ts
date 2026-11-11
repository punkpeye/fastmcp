import { afterEach, describe, expect, it } from "vitest";

import { OAuthProxy } from "./OAuthProxy.js";
import { MemoryTokenStorage } from "./utils/tokenStore.js";

const CALLBACK_URL = "https://client.example.com/callback";

describe("OAuthProxy client registration size", () => {
  const proxies: OAuthProxy[] = [];

  afterEach(() => {
    for (const proxy of proxies.splice(0)) proxy.destroy();
  });

  const createProxy = () => {
    const tokenStorage = new MemoryTokenStorage();
    const proxy = new OAuthProxy({
      allowedRedirectUriPatterns: ["https://client.example.com/*"],
      baseUrl: "https://proxy.example.com",
      // Stored as given, so the test can count what a registration kept.
      encryptionKey: false,
      tokenStorage,
      upstreamAuthorizationEndpoint: "https://provider.example.com/authorize",
      upstreamClientId: "upstream-client",
      upstreamClientSecret: "upstream-secret",
      upstreamTokenEndpoint: "https://provider.example.com/token",
    });

    proxies.push(proxy);

    return { proxy, tokenStorage };
  };

  it.each([
    ["a client name", { client_name: "x".repeat(40_000) }],
    ["a key set", { jwks: { keys: [{ n: "x".repeat(40_000) }] } }],
    [
      "contacts",
      { contacts: Array.from({ length: 4000 }, () => "a@example.com") },
    ],
  ])("refuses a registration made too large by %s", async (_, metadata) => {
    const { proxy, tokenStorage } = createProxy();

    await expect(
      proxy.registerClient({ ...metadata, redirect_uris: [CALLBACK_URL] }),
    ).rejects.toMatchObject({
      code: "invalid_client_metadata",
      description: "Client metadata must not exceed 32768 bytes",
    });

    expect(tokenStorage.size()).toBe(0);
  });

  it("refuses an oversized list of redirect URIs before validating them", async () => {
    const { proxy, tokenStorage } = createProxy();

    // None of these is allowed, and the first would be reported if any were
    // looked at.
    const redirectUris = Array.from(
      { length: 5000 },
      (_, index) => `https://evil.example.com/callback/${index}`,
    );

    await expect(
      proxy.registerClient({ redirect_uris: redirectUris }),
    ).rejects.toMatchObject({ code: "invalid_client_metadata" });

    expect(tokenStorage.size()).toBe(0);
  });

  it("registers a client whose metadata fits", async () => {
    const { proxy, tokenStorage } = createProxy();

    const registration = await proxy.registerClient({
      client_name: "x".repeat(30_000),
      client_uri: "https://client.example.com",
      redirect_uris: [CALLBACK_URL, `${CALLBACK_URL}/2`],
    });

    expect(registration.client_id).toEqual(expect.any(String));
    expect(registration.client_name).toHaveLength(30_000);
    expect(tokenStorage.size()).toBe(1);
  });
});
