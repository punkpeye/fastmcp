/**
 * Client ID Metadata Document (CIMD) support in OAuthProxy.
 *
 * CIMD (MCP authorization spec SEP-991) lets a client identify itself with
 * an HTTPS URL instead of calling POST /oauth/register. These tests cover
 * the feature end-to-end through authorize() and exchangeAuthorizationCode(),
 * that it is off unless explicitly enabled, and that it does not weaken the
 * existing redirect-URI allow-list.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import type { AuthorizationParams, UpstreamTokenSet } from "./types.js";

import { OAuthProxy, OAuthProxyError } from "./OAuthProxy.js";
import { PKCEUtils } from "./utils/pkce.js";

const CLIENT_METADATA_URL = "https://client.example.com/client-metadata.json";
const REDIRECT_URI = "http://127.0.0.1:33418/";

/**
 * A CIMD client is a public client, so the proxy requires S256 PKCE from it.
 * One pair is reused across the suite; nothing here depends on it being fresh.
 */
const PKCE = PKCEUtils.generatePair("S256");

const baseConfig = {
  allowedRedirectUriPatterns: ["http://127.0.0.1:*"],
  baseUrl: "http://localhost:4200",
  consentRequired: false,
  // Pass-through mode, so the token-exchange assertions below can check the
  // mocked upstream token directly — token swap itself is covered by
  // OAuthProxy.token-swap.test.ts and is orthogonal to CIMD identity resolution.
  enableTokenSwap: false,
  encryptionKey: false as const,
  redirectPath: "/oauth/callback",
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamClientId: "legit-upstream-id",
  upstreamClientSecret: "legit-upstream-secret",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
};

function buildAuthParams(
  overrides: Partial<AuthorizationParams> = {},
): AuthorizationParams {
  return {
    client_id: CLIENT_METADATA_URL,
    code_challenge: PKCE.challenge,
    code_challenge_method: "S256",
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    state: "test-state",
    ...overrides,
  } as AuthorizationParams;
}

function clientMetadataFetchCount(
  fetchMock: ReturnType<typeof mockFetchRouting>,
): number {
  return fetchMock.mock.calls.filter(
    ([input]) =>
      (typeof input === "string" ? input : input.toString()) ===
      CLIENT_METADATA_URL,
  ).length;
}

function clientMetadataResponse(
  overrides: Record<string, unknown> = {},
): Response {
  return new Response(
    JSON.stringify({
      client_id: CLIENT_METADATA_URL,
      client_name: "Example MCP Client",
      redirect_uris: [REDIRECT_URI],
      ...overrides,
    }),
    { headers: { "Content-Type": "application/json" }, status: 200 },
  );
}

/**
 * Routes the client-metadata URL to one handler and everything else (the
 * upstream token endpoint) to another, so a single mock can drive a full
 * authorize -> callback -> token flow.
 */
function mockFetchRouting(clientMetadataHandler: () => Response) {
  const fetchMock = vi.fn(async (input: Request | string | URL) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url === CLIENT_METADATA_URL) {
      return clientMetadataHandler();
    }
    return upstreamTokenResponse();
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function upstreamTokenResponse(): Response {
  const upstream: UpstreamTokenSet = {
    accessToken: "UP_ACCESS_TOKEN",
    expiresIn: 3600,
    issuedAt: new Date(),
    scope: ["read"],
    tokenType: "Bearer",
  };
  return new Response(
    JSON.stringify({
      access_token: upstream.accessToken,
      expires_in: upstream.expiresIn,
      scope: upstream.scope.join(" "),
      token_type: upstream.tokenType,
    }),
    { headers: { "Content-Type": "application/json" }, status: 200 },
  );
}

describe("OAuthProxy CIMD support", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("is off by default: a CIMD-shaped client_id is still an unknown client", async () => {
    const proxy = new OAuthProxy(baseConfig);
    mockFetchRouting(clientMetadataResponse);

    await expect(proxy.authorize(buildAuthParams())).rejects.toMatchObject({
      code: "invalid_client",
    });

    proxy.destroy();
  });

  it("does not advertise client_id_metadata_document_supported when disabled", () => {
    const proxy = new OAuthProxy(baseConfig);
    expect(
      proxy.getAuthorizationServerMetadata().clientIdMetadataDocumentSupported,
    ).toBeUndefined();
    proxy.destroy();
  });

  it("advertises client_id_metadata_document_supported when enabled", () => {
    const proxy = new OAuthProxy({ ...baseConfig, enableCimd: true });
    expect(
      proxy.getAuthorizationServerMetadata().clientIdMetadataDocumentSupported,
    ).toBe(true);
    proxy.destroy();
  });

  it("resolves a valid CIMD client_id and completes the full authorize -> callback -> token flow", async () => {
    const proxy = new OAuthProxy({ ...baseConfig, enableCimd: true });
    mockFetchRouting(clientMetadataResponse);

    const authResp = await proxy.authorize(buildAuthParams());
    expect(authResp.status).toBe(302);

    const upstreamUrl = new URL(authResp.headers.get("Location")!);
    const transactionId = upstreamUrl.searchParams.get("state")!;

    const cbReq = new Request(
      `${baseConfig.baseUrl}${baseConfig.redirectPath}?code=UP_CODE&state=${encodeURIComponent(transactionId)}`,
    );
    const cbResp = await proxy.handleCallback(cbReq);
    expect(cbResp.status).toBe(302);

    const finalLocation = new URL(cbResp.headers.get("Location")!);
    expect(finalLocation.origin + finalLocation.pathname).toBe(REDIRECT_URI);
    const code = finalLocation.searchParams.get("code")!;
    expect(code).toBeTruthy();

    const tokenResp = await proxy.exchangeAuthorizationCode({
      client_id: CLIENT_METADATA_URL,
      code,
      code_verifier: PKCE.verifier,
      grant_type: "authorization_code",
      redirect_uri: REDIRECT_URI,
    });
    expect(tokenResp.access_token).toBe("UP_ACCESS_TOKEN");

    proxy.destroy();
  });

  it("caches the resolved client: the metadata document is fetched only once across authorize + token exchange", async () => {
    const proxy = new OAuthProxy({ ...baseConfig, enableCimd: true });
    const fetchMock = mockFetchRouting(clientMetadataResponse);

    const authResp = await proxy.authorize(buildAuthParams());
    const upstreamUrl = new URL(authResp.headers.get("Location")!);
    const transactionId = upstreamUrl.searchParams.get("state")!;

    const cbReq = new Request(
      `${baseConfig.baseUrl}${baseConfig.redirectPath}?code=UP_CODE&state=${encodeURIComponent(transactionId)}`,
    );
    const cbResp = await proxy.handleCallback(cbReq);
    const finalLocation = new URL(cbResp.headers.get("Location")!);
    const code = finalLocation.searchParams.get("code")!;

    await proxy.exchangeAuthorizationCode({
      client_id: CLIENT_METADATA_URL,
      code,
      code_verifier: PKCE.verifier,
      grant_type: "authorization_code",
      redirect_uri: REDIRECT_URI,
    });

    const clientMetadataFetches = fetchMock.mock.calls.filter(
      ([input]) =>
        (typeof input === "string" ? input : input.toString()) ===
        CLIENT_METADATA_URL,
    );
    expect(clientMetadataFetches).toHaveLength(1);

    proxy.destroy();
  });

  it("re-reads the metadata document once the cached resolution lapses", async () => {
    vi.useFakeTimers();

    try {
      const proxy = new OAuthProxy({ ...baseConfig, enableCimd: true });
      const fetchMock = mockFetchRouting(clientMetadataResponse);

      await proxy.authorize(buildAuthParams());
      expect(clientMetadataFetchCount(fetchMock)).toBe(1);

      // Still inside the cache window: served from the cached resolution.
      vi.advanceTimersByTime(60_000);
      await proxy.authorize(buildAuthParams());
      expect(clientMetadataFetchCount(fetchMock)).toBe(1);

      // Past it: the document is authoritative again, not the snapshot.
      vi.advanceTimersByTime(15 * 60 * 1000);
      await proxy.authorize(buildAuthParams());
      expect(clientMetadataFetchCount(fetchMock)).toBe(2);

      proxy.destroy();
    } finally {
      vi.useRealTimers();
    }
  });

  it("stops honouring a client whose document dropped the redirect URI, once the resolution lapses", async () => {
    vi.useFakeTimers();

    try {
      const proxy = new OAuthProxy({ ...baseConfig, enableCimd: true });
      let currentRedirectUris = [REDIRECT_URI];
      mockFetchRouting(() =>
        clientMetadataResponse({ redirect_uris: currentRedirectUris }),
      );

      await expect(proxy.authorize(buildAuthParams())).resolves.toBeDefined();

      // The client rotates the URI away — a revocation the proxy must observe.
      currentRedirectUris = ["http://127.0.0.1:9999/"];

      vi.advanceTimersByTime(16 * 60 * 1000);
      await expect(proxy.authorize(buildAuthParams())).rejects.toMatchObject({
        code: "invalid_client",
      });

      proxy.destroy();
    } finally {
      vi.useRealTimers();
    }
  });

  it("refuses to issue a code to a CIMD client that sent no code_challenge", async () => {
    const proxy = new OAuthProxy({ ...baseConfig, enableCimd: true });
    mockFetchRouting(clientMetadataResponse);

    await expect(
      proxy.authorize(
        buildAuthParams({
          code_challenge: undefined,
          code_challenge_method: undefined,
        }),
      ),
    ).rejects.toMatchObject({ code: "invalid_request" });

    proxy.destroy();
  });

  it("refuses `plain` PKCE from a CIMD client even where allowPlainPkce permits it", async () => {
    // allowPlainPkce defaults to true, and this proxy leaves it there: the
    // stricter rule has to come from the client being CIMD, not from config.
    const proxy = new OAuthProxy({ ...baseConfig, enableCimd: true });
    mockFetchRouting(clientMetadataResponse);

    await expect(
      proxy.authorize(
        buildAuthParams({
          code_challenge: "a-verifier-doubling-as-its-own-challenge",
          code_challenge_method: "plain",
        }),
      ),
    ).rejects.toMatchObject({ code: "invalid_request" });

    proxy.destroy();
  });

  it("still lets a DCR client authorize without PKCE — the requirement is CIMD-only", async () => {
    const proxy = new OAuthProxy({ ...baseConfig, enableCimd: true });
    const registration = await proxy.registerClient({
      redirect_uris: [REDIRECT_URI],
    });

    await expect(
      proxy.authorize({
        client_id: registration.client_id,
        redirect_uri: REDIRECT_URI,
        response_type: "code",
        state: "test-state",
      } as AuthorizationParams),
    ).resolves.toBeDefined();

    proxy.destroy();
  });

  it("rejects a token exchange that presents the wrong verifier", async () => {
    const proxy = new OAuthProxy({ ...baseConfig, enableCimd: true });
    mockFetchRouting(clientMetadataResponse);

    const authResp = await proxy.authorize(buildAuthParams());
    const upstreamUrl = new URL(authResp.headers.get("Location")!);
    const transactionId = upstreamUrl.searchParams.get("state")!;

    const cbResp = await proxy.handleCallback(
      new Request(
        `${baseConfig.baseUrl}${baseConfig.redirectPath}?code=UP_CODE&state=${encodeURIComponent(transactionId)}`,
      ),
    );
    const code = new URL(cbResp.headers.get("Location")!).searchParams.get(
      "code",
    )!;

    await expect(
      proxy.exchangeAuthorizationCode({
        client_id: CLIENT_METADATA_URL,
        code,
        code_verifier: PKCEUtils.generatePair("S256").verifier,
        grant_type: "authorization_code",
        redirect_uri: REDIRECT_URI,
      }),
    ).rejects.toMatchObject({ code: "invalid_grant" });

    proxy.destroy();
  });

  it("rejects a CIMD document whose redirect_uris fall outside allowedRedirectUriPatterns", async () => {
    const proxy = new OAuthProxy({
      ...baseConfig,
      allowedRedirectUriPatterns: ["https://only-this-host.example.com/*"],
      enableCimd: true,
    });
    mockFetchRouting(clientMetadataResponse);

    await expect(proxy.authorize(buildAuthParams())).rejects.toMatchObject({
      code: "invalid_client",
    });

    proxy.destroy();
  });

  it("rejects a CIMD document that does not vouch for the requested redirect_uri", async () => {
    const proxy = new OAuthProxy({ ...baseConfig, enableCimd: true });
    mockFetchRouting(() =>
      clientMetadataResponse({ redirect_uris: ["http://127.0.0.1:9999/"] }),
    );

    await expect(proxy.authorize(buildAuthParams())).rejects.toMatchObject({
      code: "invalid_client",
    });

    proxy.destroy();
  });

  it("rejects a non-HTTPS client_id even when CIMD is enabled", async () => {
    const proxy = new OAuthProxy({ ...baseConfig, enableCimd: true });
    const fetchMock = mockFetchRouting(clientMetadataResponse);

    await expect(
      proxy.authorize(
        buildAuthParams({
          client_id: "http://client.example.com/client-metadata.json",
        }),
      ),
    ).rejects.toBeInstanceOf(OAuthProxyError);
    expect(fetchMock).not.toHaveBeenCalled();

    proxy.destroy();
  });

  it("exchangeAuthorizationCode() independently rejects an unresolved CIMD client_id when disabled", async () => {
    const proxy = new OAuthProxy(baseConfig);

    await expect(
      proxy.exchangeAuthorizationCode({
        client_id: CLIENT_METADATA_URL,
        code: "irrelevant",
        grant_type: "authorization_code",
        redirect_uri: REDIRECT_URI,
      }),
    ).rejects.toMatchObject({ code: "invalid_client" });

    proxy.destroy();
  });
});
