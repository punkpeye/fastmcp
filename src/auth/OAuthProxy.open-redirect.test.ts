/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Regression tests for CWE-601 open-redirect / authorization-code theft in
 * OAuthProxy. See the SECURITY advisory for the full threat model.
 *
 * The pre-patch behaviour was:
 *   - `authorize()` stored `redirect_uri` verbatim, with no allow-list check.
 *   - `handleCallback()` then 302-redirected the fresh authorization code to
 *     that attacker-controlled URL.
 *   - `validateRedirectUri()` existed but was only called from DCR, and its
 *     default patterns (`["https://*", "http://localhost:*"]`) matched
 *     `https://evil.attacker.com/*` anyway.
 *   - `registeredClients` was written by DCR but never read.
 *
 * These tests verify that the patched behaviour closes all four gaps.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AuthorizationParams, UpstreamTokenSet } from "./types.js";

import { OAuthProxy, OAuthProxyError } from "./OAuthProxy.js";

const baseConfig = {
  allowedRedirectUriPatterns: ["https://client.example.com/*"],
  baseUrl: "http://localhost:4200",
  consentRequired: false,
  redirectPath: "/oauth/callback",
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamClientId: "legit-upstream-id",
  upstreamClientSecret: "legit-upstream-secret",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
};

const LEGIT_REDIRECT = "https://client.example.com/callback";
const EVIL_REDIRECT = "http://evil.attacker.com/steal";

function buildAuthParams(
  overrides: Partial<AuthorizationParams> = {},
): AuthorizationParams {
  return {
    client_id: baseConfig.upstreamClientId,
    redirect_uri: LEGIT_REDIRECT,
    response_type: "code",
    state: "victim-state",
    ...overrides,
  } as AuthorizationParams;
}

function mockUpstreamTokenEndpoint() {
  const upstream: UpstreamTokenSet = {
    accessToken: "UP_ACCESS_TOKEN",
    expiresIn: 3600,
    issuedAt: new Date(),
    refreshToken: "UP_REFRESH_TOKEN",
    scope: ["read"],
    tokenType: "Bearer",
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            access_token: upstream.accessToken,
            expires_in: upstream.expiresIn,
            refresh_token: upstream.refreshToken,
            scope: upstream.scope.join(" "),
            token_type: upstream.tokenType,
          }),
          {
            headers: { "Content-Type": "application/json" },
            status: 200,
          },
        ),
    ),
  );
}

describe("OAuthProxy CWE-601 open-redirect regression", () => {
  let proxy: OAuthProxy;

  beforeEach(() => {
    proxy = new OAuthProxy(baseConfig);
  });

  describe("authorize() rejects unregistered redirect_uri", () => {
    it("rejects an arbitrary attacker host even when client_id is valid", async () => {
      const dcr = await proxy.registerClient({ redirect_uris: [LEGIT_REDIRECT] });

      await expect(
        proxy.authorize(
          buildAuthParams({ client_id: dcr.client_id, redirect_uri: EVIL_REDIRECT }),
        ),
      ).rejects.toMatchObject({
        code: "invalid_request",
        description: expect.stringContaining("redirect_uri"),
      });
    });

    it("rejects redirect_uri before any client has been registered", async () => {
      // No DCR call at all — registeredClientsByClientId is empty, so we get
      // invalid_client (unknown client_id) rather than invalid_request.
      await expect(
        proxy.authorize(buildAuthParams({ redirect_uri: LEGIT_REDIRECT })),
      ).rejects.toMatchObject({ code: "invalid_client" });
    });

    it("rejects a URI that only differs by trailing slash (exact match required)", async () => {
      const dcr = await proxy.registerClient({ redirect_uris: [LEGIT_REDIRECT] });

      await expect(
        proxy.authorize(
          buildAuthParams({ client_id: dcr.client_id, redirect_uri: LEGIT_REDIRECT + "/" }),
        ),
      ).rejects.toMatchObject({ code: "invalid_request" });
    });

    it("rejects a URI whose host only differs in casing (strict string compare)", async () => {
      const dcr = await proxy.registerClient({ redirect_uris: [LEGIT_REDIRECT] });

      await expect(
        proxy.authorize(
          buildAuthParams({
            client_id: dcr.client_id,
            redirect_uri: "https://CLIENT.example.com/callback",
          }),
        ),
      ).rejects.toMatchObject({ code: "invalid_request" });
    });
  });

  describe("authorize() rejects unknown client_id", () => {
    it("rejects any client_id that was not issued by this proxy", async () => {
      await proxy.registerClient({ redirect_uris: [LEGIT_REDIRECT] });

      await expect(
        proxy.authorize(
          buildAuthParams({ client_id: "arbitrary-attacker-id" }),
        ),
      ).rejects.toMatchObject({
        code: "invalid_client",
      });
    });
  });

  describe("PoC reproducer — end-to-end, pre-patch behaviour must be blocked", () => {
    it("the original PoC link no longer leaks a code to evil.attacker.com", async () => {
      // Reproduces the published PoC verbatim: no DCR, arbitrary client_id,
      // attacker redirect_uri. The pre-patch flow would 302 a fresh code to
      // http://evil.attacker.com/steal?code=...; the patched flow must throw.
      mockUpstreamTokenEndpoint();

      await expect(
        proxy.authorize({
          client_id: "arbitrary-client-id",
          redirect_uri: EVIL_REDIRECT,
          response_type: "code",
          state: "victim-state",
        } as AuthorizationParams),
      ).rejects.toBeInstanceOf(OAuthProxyError);

      // And no transaction should have been persisted.
      const transactionsField = (proxy as any).transactions as Map<
        string,
        unknown
      >;
      expect(transactionsField.size).toBe(0);
    });

    it("an attacker cannot self-register a non-localhost URI with the default config", async () => {
      // When allowedRedirectUriPatterns is omitted (undefined), the proxy
      // defaults to localhost-only.  An attacker who controls evil.attacker.com
      // or a non-localhost https URI cannot self-register through DCR.
      const defaultProxy = new OAuthProxy({
        ...baseConfig,
        allowedRedirectUriPatterns: undefined,
      });

      await expect(
        defaultProxy.registerClient({ redirect_uris: [EVIL_REDIRECT] }),
      ).rejects.toMatchObject({ code: "invalid_redirect_uri" });

      // Non-localhost https URI is also rejected under the default.
      await expect(
        defaultProxy.registerClient({ redirect_uris: [LEGIT_REDIRECT] }),
      ).rejects.toMatchObject({ code: "invalid_redirect_uri" });

      // A localhost URI IS accepted (needed for MCP clients with dynamic ports).
      await expect(
        defaultProxy.registerClient({
          redirect_uris: ["http://localhost:54321/callback"],
        }),
      ).resolves.toBeDefined();

      defaultProxy.destroy();
    });
  });

  describe("handleCallback() defense-in-depth", () => {
    it("refuses to 302 if the stored clientCallbackUrl is no longer registered", async () => {
      const dcr = await proxy.registerClient({ redirect_uris: [LEGIT_REDIRECT] });
      mockUpstreamTokenEndpoint();

      // Start a legitimate transaction.
      const authResp = await proxy.authorize(
        buildAuthParams({ client_id: dcr.client_id }),
      );
      expect(authResp.status).toBe(302);
      const upstreamUrl = new URL(authResp.headers.get("Location")!);
      const transactionId = upstreamUrl.searchParams.get("state")!;

      // Simulate revocation / tampering: drop the URI from the registry and
      // hand-craft an attacker replacement inside the transaction record.
      const transactions = (proxy as any).transactions as Map<string, any>;
      const txn = transactions.get(transactionId);
      txn.clientCallbackUrl = EVIL_REDIRECT;
      transactions.set(transactionId, txn);

      const cbReq = new Request(
        `${baseConfig.baseUrl}${baseConfig.redirectPath}?code=UP_CODE&state=${encodeURIComponent(
          transactionId,
        )}`,
      );

      await expect(proxy.handleCallback(cbReq)).rejects.toMatchObject({
        code: "invalid_request",
      });

      // Transaction should be purged so an attacker can't replay it.
      expect(transactions.has(transactionId)).toBe(false);
    });
  });

  describe("handleConsent() deny branch defense-in-depth", () => {
    it("refuses to 302 to a tampered clientCallbackUrl on deny", async () => {
      const consentProxy = new OAuthProxy({
        ...baseConfig,
        consentRequired: true,
      });
      const dcr = await consentProxy.registerClient({ redirect_uris: [LEGIT_REDIRECT] });

      const authResp = await consentProxy.authorize(
        buildAuthParams({ client_id: dcr.client_id }),
      );
      // Consent HTML response is a 200, not a 302.
      expect(authResp.status).toBe(200);

      const transactions = (consentProxy as any).transactions as Map<
        string,
        any
      >;
      const [transactionId, txn] = [...transactions.entries()][0];
      txn.clientCallbackUrl = EVIL_REDIRECT;
      transactions.set(transactionId, txn);

      const formBody = new URLSearchParams({
        action: "deny",
        transaction_id: transactionId,
      }).toString();
      const denyReq = new Request("http://localhost:4200/oauth/consent", {
        body: formBody,
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        method: "POST",
      });

      await expect(consentProxy.handleConsent(denyReq)).rejects.toMatchObject({
        code: "invalid_request",
      });

      consentProxy.destroy();
    });
  });

  describe("exchangeAuthorizationCode() rejects unknown client_id", () => {
    it("rejects a token exchange with an unregistered client_id", async () => {
      await proxy.registerClient({ redirect_uris: [LEGIT_REDIRECT] });

      await expect(
        proxy.exchangeAuthorizationCode({
          client_id: "not-the-upstream-client-id",
          code: "irrelevant",
          grant_type: "authorization_code",
          redirect_uri: LEGIT_REDIRECT,
        }),
      ).rejects.toMatchObject({ code: "invalid_client" });
    });
  });

  describe("happy path still works for registered clients", () => {
    it("a properly-registered client completes the full authorize -> callback flow", async () => {
      const dcr = await proxy.registerClient({ redirect_uris: [LEGIT_REDIRECT] });
      mockUpstreamTokenEndpoint();

      const authResp = await proxy.authorize(
        buildAuthParams({ client_id: dcr.client_id }),
      );
      expect(authResp.status).toBe(302);
      const upstreamUrl = new URL(authResp.headers.get("Location")!);
      expect(upstreamUrl.origin + upstreamUrl.pathname).toBe(
        baseConfig.upstreamAuthorizationEndpoint,
      );
      const transactionId = upstreamUrl.searchParams.get("state")!;

      const cbReq = new Request(
        `${baseConfig.baseUrl}${baseConfig.redirectPath}?code=UP_CODE&state=${encodeURIComponent(
          transactionId,
        )}`,
      );
      const cbResp = await proxy.handleCallback(cbReq);

      expect(cbResp.status).toBe(302);
      const finalLocation = new URL(cbResp.headers.get("Location")!);
      expect(finalLocation.origin + finalLocation.pathname).toBe(
        LEGIT_REDIRECT,
      );
      expect(finalLocation.searchParams.get("code")).toBeTruthy();
      expect(finalLocation.searchParams.get("state")).toBe("victim-state");
    });

    it("DCR stores every URI in the array, not just the first", async () => {
      const multi = new OAuthProxy({
        ...baseConfig,
        allowedRedirectUriPatterns: ["https://client.example.com/*"],
      });
      const dcr = await multi.registerClient({
        redirect_uris: [
          "https://client.example.com/a",
          "https://client.example.com/b",
        ],
      });

      await expect(
        multi.authorize(
          buildAuthParams({
            client_id: dcr.client_id,
            redirect_uri: "https://client.example.com/b",
          }),
        ),
      ).resolves.toBeDefined();

      multi.destroy();
    });
  });

  describe("validateRedirectUri() has no permissive fallback", () => {
    it("rejects https://evil.attacker.com with empty patterns", async () => {
      const strict = new OAuthProxy({
        ...baseConfig,
        allowedRedirectUriPatterns: [],
      });
      await expect(
        strict.registerClient({
          redirect_uris: ["https://evil.attacker.com/steal"],
        }),
      ).rejects.toMatchObject({ code: "invalid_redirect_uri" });
      strict.destroy();
    });

    it("rejects http://localhost:9999 with empty patterns", async () => {
      const strict = new OAuthProxy({
        ...baseConfig,
        allowedRedirectUriPatterns: [],
      });
      await expect(
        strict.registerClient({
          redirect_uris: ["http://localhost:9999/cb"],
        }),
      ).rejects.toMatchObject({ code: "invalid_redirect_uri" });
      strict.destroy();
    });

    it("accepts URIs that explicitly match a configured pattern", async () => {
      const loose = new OAuthProxy({
        ...baseConfig,
        allowedRedirectUriPatterns: ["http://localhost:*/cb"],
      });
      await expect(
        loose.registerClient({
          redirect_uris: ["http://localhost:9999/cb"],
        }),
      ).resolves.toBeDefined();
      loose.destroy();
    });
  });
});
