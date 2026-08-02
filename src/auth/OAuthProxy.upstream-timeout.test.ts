/**
 * Regression tests for CWE-400 uncontrolled resource consumption in
 * OAuthProxy: the upstream token/refresh fetch calls were bare `fetch(...)`
 * with no timeout, so a hung or trickling identity provider stalled the
 * corresponding authorize/token/refresh request indefinitely.
 *
 * These tests verify that every upstream call now carries an AbortSignal
 * bounded by `upstreamRequestTimeoutMs` and that a timeout surfaces as a
 * clean `OAuthProxyError("server_error", "Upstream request timed out")`
 * instead of a raw `TimeoutError`/`AbortError`.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, expect, it, vi } from "vitest";

import { OAuthProxy } from "./OAuthProxy.js";

/**
 * Simulates an upstream that never answers: the returned promise only
 * rejects when the caller's AbortSignal fires, mirroring how an in-flight
 * fetch is rejected on abort.
 */
const mockHungUpstream = () =>
  vi.spyOn(global, "fetch").mockImplementation(
    (_input, init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new DOMException("The operation timed out.", "TimeoutError"));
        });
      }),
  );

describe("OAuthProxy - Upstream Request Timeout", () => {
  const baseConfig = {
    baseUrl: "https://proxy.example.com",
    consentRequired: false,
    upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
    upstreamClientId: "upstream-client-id",
    upstreamClientSecret: "upstream-client-secret",
    upstreamRequestTimeoutMs: 50,
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

  it("bounds the authorization-code exchange and maps the timeout to server_error", async () => {
    const proxy = new OAuthProxy(baseConfig);
    const fetchSpy = mockHungUpstream();

    await expect(
      (proxy as any).exchangeUpstreamCode("auth-code", transaction),
    ).rejects.toMatchObject({
      code: "server_error",
      description: "Upstream request timed out",
      name: "OAuthProxyError",
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);

    proxy.destroy();
    fetchSpy.mockRestore();
  });

  it("bounds the passthrough refresh exchange and maps the timeout to server_error", async () => {
    const proxy = new OAuthProxy({ ...baseConfig, enableTokenSwap: false });
    const fetchSpy = mockHungUpstream();

    await expect(
      (proxy as any).handlePassthroughRefresh({
        client_id: "client-id",
        grant_type: "refresh_token",
        refresh_token: "upstream-refresh-token",
      }),
    ).rejects.toMatchObject({
      code: "server_error",
      description: "Upstream request timed out",
      name: "OAuthProxyError",
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);

    proxy.destroy();
    fetchSpy.mockRestore();
  });

  it("bounds the swap-mode upstream refresh and maps the timeout to server_error", async () => {
    const proxy = new OAuthProxy(baseConfig);
    const fetchSpy = mockHungUpstream();

    await expect(
      (proxy as any).refreshUpstreamTokens("upstream-refresh-token"),
    ).rejects.toMatchObject({
      code: "server_error",
      description: "Upstream request timed out",
      name: "OAuthProxyError",
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);

    proxy.destroy();
    fetchSpy.mockRestore();
  });

  it("passes an AbortSignal to every upstream fetch", async () => {
    const proxy = new OAuthProxy(baseConfig);
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({ access_token: "t", token_type: "Bearer" }),
        {
          headers: { "Content-Type": "application/json" },
          status: 200,
        },
      ),
    );

    await (proxy as any).refreshUpstreamTokens("upstream-refresh-token");

    const init = fetchSpy.mock.calls[0]?.[1];

    expect(init?.signal).toBeInstanceOf(AbortSignal);

    proxy.destroy();
    fetchSpy.mockRestore();
  });

  it("does not remap non-timeout fetch failures", async () => {
    const proxy = new OAuthProxy(baseConfig);
    const fetchSpy = vi
      .spyOn(global, "fetch")
      .mockRejectedValue(new TypeError("fetch failed"));

    await expect(
      (proxy as any).refreshUpstreamTokens("upstream-refresh-token"),
    ).rejects.toThrow(TypeError);

    proxy.destroy();
    fetchSpy.mockRestore();
  });
});
