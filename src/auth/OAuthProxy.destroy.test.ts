/**
 * `destroy()` is the only teardown the proxy exposes, so it has to release
 * everything the proxy allocated, including the fallback store's interval
 * when the store is wrapped for encryption.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FastMCP } from "../FastMCP.js";
import { OAuthProxy } from "./OAuthProxy.js";
import { MemoryTokenStorage } from "./utils/tokenStore.js";

const baseConfig = {
  baseUrl: "https://proxy.example.com",
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamClientId: "upstream-client-id",
  upstreamClientSecret: "upstream-client-secret",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
};

// Count scheduled intervals, including ones that no longer keep Node alive.
const activeTimers = vi.getTimerCount;

describe("OAuthProxy lifecycle", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["clearInterval", "Date", "setInterval"] });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("releases the timers of the token storage it created for itself", () => {
    const before = activeTimers();

    const proxy = new OAuthProxy(baseConfig);

    // Sanity check, so the assertion below cannot pass vacuously: two timers
    // start here, the proxy's own cleanup sweep and the fallback storage's.
    expect(activeTimers()).toBe(before + 2);

    proxy.destroy();

    // Nothing between the reads awaits, so no other task can add or remove a
    // timer in between. Before the fix the storage timer survived and this
    // came back one over the baseline.
    expect(activeTimers()).toBe(before);
  });

  it("leaves a caller-supplied storage running", async () => {
    const before = activeTimers();

    const tokenStorage = new MemoryTokenStorage();
    const withCallerStorage = activeTimers();

    const proxy = new OAuthProxy({ ...baseConfig, tokenStorage });
    proxy.destroy();

    // The proxy tears down what it created, not what it was handed: the caller
    // may share one storage between proxies, or keep using it afterwards.
    expect(activeTimers()).toBe(withCallerStorage);

    await tokenStorage.save("still-usable", "value");
    expect(await tokenStorage.get("still-usable")).toBe("value");

    tokenStorage.destroy();
    expect(activeTimers()).toBe(before);
  });

  it("can be called twice", () => {
    const before = activeTimers();

    const proxy = new OAuthProxy(baseConfig);
    proxy.destroy();
    proxy.destroy();

    expect(activeTimers()).toBe(before);
  });

  it("keeps cleanup running after a server restart", async () => {
    const tokenStorage = new MemoryTokenStorage();
    const cleanup = vi.spyOn(tokenStorage, "cleanup");
    const proxy = new OAuthProxy({ ...baseConfig, tokenStorage });
    const server = new FastMCP({
      name: "oauth-test",
      oauth: { enabled: true, proxy },
      version: "1.0.0",
    });
    const options = {
      httpStream: { host: "127.0.0.1", port: 0 },
      transportType: "httpStream",
    } as const;

    try {
      await server.start(options);
      await server.stop();
      expect.soft(proxy["cleanupInterval"]?.hasRef()).toBe(false);
      expect.soft(tokenStorage["cleanupInterval"]?.hasRef()).toBe(false);

      await server.start(options);
      await tokenStorage.save("expired", "value", 1);
      await vi.advanceTimersByTimeAsync(60_000);
      expect(cleanup).toHaveBeenCalledTimes(2);
      expect(tokenStorage.size()).toBe(0);
    } finally {
      await server.stop();
      proxy.destroy();
      tokenStorage.destroy();
    }
  });
});
