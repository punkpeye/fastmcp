/**
 * `destroy()` is the only teardown the proxy exposes, so it has to release
 * everything the proxy allocated. A `setInterval` that is never cleared keeps
 * the Node event loop alive: a process that has stopped serving never exits on
 * its own. The proxy cleared its own sweep timer, but not the one belonging to
 * the `MemoryTokenStorage` it creates when the caller supplies no storage —
 * which, once wrapped in `EncryptedTokenStorage` (no `destroy()`), was no
 * longer reachable from anywhere.
 */

import { describe, expect, it } from "vitest";

import { OAuthProxy } from "./OAuthProxy.js";
import { MemoryTokenStorage } from "./utils/tokenStore.js";

const baseConfig = {
  baseUrl: "https://proxy.example.com",
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamClientId: "upstream-client-id",
  upstreamClientSecret: "upstream-client-secret",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
};

/** How many timers are currently keeping the event loop alive. */
const activeTimers = () =>
  process.getActiveResourcesInfo().filter((type) => type === "Timeout").length;

describe("OAuthProxy destroy", () => {
  it("releases the timers of the token storage it created for itself", () => {
    const before = activeTimers();

    const proxy = new OAuthProxy(baseConfig);

    // Sanity check, so the assertion below cannot pass vacuously: two timers
    // start here, the proxy's own cleanup sweep and the fallback storage's.
    expect(activeTimers()).toBeGreaterThan(before);

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
});
