/**
 * RED: matchesPattern() builds a RegExp from the configured pattern without
 * escaping regex metacharacters, so `.` matches any character and the pattern
 * is far wider than the glob the operator wrote.
 */
import { describe, expect, it } from "vitest";

import type { TokenStorage } from "./types.js";

import { OAuthProxy } from "./OAuthProxy.js";

class MemStore implements TokenStorage {
  private store = new Map<string, unknown>();
  async cleanup(): Promise<void> {}
  async delete(k: string): Promise<void> {
    this.store.delete(k);
  }
  async get(k: string): Promise<null | unknown> {
    return this.store.get(k) ?? null;
  }
  async save(k: string, v: unknown): Promise<void> {
    this.store.set(k, v);
  }
  async take(k: string): Promise<null | unknown> {
    const v = this.store.get(k) ?? null;
    this.store.delete(k);
    return v;
  }
}

const makeProxy = (patterns: string[]) =>
  new OAuthProxy({
    allowedRedirectUriPatterns: patterns,
    baseUrl: "http://localhost:4200",
    consentRequired: false,
    encryptionKey: false,
    redirectPath: "/oauth/callback",
    tokenStorage: new MemStore(),
    upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
    upstreamClientId: "id",
    upstreamClientSecret: "secret",
    upstreamTokenEndpoint: "https://provider.com/oauth/token",
  });

describe("allowedRedirectUriPatterns regex metacharacters", () => {
  it("does not let `.` in the pattern match an arbitrary character", async () => {
    // Operator intent: only the host client.example.com.
    const proxy = makeProxy(["https://client.example.com/*"]);

    // Attacker registers a host they control where each `.` is replaced by
    // another character. `.` is unescaped in the generated RegExp, so it
    // matches.
    await expect(
      proxy.registerClient({
        client_name: "evil",
        redirect_uris: ["https://clientXexampleYcom/steal"],
      }),
    ).rejects.toThrow();
  });

  it("does not treat a `+` in the pattern as a regex quantifier", async () => {
    const proxy = makeProxy(["https://a+.example.com/cb"]);

    await expect(
      proxy.registerClient({
        client_name: "evil",
        redirect_uris: ["https://aaaaZexampleZcom/cb"],
      }),
    ).rejects.toThrow();
  });
});
