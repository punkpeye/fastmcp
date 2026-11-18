/**
 * A redirect URI pattern is a glob over the URI as written, and `*` matches
 * `/`. A pattern with a wildcard in its host, such as the documented
 * `https://*.example.com/*`, could therefore be satisfied by a URI on any
 * host that carried the rest of the pattern in its path. The host a URI
 * really leads to has to match the pattern's host too.
 */

import { afterEach, describe, expect, it } from "vitest";

import { OAuthProxy } from "./OAuthProxy.js";
import { MemoryTokenStorage } from "./utils/tokenStore.js";

describe("allowedRedirectUriPatterns match the host a URI leads to", () => {
  const proxies: OAuthProxy[] = [];

  afterEach(() => {
    for (const proxy of proxies.splice(0)) proxy.destroy();
  });

  /** Whether a proxy allowing `pattern` lets a client register `uri`. */
  const accepts = async (pattern: string | undefined, uri: string) => {
    const proxy = new OAuthProxy({
      allowedRedirectUriPatterns: pattern === undefined ? undefined : [pattern],
      baseUrl: "https://proxy.example.com",
      upstreamAuthorizationEndpoint: "https://provider.example/authorize",
      upstreamClientId: "upstream-client",
      upstreamClientSecret: "upstream-secret",
      upstreamTokenEndpoint: "https://provider.example/token",
    });

    proxies.push(proxy);

    return proxy.registerClient({ redirect_uris: [uri] }).then(
      () => true,
      (error: unknown) => {
        expect(error).toMatchObject({ code: "invalid_redirect_uri" });
        return false;
      },
    );
  };

  it.each([
    ["https://app.example.com#*", "https://app.example.com#"],
    // The rest of the pattern, carried where the host is not.
    ["https://*.example.com/*", "https://elsewhere.test/a.example.com/cb"],
    ["https://*.example.com/*", "https://elsewhere.test/?x=.example.com/cb"],
    ["https://*.example.com/*", "https://elsewhere.test#.example.com/cb"],
    ["https://*.example.com/*", "https://elsewhere.test\\.example.com/cb"],
    ["https://*.example.com/*", "https://elsewhere.test/x/.example.com/"],
    ["https://app-*.example.com/cb", "https://app-x.test/.example.com/cb"],
    ["https://*.example.com", "https://elsewhere.test/.example.com"],
    ["*://app.example.com/*", "https://elsewhere.test/x://app.example.com/y"],
    ["https://app?.example.com/*", "https://app/.example.com/cb"],
    ["https://*.example.com?x=*", "https://elsewhere.test/a.example.com?x=1"],
    [
      "https://*.example.com/*",
      "https://a.example.com.elsewhere.test/.example.com/cb",
    ],
    [
      "*://app.example.com/*",
      "https://evilapp.example.com/x://app.example.com/y",
    ],
    // A `?` or a `*` that ends the host does not run on into a longer one.
    ["https://app.example.com?*", "https://app.example.com.elsewhere.test/cb"],
    [
      "https://app.example.com?source=*",
      "https://app.example.com.source=.elsewhere.test/cb",
    ],
    ["https://app.example.com*", "https://app.example.com.elsewhere.test/cb"],
    ["https://app.example.com**", "https://app.example.com.elsewhere.test/cb"],
    ["https://*.example.com*", "https://a.example.com.elsewhere.test/cb"],
    ["cursor://*.cursor-mcp/*", "cursor://elsewhere/x.cursor-mcp/cb"],
    // Not the pattern's host at all.
    ["https://*.example.com/*", "https://example.com.elsewhere.test/cb"],
    ["https://*.example.com/*", "https://elsewhere.test/cb"],
  ])("%s refuses %s", async (pattern, uri) => {
    expect(await accepts(pattern, uri)).toBe(false);
  });

  it.each([
    ["https://*.example.com/*", "https://app.example.com/cb"],
    ["https://*.example.com/*", "https://a.b.example.com/cb?x=1%23y"],
    ["https://*.EXAMPLE.com/*", "https://app.EXAMPLE.com/cb"],
    ["https://app-*.example.com/cb", "https://app-1.example.com/cb"],
    ["https://*", "https://anything.test/any/path?x=1"],
    ["https://*/callback", "https://anything.test/callback"],
    ["http://localhost:*", "http://localhost:3000"],
    ["http://localhost:*", "http://localhost:3000/oauth/callback?x=1"],
    ["http://localhost:*", "http://localhost:80/cb"],
    ["http://127.0.0.1:*", "http://127.0.0.1:54321/callback"],
    ["http://[::1]:*", "http://[::1]:54321/callback"],
    // A wildcard for the port has always reached into the path.
    ["http://localhost:*/cb", "http://localhost:9999/cb"],
    ["http://localhost:*/cb", "http://localhost:9999/oauth/cb"],
    ["https://app.example.com/callback", "https://app.example.com/callback"],
    ["https://app.example.com/*", "https://app.example.com/a/b/c"],
    ["https://app.example.com:443/*", "https://app.example.com:443/cb"],
    ["https://app.example.com:8443/*", "https://app.example.com:8443/cb"],
    ["https://app.example.com?source=*", "https://app.example.com?source=x"],
    ["https://app.example.com*", "https://app.example.com/cb"],
    // A `?` in the host may stand for a character...
    ["https://app?.example.com/*", "https://app1.example.com/cb"],
    ["https://*.dev?.example.com/*", "https://x.dev1.example.com/cb"],
    ["http://localhost:30??/cb", "http://localhost:3042/cb"],
    // ...or start the query, as in a URL.
    ["https://*.example.com?x=*", "https://app.example.com?x=1"],
    ["https://app?.example.com?x=*", "https://app1.example.com?x=1"],
    ["https://app.example.com*", "https://app.example.com:8443/cb"],
    ["https://*", "https://a.b.elsewhere.test:8443/cb"],
    // The host as its author would write it.
    ["https://bücher.example/*", "https://bücher.example/cb"],
    ["https://*.bücher.example/*", "https://a.bücher.example/cb"],
    ["myapp://bücher/*", "myapp://bücher/cb"],
    ["http://127.1:*", "http://127.1:3000/cb"],
    ["http://[0:0:0:0:0:0:0:1]:*", "http://[0:0:0:0:0:0:0:1]:3000/cb"],
    ["https://exa%6dple.com/*", "https://exa%6dple.com/cb"],
    // A `://` that is not after a scheme names no host.
    [
      "myapp:/cb?return=https://app.example.com/*",
      "myapp:/cb?return=https://app.example.com/x",
    ],
    ["myapp:cb?next=http://localhost:*", "myapp:cb?next=http://localhost:3000"],
    ["*://app.example.com/*", "https://app.example.com/cb"],
    ["cursor://anysphere.cursor-mcp/*", "cursor://anysphere.cursor-mcp/cb"],
    ["cursor://*", "cursor://anysphere.cursor-mcp/oauth/callback"],
    ["com.example.app:/oauth*", "com.example.app:/oauth2redirect"],
    [undefined, "http://localhost:54321/callback"],
    [undefined, "http://127.0.0.1:54321/callback"],
  ])("%s accepts %s", async (pattern, uri) => {
    expect(await accepts(pattern, uri)).toBe(true);
  });

  it.each([
    ["https://app.example.com/callback", "https://app.example.com/callback/x"],
    ["https://app.example.com/*", "https://app.example.com:8443/cb"],
    ["http://localhost:*", "http://localhost/cb"],
    // The URI as written is matched as it always was, letter for letter.
    ["https://*.example.com/*", "https://APP.Example.com/cb"],
    ["https://app.example.com?source=*", "https://app.example.com/?source=x"],
    ["http://localhost:*", "http://localhost.elsewhere.test:80/cb"],
    ["http://localhost:*", "http://localhost:80@elsewhere.test/cb"],
    [undefined, "https://app.example.com/cb"],
  ])("%s still refuses %s", async (pattern, uri) => {
    expect(await accepts(pattern, uri)).toBe(false);
  });

  // RFC 6749 §3.1.2: a redirect URI MUST NOT include a fragment, whatever the
  // pattern or the scheme. An encoded `%23` is part of the URI, not a fragment.
  it.each([
    [undefined, "http://localhost:54321/callback#frag"],
    ["*", "https://app.example.com/cb#frag"],
    ["https://*", "https://app.example.com/cb?x=1#frag"],
    ["https://app.example.com/*", "https://app.example.com/cb#"],
    ["myapp://*", "myapp://callback#frag"],
    ["cursor://*", "cursor://anysphere.cursor-mcp/oauth/callback#"],
    ["com.example.app:/oauth*", "com.example.app:/oauth2redirect#x"],
  ])("%s refuses the fragment in %s", async (pattern, uri) => {
    expect(await accepts(pattern, uri)).toBe(false);
  });

  it.each([
    ["myapp://*", "myapp://callback%23frag"],
    ["com.example.app:/oauth*", "com.example.app:/oauth2redirect?x=%23"],
  ])("%s accepts the encoded # in %s", async (pattern, uri) => {
    expect(await accepts(pattern, uri)).toBe(true);
  });

  it("refuses authorization for a registration its patterns no longer allow", async () => {
    // Registrations are kept, here in storage two deployments share: one made
    // when the allow-list let more through, and one it still allows.
    const tokenStorage = new MemoryTokenStorage();
    const config = {
      baseUrl: "https://proxy.example.com",
      encryptionKey: false as const,
      tokenStorage,
      upstreamAuthorizationEndpoint: "https://provider.example/authorize",
      upstreamClientId: "upstream-client",
      upstreamClientSecret: "upstream-secret",
      upstreamTokenEndpoint: "https://provider.example/token",
    };
    const before = new OAuthProxy({
      ...config,
      allowedRedirectUriPatterns: ["https://*"],
    });
    const after = new OAuthProxy({
      ...config,
      allowedRedirectUriPatterns: ["https://client.example.com/*"],
    });

    proxies.push(before, after);

    const authorize = async (redirectUri: string) => {
      const { client_id } = await before.registerClient({
        redirect_uris: [redirectUri],
      });

      return after.authorize({
        client_id,
        redirect_uri: redirectUri,
        response_type: "code",
      });
    };

    await expect(authorize("https://elsewhere.test/cb")).rejects.toMatchObject({
      code: "invalid_request",
      description: "redirect_uri is no longer allowed",
    });
    expect((await authorize("https://client.example.com/cb")).status).toBe(200);

    tokenStorage.destroy();
  });

  it("refuses authorization for a stored redirect URI with a fragment", async () => {
    const proxy = new OAuthProxy({
      allowedRedirectUriPatterns: ["https://client.example.com/*"],
      baseUrl: "https://proxy.example.com",
      encryptionKey: false,
      upstreamAuthorizationEndpoint: "https://provider.example/authorize",
      upstreamClientId: "upstream-client",
      upstreamClientSecret: "upstream-secret",
      upstreamTokenEndpoint: "https://provider.example/token",
    });

    proxies.push(proxy);

    // Registered before fragments were refused: registerClient() no longer
    // takes it, so it is written to storage as that registration was.
    const redirectUris = [
      "https://client.example.com/cb#frag",
      "https://client.example.com/cb",
    ];

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await (proxy as any).stateStore.saveRegisteredClient({
      callbackUrl: redirectUris[0],
      clientId: "stored-client",
      clientSecret: "stored-secret",
      metadata: {},
      redirectUris,
      registeredAt: new Date(),
      tokenEndpointAuthMethod: "client_secret_basic",
    });

    const authorize = (redirectUri: string) =>
      proxy.authorize({
        client_id: "stored-client",
        redirect_uri: redirectUri,
        response_type: "code",
      });

    await expect(authorize(redirectUris[0])).rejects.toMatchObject({
      code: "invalid_request",
      description: "redirect_uri is no longer allowed",
    });
    expect((await authorize(redirectUris[1])).status).toBe(200);
  });
});
