/**
 * Every MCP client reaches the upstream provider through the proxy's one
 * client, so the provider cannot tell them apart. The consent screen is what
 * stops a user's sign-in from authorizing a client they never approved, and it
 * only does that if the request is approved, and finished, in the browser the
 * screen was shown to.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { OAuthProxyConfig } from "./types.js";

import { OAuthProxy } from "./OAuthProxy.js";
import { MemoryTokenStorage } from "./utils/tokenStore.js";

const CALLBACK_URL = "https://client.example.com/callback";

const baseConfig = {
  allowedRedirectUriPatterns: ["https://client.example.com/*"],
  baseUrl: "https://proxy.example.com",
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamClientId: "upstream-client-id",
  upstreamClientSecret: "upstream-client-secret",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
};

const COOKIE_NAME = "__Host-fastmcp-consent";

describe("OAuthProxy consent is bound to the browser", () => {
  const proxies: OAuthProxy[] = [];
  let upstreamTokenEndpoint: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    upstreamTokenEndpoint = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () =>
        Response.json({
          access_token: "upstream-access-token",
          expires_in: 3600,
          token_type: "Bearer",
        }),
      );
  });

  afterEach(() => {
    for (const proxy of proxies.splice(0)) proxy.destroy();
    vi.restoreAllMocks();
  });

  const createProxy = (config: Partial<OAuthProxyConfig> = {}) => {
    const proxy = new OAuthProxy({
      ...baseConfig,
      ...config,
      tokenStorage: new MemoryTokenStorage(),
    });

    proxies.push(proxy);

    return proxy;
  };

  /**
   * Requests authorization and returns the consent screen, as a browser that
   * already holds `cookie` sees it.
   */
  const openConsentScreen = async (
    proxy: OAuthProxy,
    {
      cookie,
      ...registration
    }: { client_name?: string; cookie?: string; redirect_uris?: string[] } = {},
  ) => {
    const client = await proxy.registerClient({
      redirect_uris: [CALLBACK_URL],
      ...registration,
    });
    const response = await proxy.authorize(
      {
        client_id: client.client_id,
        redirect_uri: registration.redirect_uris?.[0] ?? CALLBACK_URL,
        response_type: "code",
        state: "client-state",
      },
      new Request(`${baseConfig.baseUrl}/oauth/authorize`, {
        headers: cookie ? { cookie } : {},
      }),
    );
    const [setCookie] = response.headers.getSetCookie();
    const html = await response.text();

    return {
      // What the browser sends back from then on.
      cookie: setCookie.split(";")[0],
      html,
      response,
      setCookie,
      transactionId: /name="transaction_id" value="([^"]+)"/.exec(html)![1],
    };
  };

  const answer = (
    proxy: OAuthProxy,
    action: "approve" | "deny",
    transactionId: string,
    cookie?: string,
  ) =>
    proxy.handleConsent(
      new Request(`${baseConfig.baseUrl}/oauth/consent`, {
        body: new URLSearchParams({ action, transaction_id: transactionId }),
        headers: cookie ? { cookie } : {},
        method: "POST",
      }),
    );

  /** The provider's redirect back to the proxy, arriving in some browser. */
  const finish = (proxy: OAuthProxy, state: string, cookie?: string) =>
    proxy.handleCallback(
      new Request(
        `${baseConfig.baseUrl}/oauth/callback?${new URLSearchParams({
          code: "upstream-code",
          state,
        })}`,
        { headers: cookie ? { cookie } : {} },
      ),
    );

  const upstreamState = (response: Response) =>
    new URL(response.headers.get("Location")!).searchParams.get("state")!;

  it("leaves a cookie in the browser the consent screen is shown to", async () => {
    const { setCookie } = await openConsentScreen(createProxy());

    expect(setCookie).toMatch(
      /^__Host-fastmcp-consent=[\w-]{43}; Path=\/; Max-Age=600; HttpOnly; SameSite=Lax; Secure$/,
    );
  });

  it.each(["https://proxy.example.com", "HTTPS://proxy.example.com"])(
    "protects the cookie over HTTPS (%s)",
    async (baseUrl) => {
      const { setCookie } = await openConsentScreen(createProxy({ baseUrl }));

      expect(setCookie).toMatch(/^__Host-fastmcp-consent=.*; Secure$/);
    },
  );

  it("leaves a cookie that a browser keeps over plain HTTP", async () => {
    const { setCookie } = await openConsentScreen(
      createProxy({ baseUrl: "http://localhost:8080" }),
    );

    // `Secure` and the `__Host-` prefix are refused outside HTTPS.
    expect(setCookie).toMatch(
      /^fastmcp-consent=[\w-]{43}; Path=\/; Max-Age=600; HttpOnly; SameSite=Lax$/,
    );
  });

  it("does not let the consent screen be framed or stored", async () => {
    const { response } = await openConsentScreen(createProxy());

    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
    expect(response.headers.get("Content-Security-Policy")).toBe(
      "frame-ancestors 'none'",
    );
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("names the client and where it sends the user", async () => {
    const { html } = await openConsentScreen(createProxy(), {
      client_name: '<script>alert("x")</script> Editor',
      redirect_uris: [`${CALLBACK_URL}?source=<b>app</b>`],
    });

    expect(html).toContain(
      "&lt;script&gt;alert(&quot;x&quot;)&lt;&#x2F;script&gt; Editor",
    );
    expect(html).toContain(
      "<strong>https:&#x2F;&#x2F;client.example.com&#x2F;callback</strong>",
    );
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<b>app</b>");
  });

  it.each([
    [
      "a host too long to show whole",
      `https://accounts.example.com.${"a".repeat(200)}.elsewhere.example/cb`,
      `https://…${"a".repeat(62)}.elsewhere.example/cb`,
    ],
    [
      "a tab in the host",
      "https://accounts.example.com\t.elsewhere.example/cb",
      "https://accounts.example.com.elsewhere.example/cb",
    ],
    [
      "a backslash before an @",
      "https://elsewhere.example\\@accounts.example.com/cb",
      "https://elsewhere.example/@accounts.example.com/cb",
    ],
    [
      "a look-alike letter",
      "https://\u0430ccounts.example.com/cb",
      "https://xn--ccounts-1fg.example.com/cb",
    ],
  ])(
    "shows where the user is really sent, given %s",
    async (_, redirectUri, shown) => {
      const { html } = await openConsentScreen(
        createProxy({ allowedRedirectUriPatterns: ["https://*"] }),
        { redirect_uris: [redirectUri] },
      );

      expect(html).toContain(
        `<strong>${shown.replaceAll("/", "&#x2F;")}</strong>`,
      );
    },
  );

  it("gives a client that registered no usable name a generic one", async () => {
    const { html } = await openConsentScreen(createProxy(), {
      // Registration stores what it is sent.
      client_name: 42 as unknown as string,
    });

    expect(html).toContain('<span class="app-name">MCP Client</span>');
  });

  it("keeps consent on when the option is passed on as undefined", async () => {
    const { response } = await openConsentScreen(
      createProxy({ consentRequired: undefined }),
    );

    expect(response.status).toBe(200);
  });

  it("finishes a request approved in the same browser", async () => {
    const proxy = createProxy();
    const { cookie, transactionId } = await openConsentScreen(proxy);

    const approved = await answer(proxy, "approve", transactionId, cookie);
    expect(approved.status).toBe(302);

    const finished = await finish(proxy, upstreamState(approved), cookie);
    const location = new URL(finished.headers.get("Location")!);

    expect(finished.status).toBe(302);
    expect(location.origin + location.pathname).toBe(CALLBACK_URL);
    expect(location.searchParams.get("code")).toBeTruthy();
    expect(location.searchParams.get("state")).toBe("client-state");
  });

  it("uses the cookie a browser already holds for its next request", async () => {
    const proxy = createProxy();
    const first = await openConsentScreen(proxy);
    const second = await openConsentScreen(proxy, { cookie: first.cookie });

    // One cookie, however many requests the browser has open.
    expect(second.cookie).toBe(first.cookie);

    for (const { transactionId } of [second, first]) {
      const approved = await answer(
        proxy,
        "approve",
        transactionId,
        first.cookie,
      );
      const finished = await finish(
        proxy,
        upstreamState(approved),
        first.cookie,
      );

      expect(finished.status).toBe(302);
    }
  });

  it("gives a browser whose cookie is not one of its own a new one", async () => {
    const proxy = createProxy();
    const { cookie } = await openConsentScreen(proxy, {
      cookie: `${COOKIE_NAME}=chosen-by-someone-else`,
    });

    expect(cookie).toMatch(/^__Host-fastmcp-consent=[\w-]{43}$/);
  });

  it.each(["approve", "deny"] as const)(
    "refuses to %s a request from another browser",
    async (action) => {
      const proxy = createProxy();
      const { cookie, transactionId } = await openConsentScreen(proxy);
      const other = await openConsentScreen(proxy);
      const value = cookie.split("=")[1];

      for (const presented of [
        undefined,
        `${COOKIE_NAME}=`,
        `${COOKIE_NAME}=not-the-value`,
        // The cookie of a browser that did open a consent screen.
        other.cookie,
        // Not this cookie's name. A browser does not hold these to the
        // rules of the `__Host-` prefix, so another host could set them.
        `x${COOKIE_NAME}=${value}`,
        `fastmcp-consent=${value}`,
        `\u00a0${COOKIE_NAME}=${value}`,
        `\u000b${COOKIE_NAME}=${value}`,
        // The first cookie of the name is the one that counts.
        `${other.cookie}; ${cookie}`,
      ]) {
        await expect(
          answer(proxy, action, transactionId, presented),
        ).rejects.toMatchObject({
          code: "invalid_request",
          description: "Consent must be given in the browser that requested it",
        });
      }

      // The request is untouched, and its own browser can still answer it,
      // whatever else it sends along.
      expect(
        (
          await answer(
            proxy,
            action,
            transactionId,
            `theme=dark;\t ${cookie} ; session=abc`,
          )
        ).status,
      ).toBe(302);
    },
  );

  it("does not finish a request in a browser other than the one that approved it", async () => {
    const proxy = createProxy();

    // Whoever starts a request can approve it themselves, and send a user
    // the provider's URL. The user signs in, and the provider sends their
    // browser, which holds another cookie or none, to the callback.
    const user = await openConsentScreen(proxy);

    for (const presented of [undefined, user.cookie]) {
      const { cookie, transactionId } = await openConsentScreen(proxy);
      const approved = await answer(proxy, "approve", transactionId, cookie);
      const state = upstreamState(approved);

      await expect(finish(proxy, state, presented)).rejects.toMatchObject({
        code: "access_denied",
        description:
          "This authorization request was not approved in this browser",
      });

      // The request is spent, so its own browser cannot finish it either.
      await expect(finish(proxy, state, cookie)).rejects.toMatchObject({
        code: "invalid_request",
        description: "Invalid or expired state",
      });
    }

    // The user's sign-in was never redeemed.
    expect(upstreamTokenEndpoint).not.toHaveBeenCalled();
  });

  it("does not finish a request nobody approved", async () => {
    const proxy = createProxy();
    const { cookie, transactionId } = await openConsentScreen(proxy);

    // The transaction ID doubles as the provider's `state`, so the provider
    // can be reached without going through the consent screen at all.
    await expect(finish(proxy, transactionId, cookie)).rejects.toMatchObject({
      code: "access_denied",
    });
    expect(upstreamTokenEndpoint).not.toHaveBeenCalled();
  });

  it("does not answer or finish a request that was shown to no browser", async () => {
    const proxy = createProxy();
    const client = await proxy.registerClient({
      redirect_uris: [CALLBACK_URL],
    });
    const { cookie } = await openConsentScreen(proxy);

    const createTransaction = () =>
      (
        proxy as unknown as {
          createTransaction: (params: object) => Promise<{ id: string }>;
        }
      ).createTransaction({
        client_id: client.client_id,
        redirect_uri: CALLBACK_URL,
        response_type: "code",
      });

    await expect(
      answer(proxy, "approve", (await createTransaction()).id, cookie),
    ).rejects.toMatchObject({ code: "invalid_request" });
    await expect(
      finish(proxy, (await createTransaction()).id, cookie),
    ).rejects.toMatchObject({ code: "access_denied" });
  });

  it("asks for no cookie when consent is not required", async () => {
    const proxy = createProxy({ consentRequired: false });
    const client = await proxy.registerClient({
      redirect_uris: [CALLBACK_URL],
    });
    const redirected = await proxy.authorize({
      client_id: client.client_id,
      redirect_uri: CALLBACK_URL,
      response_type: "code",
    });

    expect(redirected.status).toBe(302);
    expect(redirected.headers.getSetCookie()).toEqual([]);

    const finished = await finish(proxy, upstreamState(redirected));

    expect(finished.status).toBe(302);
    expect(finished.headers.getSetCookie()).toEqual([]);
  });
});
