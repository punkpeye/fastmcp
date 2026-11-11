import { createHash } from "node:crypto";
import http from "node:http";
import { type AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";

import { OAuthProvider } from "./auth/providers/OAuthProvider.js";
import { FastMCP } from "./FastMCP.js";
import { getTestPort } from "./getTestPort.js";

const CLIENT_REDIRECT = "http://localhost:6666/cb";

/**
 * A browser, as far as these flows need one: it follows nothing on its own,
 * but keeps the cookies it is given and sends them back.
 */
class Browser {
  get cookieNames(): string[] {
    return [...this.#cookies.keys()];
  }

  #cookies = new Map<string, string>();

  async fetch(url: string, init: RequestInit = {}): Promise<Response> {
    const response = await fetch(url, {
      ...init,
      headers: {
        ...(init.headers as Record<string, string>),
        ...(this.#cookies.size > 0 && {
          cookie: [...this.#cookies]
            .map(([name, value]) => `${name}=${value}`)
            .join("; "),
        }),
      },
      redirect: "manual",
    });

    for (const cookie of response.headers.getSetCookie()) {
      const [pair, ...attributes] = cookie.split("; ");
      const separator = pair.indexOf("=");
      const name = pair.slice(0, separator);

      if (attributes.includes("Max-Age=0")) {
        this.#cookies.delete(name);
      } else {
        this.#cookies.set(name, pair.slice(separator + 1));
      }
    }

    return response;
  }
}

describe("OAuth proxy consent over HTTP", () => {
  const cleanup: (() => Promise<void> | void)[] = [];

  afterEach(async () => {
    for (const stop of cleanup.splice(0).reverse()) await stop();
  });

  /**
   * An upstream provider whose user has already authorized the app: it sends
   * the browser straight back, and requires PKCE at its token endpoint.
   */
  const startUpstream = async () => {
    const challenges = new Map<string, null | string>();
    const exchanged: string[] = [];
    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url!, "http://upstream");
      let body = "";
      for await (const chunk of req) body += chunk;

      if (url.pathname === "/authorize") {
        const code = `upstream-code-${challenges.size}`;
        challenges.set(code, url.searchParams.get("code_challenge"));
        const back = new URL(url.searchParams.get("redirect_uri")!);
        back.searchParams.set("code", code);
        back.searchParams.set("state", url.searchParams.get("state")!);
        res.writeHead(302, { Location: back.toString() }).end();
        return;
      }

      if (url.pathname === "/token") {
        const params = new URLSearchParams(body);
        const code = params.get("code")!;
        const verified =
          createHash("sha256")
            .update(params.get("code_verifier") ?? "")
            .digest("base64url") === challenges.get(code);

        exchanged.push(code);
        res
          .writeHead(verified ? 200 : 400, {
            "content-type": "application/json",
          })
          .end(
            JSON.stringify(
              verified
                ? {
                    access_token: "upstream-access-token",
                    expires_in: 3600,
                    token_type: "Bearer",
                  }
                : { error: "invalid_grant" },
            ),
          );
        return;
      }

      res.writeHead(404).end();
    });

    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    cleanup.push(async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });

    return {
      exchanged,
      url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    };
  };

  const startServer = async (basePath?: `/${string}`) => {
    const upstream = await startUpstream();
    const port = await getTestPort();
    const base = `http://localhost:${port}${basePath ?? ""}`;
    const provider = new OAuthProvider({
      authorizationEndpoint: `${upstream.url}/authorize`,
      baseUrl: base,
      clientId: "upstream-client",
      clientSecret: "upstream-secret",
      consentRequired: true,
      tokenEndpoint: `${upstream.url}/token`,
    });
    const server = new FastMCP({
      auth: provider,
      name: "test",
      version: "1.0.0",
    });

    await server.start({
      httpStream: { ...(basePath && { basePath }), port },
      transportType: "httpStream",
    });
    cleanup.push(async () => {
      await server.stop();
      provider.getProxy().destroy();
    });

    const client = (await (
      await fetch(`${base}/oauth/register`, {
        body: JSON.stringify({
          client_name: "Example Editor",
          redirect_uris: [CLIENT_REDIRECT],
          token_endpoint_auth_method: "client_secret_post",
        }),
        headers: { "content-type": "application/json" },
        method: "POST",
      })
    ).json()) as { client_id: string; client_secret: string };

    /** Requests authorization in `browser` and returns its consent screen. */
    const openConsentScreen = async (browser: Browser) => {
      const response = await browser.fetch(
        `${base}/oauth/authorize?${new URLSearchParams({
          client_id: client.client_id,
          redirect_uri: CLIENT_REDIRECT,
          response_type: "code",
          state: "client-state",
        })}`,
      );
      const html = await response.text();

      return {
        html,
        response,
        transactionId: /name="transaction_id" value="([^"]+)"/.exec(html)![1],
      };
    };

    const approve = (browser: Browser, transactionId: string) =>
      browser.fetch(`${base}/oauth/consent`, {
        body: new URLSearchParams({
          action: "approve",
          transaction_id: transactionId,
        }),
        method: "POST",
      });

    /** Follows the provider's URL in `browser`, back to the proxy's callback. */
    const signIn = async (browser: Browser, upstreamUrl: string) => {
      const redirected = await browser.fetch(upstreamUrl);

      return browser.fetch(redirected.headers.get("location")!);
    };

    const redeem = (code: string) =>
      fetch(`${base}/oauth/token`, {
        body: new URLSearchParams({
          client_id: client.client_id,
          client_secret: client.client_secret,
          code,
          grant_type: "authorization_code",
          redirect_uri: CLIENT_REDIRECT,
        }),
        method: "POST",
      });

    return { approve, base, openConsentScreen, redeem, signIn, upstream };
  };

  it.each([undefined, "/issuer1"] as const)(
    "finishes a request in the browser that approved it (base path: %s)",
    async (basePath) => {
      const { approve, openConsentScreen, redeem, signIn } =
        await startServer(basePath);
      const browser = new Browser();

      const { html, response, transactionId } =
        await openConsentScreen(browser);

      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe(
        "text/html; charset=utf-8",
      );
      expect(response.headers.get("x-frame-options")).toBe("DENY");
      expect(response.headers.get("content-security-policy")).toBe(
        "frame-ancestors 'none'",
      );
      expect(html).toContain("Example Editor");
      expect(html).toContain("http:&#x2F;&#x2F;localhost:6666&#x2F;cb");
      expect(browser.cookieNames).toEqual(["fastmcp-consent"]);

      const approved = await approve(browser, transactionId);
      expect(approved.status).toBe(302);

      const finished = await signIn(browser, approved.headers.get("location")!);
      const location = new URL(finished.headers.get("location")!);

      expect(finished.status).toBe(302);
      expect(location.origin + location.pathname).toBe(CLIENT_REDIRECT);
      expect(location.searchParams.get("state")).toBe("client-state");

      expect((await redeem(location.searchParams.get("code")!)).status).toBe(
        200,
      );
    },
  );

  it("lets one browser have several requests open", async () => {
    const { approve, openConsentScreen, redeem, signIn } = await startServer();
    const browser = new Browser();

    const first = await openConsentScreen(browser);
    const second = await openConsentScreen(browser);

    // It holds one cookie, which both requests are bound to.
    expect(browser.cookieNames).toEqual(["fastmcp-consent"]);

    for (const { transactionId } of [first, second]) {
      const approved = await approve(browser, transactionId);
      const finished = await signIn(browser, approved.headers.get("location")!);
      const code = new URL(finished.headers.get("location")!).searchParams.get(
        "code",
      )!;

      expect((await redeem(code)).status).toBe(200);
    }
  });

  it("does not hand a client the sign-in of a user who never saw its consent screen", async () => {
    const { approve, openConsentScreen, signIn, upstream } =
      await startServer();

    // The client approves its own request, then sends a user the provider's
    // URL that the approval returned.
    const attacker = new Browser();
    const { transactionId } = await openConsentScreen(attacker);
    const approved = await approve(attacker, transactionId);
    const upstreamUrl = approved.headers.get("location")!;

    expect(approved.status).toBe(302);

    // The user's browser never saw the consent screen and holds no cookie.
    const refused = await signIn(new Browser(), upstreamUrl);

    expect(refused.status).toBe(400);
    expect(refused.headers.get("location")).toBeNull();
    expect(await refused.json()).toEqual({
      error: "access_denied",
      error_description:
        "This authorization request was not approved in this browser",
    });
    // The user's sign-in was never redeemed.
    expect(upstream.exchanged).toEqual([]);

    // The request is spent, so the client cannot finish it either.
    expect((await signIn(attacker, upstreamUrl)).status).toBe(400);
    expect(upstream.exchanged).toEqual([]);
  });

  it("does not finish a request that skipped the consent screen", async () => {
    const { base, openConsentScreen, signIn, upstream } = await startServer();
    const browser = new Browser();
    const { transactionId } = await openConsentScreen(browser);

    // The provider's `state` is the transaction ID the consent screen shows,
    // so the provider can be reached without approving anything.
    const refused = await signIn(
      browser,
      `${upstream.url}/authorize?${new URLSearchParams({
        client_id: "upstream-client",
        redirect_uri: `${base}/oauth/callback`,
        response_type: "code",
        state: transactionId,
      })}`,
    );

    expect(refused.status).toBe(400);
    expect(await refused.json()).toMatchObject({ error: "access_denied" });
    expect(upstream.exchanged).toEqual([]);
  });

  it("refuses an approval that does not come from the consent screen's browser", async () => {
    const { approve, openConsentScreen } = await startServer();
    const { transactionId } = await openConsentScreen(new Browser());

    // A page that knows the transaction ID submits the form from elsewhere.
    const refused = await approve(new Browser(), transactionId);

    expect(refused.status).toBe(400);
    expect(await refused.json()).toEqual({
      error: "invalid_request",
      error_description:
        "Consent must be given in the browser that requested it",
    });
  });
});
