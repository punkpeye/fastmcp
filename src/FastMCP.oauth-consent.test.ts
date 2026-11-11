import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { OAuthProxy } from "./auth/OAuthProxy.js";
import { FastMCP } from "./FastMCP.js";
import { getTestPort } from "./getTestPort.js";

const CALLBACK_URL = "https://client.example.com/callback";
const UPSTREAM_AUTHORIZATION_URL =
  "https://provider.example.com/oauth/authorize";

describe("OAuth consent framing headers", () => {
  let authProxy: OAuthProxy;
  let server: FastMCP;
  let baseUrl: string;

  beforeEach(async () => {
    const port = await getTestPort();
    baseUrl = `http://localhost:${port}`;
    authProxy = new OAuthProxy({
      allowedRedirectUriPatterns: ["https://client.example.com/*"],
      baseUrl,
      consentRequired: true,
      upstreamAuthorizationEndpoint: UPSTREAM_AUTHORIZATION_URL,
      upstreamClientId: "upstream-client-id",
      upstreamClientSecret: "upstream-client-secret",
      upstreamTokenEndpoint: "https://provider.example.com/oauth/token",
    });
    server = new FastMCP({
      name: "Consent Test Server",
      oauth: {
        authorizationServer: authProxy.getAuthorizationServerMetadata(),
        enabled: true,
        proxy: authProxy,
      },
      version: "1.0.0",
    });
    await server.start({
      httpStream: { port },
      transportType: "httpStream",
    });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await server.stop();
    authProxy.destroy();
  });

  const registerClient = async () => {
    const response = await fetch(`${baseUrl}/oauth/register`, {
      body: JSON.stringify({ redirect_uris: [CALLBACK_URL] }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
    });
    expect(response.status).toBe(201);

    return (await response.json()) as { client_id: string };
  };

  const expectFramingHeaders = (response: Response) => {
    expect.soft(response.headers.get("X-Frame-Options")).toBe("DENY");
    expect
      .soft(response.headers.get("Content-Security-Policy"))
      .toBe("frame-ancestors 'none'");
  };

  it("sends the framing headers with the consent page", async () => {
    const client = await registerClient();
    const page = await fetch(
      `${baseUrl}/oauth/authorize?${new URLSearchParams({
        client_id: client.client_id,
        redirect_uri: CALLBACK_URL,
        response_type: "code",
        state: "client-state",
      })}`,
      { redirect: "manual" },
    );

    expect(page.status).toBe(200);
    expect(page.headers.get("Content-Type")).toContain("text/html");
    expectFramingHeaders(page);
    expect(await page.text()).toContain('name="action" value="approve"');
  });

  it("preserves the framing headers when a consent POST returns HTML", async () => {
    const client = await registerClient();
    const consent = await authProxy.authorize({
      client_id: client.client_id,
      redirect_uri: CALLBACK_URL,
      response_type: "code",
    });
    const html = await consent.clone().text();
    const transactionId = /name="transaction_id" value="([^"]+)"/.exec(
      html,
    )![1];

    // The built-in POST handler redirects. Exercise its HTML response path
    // using a real consent response from the proxy.
    vi.spyOn(authProxy, "handleConsent").mockResolvedValueOnce(consent);
    const response = await fetch(`${baseUrl}/oauth/consent`, {
      body: new URLSearchParams({
        action: "approve",
        transaction_id: transactionId,
      }),
      method: "POST",
      redirect: "manual",
    });

    expect(response.status).toBe(200);
    expectFramingHeaders(response);
    expect
      .soft(response.headers.get("Content-Type"))
      .toBe("text/html; charset=utf-8");
    expect(await response.text()).toBe(html);
  });
});
