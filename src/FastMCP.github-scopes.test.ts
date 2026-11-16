import type { IncomingMessage } from "node:http";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { OAuthProxy, PKCEUtils } from "./auth/index.js";
import {
  FastMCP,
  GitHubProvider,
  OAuthProvider,
  requireScopes,
} from "./FastMCP.js";

const baseUrl = "https://proxy.example.com";
const redirectUri = "https://client.example.com/callback";
const githubTokenEndpoint = "https://github.com/login/oauth/access_token";
const genericTokenEndpoint = "https://provider.example.com/token";
const providerConfig = {
  allowedRedirectUriPatterns: [redirectUri],
  baseUrl,
  clientId: "upstream-client",
  clientSecret: "upstream-secret",
  consentRequired: false,
};

const exchangeCode = async (proxy: OAuthProxy) => {
  const client = await proxy.registerClient({
    redirect_uris: [redirectUri],
    token_endpoint_auth_method: "none",
  });
  const pkce = PKCEUtils.generatePair("S256");
  const authorization = await proxy.authorize({
    client_id: client.client_id,
    code_challenge: pkce.challenge,
    code_challenge_method: "S256",
    redirect_uri: redirectUri,
    response_type: "code",
  });
  expect(authorization.status).toBe(302);
  const state = new URL(
    authorization.headers.get("Location")!,
  ).searchParams.get("state")!;
  const callbackUrl = new URL("/oauth/callback", baseUrl);
  callbackUrl.searchParams.set("code", "upstream-code");
  callbackUrl.searchParams.set("state", state);
  const callback = await proxy.handleCallback(new Request(callbackUrl));
  expect(callback.status).toBe(302);
  const code = new URL(callback.headers.get("Location")!).searchParams.get(
    "code",
  )!;
  const tokens = await proxy.exchangeAuthorizationCode({
    client_id: client.client_id,
    code,
    code_verifier: pkce.verifier,
    grant_type: "authorization_code",
    redirect_uri: redirectUri,
  });
  return { clientId: client.client_id, tokens };
};

describe.each(["application/json", "application/x-www-form-urlencoded"])(
  "GitHub granted scopes (%s)",
  (contentType) => {
    const tokenResponse = (scope: string) => {
      const body = {
        access_token: "upstream-access-token",
        refresh_token: "upstream-refresh-token",
        scope,
        token_type: "bearer",
      };
      return new Response(
        contentType === "application/json"
          ? JSON.stringify(body)
          : new URLSearchParams(body).toString(),
        { headers: { "Content-Type": contentType } },
      );
    };

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it.each([
      {
        expected: ["read:user", "user:email"],
        github: true,
        scope: "read:user,user:email",
        toolScope: "user:email",
      },
      {
        expected: ["read:user", "user:email"],
        github: true,
        scope: "read:user user:email",
        toolScope: "user:email",
      },
      {
        expected: ["read:user", "user:email"],
        github: true,
        scope: "read:user, user:email",
        toolScope: "user:email",
      },
      {
        expected: ["literal,scope"],
        github: false,
        scope: "literal,scope",
        toolScope: "literal,scope",
      },
    ])(
      "authenticates and runs scoped tools for $scope (GitHub=$github)",
      async ({ expected, github, scope, toolScope }) => {
        const provider = github
          ? new GitHubProvider(providerConfig)
          : new OAuthProvider({
              ...providerConfig,
              authorizationEndpoint: "https://provider.example.com/authorize",
              scopes: [scope],
              tokenEndpoint: genericTokenEndpoint,
            });
        vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
          expect(input).toBe(
            github ? githubTokenEndpoint : genericTokenEndpoint,
          );
          return tokenResponse(scope);
        });
        const proxy = provider.getProxy();
        const client = new Client({ name: "scope-client", version: "1.0.0" });

        try {
          const { tokens } = await exchangeCode(proxy);
          expect.soft(tokens.scope).toBe(expected.join(" "));
          const session = await provider.authenticate({
            headers: { authorization: `Bearer ${tokens.access_token}` },
          } as IncomingMessage);
          expect.soft(session?.scopes).toEqual(expected);

          const server = new FastMCP({
            auth: provider,
            name: "Scope test",
            version: "1.0.0",
          });
          server.addTool({
            execute: async (_args, { session }) =>
              JSON.stringify(session?.scopes),
            name: "scope_guarded",
            scopes: [toolScope],
          });
          server.addTool({
            canAccess: requireScopes(toolScope),
            execute: async () => "allowed",
            name: "require_scopes_guarded",
          });
          const [clientTransport, serverTransport] =
            InMemoryTransport.createLinkedPair();
          await Promise.all([
            server.connect(serverTransport, { ...session }),
            client.connect(clientTransport),
          ]);

          expect
            .soft(
              (await client.listTools()).tools.map((tool) => tool.name).sort(),
            )
            .toEqual(["require_scopes_guarded", "scope_guarded"]);
          expect(await client.callTool({ name: "scope_guarded" })).toEqual({
            content: [{ text: JSON.stringify(expected), type: "text" }],
          });
          expect(
            await client.callTool({ name: "require_scopes_guarded" }),
          ).toEqual({ content: [{ text: "allowed", type: "text" }] });
        } finally {
          await client.close();
          proxy.destroy();
        }
      },
    );

    it.each([
      { enableTokenSwap: false, github: true },
      { enableTokenSwap: true, github: true },
      { enableTokenSwap: false, github: false },
      { enableTokenSwap: true, github: false },
    ])(
      "preserves granted scopes on refresh (swap=$enableTokenSwap, GitHub=$github)",
      async ({ enableTokenSwap, github }) => {
        const expected = github ? "read:user user:email" : "literal,scope";
        const endpoint = github ? githubTokenEndpoint : genericTokenEndpoint;
        const upstream = vi
          .spyOn(globalThis, "fetch")
          .mockImplementation(async (input) => {
            expect(input).toBe(endpoint);
            return tokenResponse(expected);
          });
        const proxy = new OAuthProxy({
          ...providerConfig,
          enableTokenSwap,
          upstreamAuthorizationEndpoint:
            "https://provider.example.com/authorize",
          upstreamClientId: providerConfig.clientId,
          upstreamClientSecret: providerConfig.clientSecret,
          upstreamTokenEndpoint: endpoint,
        });

        try {
          const { clientId, tokens } = await exchangeCode(proxy);
          expect(tokens.scope).toBe(expected);
          upstream.mockImplementation(async (input) => {
            expect(input).toBe(endpoint);
            return tokenResponse(github ? "read:user,user:email" : expected);
          });

          const refreshed = await proxy.exchangeRefreshToken({
            client_id: clientId,
            grant_type: "refresh_token",
            refresh_token: tokens.refresh_token!,
          });
          expect(refreshed.scope).toBe(expected);
          if (enableTokenSwap) {
            expect(
              (await proxy.loadUpstreamTokens(refreshed.access_token))?.scope,
            ).toEqual(expected.split(" "));
          }
        } finally {
          proxy.destroy();
        }
      },
    );
  },
);
