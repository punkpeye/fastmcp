import type { IncomingMessage } from "node:http";

import { describe, expect, it } from "vitest";

import { AzureProvider } from "./AzureProvider.js";
import { GitHubProvider } from "./GitHubProvider.js";
import { GoogleProvider } from "./GoogleProvider.js";
import { OAuthProvider } from "./OAuthProvider.js";

describe("OAuthProvider", () => {
  const baseConfig = {
    authorizationEndpoint: "https://auth.example.com/authorize",
    baseUrl: "http://localhost:8000",
    clientId: "test-client-id",
    clientSecret: "test-client-secret",
    tokenEndpoint: "https://auth.example.com/token",
  };

  it("should create a provider with getProxy returning an OAuthProxy", () => {
    const provider = new OAuthProvider(baseConfig);
    const proxy = provider.getProxy();

    expect(proxy).toBeDefined();
    expect(typeof proxy.loadUpstreamTokens).toBe("function");
    expect(typeof proxy.getAuthorizationServerMetadata).toBe("function");
  });

  it("should provide oauth config via getOAuthConfig", () => {
    const provider = new OAuthProvider({
      ...baseConfig,
      scopes: ["openid", "profile"],
    });
    const config = provider.getOAuthConfig();

    expect(config.enabled).toBe(true);
    expect(config.proxy).toBeDefined();
    expect(config.authorizationServer).toBeDefined();
    expect(config.authorizationServer.issuer).toBe("http://localhost:8000");
    expect(config.protectedResource).toEqual({
      authorizationServers: ["http://localhost:8000"],
      resource: "http://localhost:8000",
      scopesSupported: ["openid", "profile"],
    });
  });

  it("should default to openid scope in protected resource", () => {
    const provider = new OAuthProvider(baseConfig);
    const config = provider.getOAuthConfig();

    expect(config.protectedResource.scopesSupported).toEqual(["openid"]);
  });

  describe("authenticate", () => {
    it("should return undefined for undefined request (stdio)", async () => {
      const provider = new OAuthProvider(baseConfig);
      const result = await provider.authenticate(undefined);

      expect(result).toBeUndefined();
    });

    it("should return undefined for request without Authorization header", async () => {
      const provider = new OAuthProvider(baseConfig);
      const request = { headers: {} } as IncomingMessage;
      const result = await provider.authenticate(request);

      expect(result).toBeUndefined();
    });

    it("should return undefined for non-Bearer authorization", async () => {
      const provider = new OAuthProvider(baseConfig);
      const request = {
        headers: { authorization: "Basic dXNlcjpwYXNz" },
      } as IncomingMessage;
      const result = await provider.authenticate(request);

      expect(result).toBeUndefined();
    });

    it("should return undefined for invalid Bearer token", async () => {
      const provider = new OAuthProvider(baseConfig);
      const request = {
        headers: { authorization: "Bearer invalid-token" },
      } as IncomingMessage;
      const result = await provider.authenticate(request);

      // Without valid upstream tokens, should return undefined
      expect(result).toBeUndefined();
    });
  });
});

describe("GitHubProvider", () => {
  const baseConfig = {
    baseUrl: "http://localhost:8000",
    clientId: "github-client-id",
    clientSecret: "github-client-secret",
  };

  it("should create a provider with GitHub endpoints configured", () => {
    const provider = new GitHubProvider(baseConfig);
    const config = provider.getOAuthConfig();

    expect(config.authorizationServer.authorizationEndpoint).toContain(
      "/oauth/authorize",
    );
    expect(config.authorizationServer.tokenEndpoint).toContain("/oauth/token");
  });

  it("should use GitHub default scopes in protected resource", () => {
    const provider = new GitHubProvider(baseConfig);
    const config = provider.getOAuthConfig();

    expect(config.protectedResource.scopesSupported).toEqual([
      "read:user",
      "user:email",
    ]);
  });

  it("should allow custom scopes", () => {
    const provider = new GitHubProvider({
      ...baseConfig,
      scopes: ["repo", "gist"],
    });
    const config = provider.getOAuthConfig();

    expect(config.protectedResource.scopesSupported).toEqual(["repo", "gist"]);
  });

  it("should expose getProxy method", () => {
    const provider = new GitHubProvider(baseConfig);
    expect(provider.getProxy()).toBeDefined();
  });
});

describe("GoogleProvider", () => {
  const baseConfig = {
    baseUrl: "http://localhost:8000",
    clientId: "google-client-id",
    clientSecret: "google-client-secret",
  };

  it("should create a provider with Google endpoints configured", () => {
    const provider = new GoogleProvider(baseConfig);
    const config = provider.getOAuthConfig();

    expect(config.enabled).toBe(true);
    expect(config.authorizationServer).toBeDefined();
  });

  it("should use Google default scopes in protected resource", () => {
    const provider = new GoogleProvider(baseConfig);
    const config = provider.getOAuthConfig();

    expect(config.protectedResource.scopesSupported).toEqual([
      "openid",
      "profile",
      "email",
    ]);
  });

  it("should allow custom scopes", () => {
    const provider = new GoogleProvider({
      ...baseConfig,
      scopes: ["openid", "https://www.googleapis.com/auth/calendar"],
    });
    const config = provider.getOAuthConfig();

    expect(config.protectedResource.scopesSupported).toEqual([
      "openid",
      "https://www.googleapis.com/auth/calendar",
    ]);
  });
});

describe("AzureProvider", () => {
  const baseConfig = {
    baseUrl: "http://localhost:8000",
    clientId: "azure-client-id",
    clientSecret: "azure-client-secret",
  };

  it("should create a provider with Azure endpoints configured", () => {
    const provider = new AzureProvider(baseConfig);
    const config = provider.getOAuthConfig();

    expect(config.enabled).toBe(true);
    expect(config.authorizationServer).toBeDefined();
  });

  it("should use Azure default scopes in protected resource", () => {
    const provider = new AzureProvider(baseConfig);
    const config = provider.getOAuthConfig();

    expect(config.protectedResource.scopesSupported).toEqual([
      "openid",
      "profile",
      "email",
    ]);
  });

  it("should allow custom tenant ID", () => {
    const provider = new AzureProvider({
      ...baseConfig,
      tenantId: "my-tenant-id",
    });
    const config = provider.getOAuthConfig();

    // Just verify it creates successfully with custom tenant
    expect(config.enabled).toBe(true);
    expect(config.protectedResource.resource).toBe("http://localhost:8000");
  });

  it("should allow custom scopes", () => {
    const provider = new AzureProvider({
      ...baseConfig,
      scopes: ["openid", "User.Read"],
    });
    const config = provider.getOAuthConfig();

    expect(config.protectedResource.scopesSupported).toEqual([
      "openid",
      "User.Read",
    ]);
  });
});

describe("AuthProvider common behavior", () => {
  it("all providers should implement authenticate method", async () => {
    const providers = [
      new OAuthProvider({
        authorizationEndpoint: "https://auth.example.com/authorize",
        baseUrl: "http://localhost:8000",
        clientId: "test",
        clientSecret: "test",
        tokenEndpoint: "https://auth.example.com/token",
      }),
      new GitHubProvider({
        baseUrl: "http://localhost:8000",
        clientId: "test",
        clientSecret: "test",
      }),
      new GoogleProvider({
        baseUrl: "http://localhost:8000",
        clientId: "test",
        clientSecret: "test",
      }),
      new AzureProvider({
        baseUrl: "http://localhost:8000",
        clientId: "test",
        clientSecret: "test",
      }),
    ];

    for (const provider of providers) {
      // All should return undefined for stdio (no request)
      const result = await provider.authenticate(undefined);
      expect(result).toBeUndefined();
    }
  });

  it("all providers should implement getOAuthConfig method", () => {
    const providers = [
      new OAuthProvider({
        authorizationEndpoint: "https://auth.example.com/authorize",
        baseUrl: "http://localhost:8000",
        clientId: "test",
        clientSecret: "test",
        tokenEndpoint: "https://auth.example.com/token",
      }),
      new GitHubProvider({
        baseUrl: "http://localhost:8000",
        clientId: "test",
        clientSecret: "test",
      }),
      new GoogleProvider({
        baseUrl: "http://localhost:8000",
        clientId: "test",
        clientSecret: "test",
      }),
      new AzureProvider({
        baseUrl: "http://localhost:8000",
        clientId: "test",
        clientSecret: "test",
      }),
    ];

    for (const provider of providers) {
      const config = provider.getOAuthConfig();
      expect(config.enabled).toBe(true);
      expect(config.proxy).toBeDefined();
      expect(config.authorizationServer).toBeDefined();
      expect(config.protectedResource).toBeDefined();
    }
  });

  it("all providers should implement getProxy method", () => {
    const providers = [
      new OAuthProvider({
        authorizationEndpoint: "https://auth.example.com/authorize",
        baseUrl: "http://localhost:8000",
        clientId: "test",
        clientSecret: "test",
        tokenEndpoint: "https://auth.example.com/token",
      }),
      new GitHubProvider({
        baseUrl: "http://localhost:8000",
        clientId: "test",
        clientSecret: "test",
      }),
      new GoogleProvider({
        baseUrl: "http://localhost:8000",
        clientId: "test",
        clientSecret: "test",
      }),
      new AzureProvider({
        baseUrl: "http://localhost:8000",
        clientId: "test",
        clientSecret: "test",
      }),
    ];

    for (const provider of providers) {
      const proxy = provider.getProxy();
      expect(proxy).toBeDefined();
      expect(typeof proxy.loadUpstreamTokens).toBe("function");
    }
  });
});
