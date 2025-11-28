/**
 * GitHub OAuth Provider
 * Pre-configured OAuth Proxy for GitHub OAuth Apps
 */

import type { OAuthProviderConfig } from "../types.js";

import { OAuthProxy } from "../OAuthProxy.js";

/**
 * GitHub OAuth 2.0 Provider
 * Supports GitHub OAuth Apps
 */
export class GitHubProvider extends OAuthProxy {
  constructor(config: OAuthProviderConfig) {
    super({
      baseUrl: config.baseUrl,
      consentRequired: config.consentRequired,
      scopes: config.scopes || ["read:user", "user:email"],
      upstreamAuthorizationEndpoint: "https://github.com/login/oauth/authorize",
      upstreamClientId: config.clientId,
      upstreamClientSecret: config.clientSecret,
      upstreamTokenEndpoint: "https://github.com/login/oauth/access_token",
    });
  }
}
