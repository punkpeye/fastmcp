/**
 * GitHub OAuth Provider
 * Pre-configured OAuth provider for GitHub OAuth Apps
 */

import { OAuthProxy } from "../OAuthProxy.js";
import {
  AuthProvider,
  type AuthProviderConfig,
  type OAuthSession,
} from "./AuthProvider.js";

/**
 * GitHub-specific session with additional user info
 */
export interface GitHubSession extends OAuthSession {
  username?: string;
}

/**
 * GitHub OAuth 2.0 Provider
 * Callback URL: {baseUrl}/oauth/callback
 */
export class GitHubProvider extends AuthProvider<GitHubSession> {
  constructor(config: AuthProviderConfig) {
    super(config);
  }

  protected createProxy(): OAuthProxy {
    return new OAuthProxy({
      allowedRedirectUriPatterns: this.config.allowedRedirectUriPatterns ?? [
        "http://localhost:*",
        "https://*",
      ],
      baseUrl: this.config.baseUrl,
      consentRequired: this.config.consentRequired ?? true,
      encryptionKey: this.config.encryptionKey,
      jwtSigningKey: this.config.jwtSigningKey,
      scopes: this.config.scopes ?? this.getDefaultScopes(),
      tokenStorage: this.config.tokenStorage,
      upstreamAuthorizationEndpoint: this.getAuthorizationEndpoint(),
      upstreamClientId: this.config.clientId,
      upstreamClientSecret: this.config.clientSecret,
      upstreamTokenEndpoint: this.getTokenEndpoint(),
    });
  }

  protected getAuthorizationEndpoint(): string {
    return "https://github.com/login/oauth/authorize";
  }

  protected getDefaultScopes(): string[] {
    return ["read:user", "user:email"];
  }

  protected getTokenEndpoint(): string {
    return "https://github.com/login/oauth/access_token";
  }
}
