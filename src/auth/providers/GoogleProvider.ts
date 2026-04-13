/**
 * Google OAuth Provider
 * Pre-configured OAuth provider for Google Identity Platform
 */

import { OAuthProxy } from "../OAuthProxy.js";
import {
  AuthProvider,
  type AuthProviderConfig,
  type OAuthSession,
} from "./AuthProvider.js";

/**
 * Google-specific session with additional user info
 */
export interface GoogleSession extends OAuthSession {
  email?: string;
}

/**
 * Google OAuth 2.0 Provider
 * Callback URL: {baseUrl}/oauth/callback
 */
export class GoogleProvider extends AuthProvider<GoogleSession> {
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
    return "https://accounts.google.com/o/oauth2/v2/auth";
  }

  protected getDefaultScopes(): string[] {
    return ["openid", "profile", "email"];
  }

  protected getTokenEndpoint(): string {
    return "https://oauth2.googleapis.com/token";
  }
}
