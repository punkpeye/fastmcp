/**
 * Google OAuth Provider
 * Pre-configured OAuth Proxy for Google Identity Platform
 */

import type { OAuthProviderConfig } from "../types.js";

import { OAuthProxy } from "../OAuthProxy.js";

/**
 * Google OAuth 2.0 Provider
 * Supports Google Sign-In and Google APIs
 */
export class GoogleProvider extends OAuthProxy {
  constructor(config: OAuthProviderConfig) {
    super({
      baseUrl: config.baseUrl,
      consentRequired: config.consentRequired,
      scopes: config.scopes || ["openid", "profile", "email"],
      upstreamAuthorizationEndpoint:
        "https://accounts.google.com/o/oauth2/v2/auth",
      upstreamClientId: config.clientId,
      upstreamClientSecret: config.clientSecret,
      upstreamTokenEndpoint: "https://oauth2.googleapis.com/token",
    });
  }
}
