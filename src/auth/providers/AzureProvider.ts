/**
 * Microsoft Azure/Entra ID OAuth Provider
 * Pre-configured OAuth Proxy for Microsoft Identity Platform
 */

import type { OAuthProviderConfig } from "../types.js";

import { OAuthProxy } from "../OAuthProxy.js";

export interface AzureProviderConfig extends OAuthProviderConfig {
  /** Azure AD tenant ID or 'common', 'organizations', 'consumers' */
  tenantId?: string;
}

/**
 * Microsoft Azure AD / Entra ID OAuth 2.0 Provider
 * Supports Microsoft accounts and organizational accounts
 */
export class AzureProvider extends OAuthProxy {
  constructor(config: AzureProviderConfig) {
    const tenantId = config.tenantId || "common";

    super({
      baseUrl: config.baseUrl,
      consentRequired: config.consentRequired,
      scopes: config.scopes || ["openid", "profile", "email"],
      upstreamAuthorizationEndpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`,
      upstreamClientId: config.clientId,
      upstreamClientSecret: config.clientSecret,
      upstreamTokenEndpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    });
  }
}
