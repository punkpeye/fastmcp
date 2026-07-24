/**
 * Microsoft Azure/Entra ID OAuth Provider
 * Pre-configured OAuth provider for Microsoft Identity Platform
 */

import { OAuthProxy } from "../OAuthProxy.js";
import {
  AuthProvider,
  type AuthProviderConfig,
  type OAuthSession,
} from "./AuthProvider.js";

/**
 * Azure-specific configuration
 */
export interface AzureProviderConfig extends AuthProviderConfig {
  /** Tenant ID or 'common', 'organizations', 'consumers' (default: 'common') */
  tenantId?: string;
}

/**
 * Azure-specific session with additional user info
 */
export interface AzureSession extends OAuthSession {
  upn?: string;
}

/**
 * Microsoft Azure AD / Entra ID OAuth 2.0 Provider
 * Callback URL: {baseUrl}/oauth/callback
 */
export class AzureProvider extends AuthProvider<AzureSession> {
  private tenantId: string;

  constructor(config: AzureProviderConfig) {
    super(config);
    this.tenantId = config.tenantId ?? "common";
  }

  protected createProxy(): OAuthProxy {
    return new OAuthProxy({
      // No fallback default: framework users must explicitly list the URIs
      // they trust. A previous default of ["http://localhost:*", "https://*"]
      // enabled CWE-601 open-redirect / code-theft via /oauth/authorize.
      allowedRedirectUriPatterns: this.config.allowedRedirectUriPatterns,
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
    return `https://login.microsoftonline.com/${this.tenantId}/oauth2/v2.0/authorize`;
  }

  protected getDefaultScopes(): string[] {
    return ["openid", "profile", "email"];
  }

  protected getTokenEndpoint(): string {
    return `https://login.microsoftonline.com/${this.tenantId}/oauth2/v2.0/token`;
  }
}
