/**
 * Generic OAuth Provider
 * For any OAuth 2.0 compliant authorization server
 */

import { OAuthProxy } from "../OAuthProxy.js";
import {
  AuthProvider,
  type GenericOAuthProviderConfig,
  type OAuthSession,
} from "./AuthProvider.js";

/**
 * Generic OAuth provider for any OAuth 2.0 compliant authorization server.
 * Use when there's no built-in provider for your identity provider.
 */
export class OAuthProvider<
  TSession extends OAuthSession = OAuthSession,
> extends AuthProvider<TSession> {
  protected genericConfig: GenericOAuthProviderConfig;

  constructor(config: GenericOAuthProviderConfig) {
    super(config);
    this.genericConfig = config;
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
      upstreamTokenEndpointAuthMethod:
        this.genericConfig.tokenEndpointAuthMethod ?? "client_secret_basic",
    });
  }

  protected getAuthorizationEndpoint(): string {
    return this.genericConfig.authorizationEndpoint;
  }

  protected getDefaultScopes(): string[] {
    return ["openid"];
  }

  protected getTokenEndpoint(): string {
    return this.genericConfig.tokenEndpoint;
  }
}
