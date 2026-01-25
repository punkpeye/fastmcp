/**
 * AuthProvider Base Class
 * High-level abstraction for OAuth authentication that simplifies configuration
 */

import type { IncomingMessage } from "node:http";

import type { TokenStorage, UpstreamTokenSet } from "../types.js";

import { OAuthProxy } from "../OAuthProxy.js";

/**
 * Configuration common to all OAuth providers.
 */
export interface AuthProviderConfig {
  /** Allowed redirect URI patterns (default: ["http://localhost:*", "https://*"]) */
  allowedRedirectUriPatterns?: string[];
  /** Base URL where the MCP server is accessible */
  baseUrl: string;
  /** OAuth client ID */
  clientId: string;
  /** OAuth client secret */
  clientSecret: string;
  /** Require user consent screen (default: true) */
  consentRequired?: boolean;
  /** Encryption key for token storage (auto-generated if not provided, set to false to disable) */
  encryptionKey?: false | string;
  /** JWT signing key (auto-generated if not provided) */
  jwtSigningKey?: string;
  /** Scopes to request (defaults vary by provider) */
  scopes?: string[];
  /** Token storage backend (default: MemoryTokenStorage) */
  tokenStorage?: TokenStorage;
}

/**
 * Configuration for generic OAuth provider (user-specified endpoints).
 */
export interface GenericOAuthProviderConfig extends AuthProviderConfig {
  /** OAuth authorization endpoint URL */
  authorizationEndpoint: string;
  /** OAuth token endpoint URL */
  tokenEndpoint: string;
  /** Token endpoint auth method (default: "client_secret_basic") */
  tokenEndpointAuthMethod?: "client_secret_basic" | "client_secret_post";
}

/**
 * Standard session type for OAuth providers.
 * Contains the upstream access token and optional metadata.
 */
export interface OAuthSession {
  /** The upstream OAuth access token */
  accessToken: string;
  /** Additional claims extracted from the token (if customClaimsPassthrough enabled) */
  claims?: Record<string, unknown>;
  /** Token expiration time (Unix timestamp in seconds) */
  expiresAt?: number;
  /** ID token from OIDC providers */
  idToken?: string;
  /** Refresh token (if available) */
  refreshToken?: string;
  /** Scopes granted by the OAuth provider */
  scopes?: string[];
}

/**
 * Abstract base class for OAuth providers.
 * Encapsulates OAuthProxy creation, authenticate function, and oauth config.
 *
 * Subclasses only need to implement the endpoint and default scope methods.
 */
export abstract class AuthProvider<
  TSession extends OAuthSession = OAuthSession,
> {
  protected config: AuthProviderConfig;
  /**
   * Get the proxy, creating it lazily if needed.
   */
  protected get proxy(): OAuthProxy {
    if (!this._proxy) {
      this._proxy = this.createProxy();
    }
    return this._proxy;
  }

  private _proxy: OAuthProxy | undefined;

  constructor(config: AuthProviderConfig) {
    this.config = config;
    // Note: proxy is created lazily to allow subclass constructors to run first
  }

  /**
   * Authenticate function to be used by FastMCP.
   * Extracts Bearer token, validates it, and returns session with upstream access token.
   */
  async authenticate(
    request: IncomingMessage | undefined,
  ): Promise<TSession | undefined> {
    if (!request) {
      // stdio transport - no HTTP authentication
      return undefined;
    }

    const authHeader = request.headers?.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return undefined;
    }

    const token = authHeader.slice(7);
    const upstreamTokens = await this.proxy.loadUpstreamTokens(token);

    if (!upstreamTokens) {
      return undefined;
    }

    return this.createSession(upstreamTokens);
  }

  /**
   * Get the OAuth configuration object for FastMCP ServerOptions.
   */
  getOAuthConfig(): {
    authorizationServer: ReturnType<
      OAuthProxy["getAuthorizationServerMetadata"]
    >;
    enabled: true;
    protectedResource: {
      authorizationServers: string[];
      resource: string;
      scopesSupported: string[];
    };
    proxy: OAuthProxy;
  } {
    return {
      authorizationServer: this.proxy.getAuthorizationServerMetadata(),
      enabled: true,
      protectedResource: {
        authorizationServers: [this.config.baseUrl],
        resource: this.config.baseUrl,
        scopesSupported: this.config.scopes ?? this.getDefaultScopes(),
      },
      proxy: this.proxy,
    };
  }

  /**
   * Get the OAuthProxy instance (for advanced use cases).
   */
  getProxy(): OAuthProxy {
    return this.proxy;
  }

  /** Create the underlying OAuthProxy with provider-specific configuration */
  protected abstract createProxy(): OAuthProxy;

  /**
   * Create a session object from upstream tokens.
   * Override in subclasses to add provider-specific session data.
   */
  protected createSession(upstreamTokens: UpstreamTokenSet): TSession {
    return {
      accessToken: upstreamTokens.accessToken,
      expiresAt: upstreamTokens.expiresIn
        ? Math.floor(Date.now() / 1000) + upstreamTokens.expiresIn
        : undefined,
      idToken: upstreamTokens.idToken,
      refreshToken: upstreamTokens.refreshToken,
      scopes: upstreamTokens.scope,
    } as TSession;
  }

  /** Get the authorization endpoint for this provider */
  protected abstract getAuthorizationEndpoint(): string;

  /** Default scopes for this provider */
  protected abstract getDefaultScopes(): string[];

  /** Get the token endpoint for this provider */
  protected abstract getTokenEndpoint(): string;
}
