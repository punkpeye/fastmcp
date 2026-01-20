/**
 * OAuth 2.1 Proxy Implementation
 * Provides DCR-compatible interface for non-DCR OAuth providers
 */

import { randomBytes } from "crypto";
import { z } from "zod";

import type {
  AuthorizationParams,
  ClientCode,
  DCRRequest,
  DCRResponse,
  OAuthError,
  OAuthProxyConfig,
  OAuthTransaction,
  ProxyDCRClient,
  RefreshRequest,
  TokenRequest,
  TokenResponse,
  TokenStorage,
  UpstreamTokenSet,
} from "./types.js";

import {
  DEFAULT_ACCESS_TOKEN_TTL,
  DEFAULT_ACCESS_TOKEN_TTL_NO_REFRESH,
  DEFAULT_AUTHORIZATION_CODE_TTL,
  DEFAULT_REFRESH_TOKEN_TTL,
  DEFAULT_TRANSACTION_TTL,
} from "./types.js";
import { ClaimsExtractor } from "./utils/claimsExtractor.js";
import { ConsentManager } from "./utils/consent.js";
import { JWTIssuer } from "./utils/jwtIssuer.js";
import { PKCEUtils } from "./utils/pkce.js";
import {
  EncryptedTokenStorage,
  MemoryTokenStorage,
} from "./utils/tokenStore.js";

/**
 * OAuth 2.1 Proxy
 * Acts as transparent intermediary between MCP clients and upstream OAuth providers
 */
export class OAuthProxy {
  private claimsExtractor: ClaimsExtractor | null = null;
  private cleanupInterval: NodeJS.Timeout | null = null;
  private clientCodes: Map<string, ClientCode> = new Map();
  private config: OAuthProxyConfig;
  private consentManager: ConsentManager;
  private jwtIssuer?: JWTIssuer;
  private registeredClients: Map<string, ProxyDCRClient> = new Map();
  private tokenStorage: TokenStorage;
  private transactions: Map<string, OAuthTransaction> = new Map();

  constructor(config: OAuthProxyConfig) {
    this.config = {
      allowedRedirectUriPatterns: ["https://*", "http://localhost:*"],
      authorizationCodeTtl: DEFAULT_AUTHORIZATION_CODE_TTL,
      consentRequired: true,
      enableTokenSwap: true, // Enabled by default for security
      redirectPath: "/oauth/callback",
      transactionTtl: DEFAULT_TRANSACTION_TTL,
      upstreamTokenEndpointAuthMethod: "client_secret_basic",
      ...config,
    };

    // Set up token storage with encryption by default (matches Python's secure defaults)
    let storage = config.tokenStorage || new MemoryTokenStorage();

    // Wrap storage with encryption if not already encrypted
    // Check if it's already an EncryptedTokenStorage instance
    const isAlreadyEncrypted =
      storage.constructor.name === "EncryptedTokenStorage";

    if (!isAlreadyEncrypted && config.encryptionKey !== false) {
      // Auto-generate encryption key if not provided
      const encryptionKey =
        typeof config.encryptionKey === "string"
          ? config.encryptionKey
          : this.generateSigningKey();

      storage = new EncryptedTokenStorage(storage, encryptionKey);
    }

    this.tokenStorage = storage;
    this.consentManager = new ConsentManager(
      config.consentSigningKey || this.generateSigningKey(),
    );

    // Initialize JWT issuer if token swap is enabled
    if (this.config.enableTokenSwap) {
      // Auto-generate signing key if not provided
      const signingKey = this.config.jwtSigningKey || this.generateSigningKey();

      this.jwtIssuer = new JWTIssuer({
        audience: this.config.baseUrl,
        issuer: this.config.baseUrl,
        signingKey: signingKey,
      });
    }

    // Initialize claims extractor (enabled by default)
    const claimsConfig =
      config.customClaimsPassthrough !== undefined
        ? config.customClaimsPassthrough
        : true; // Default: enabled

    if (claimsConfig !== false) {
      this.claimsExtractor = new ClaimsExtractor(claimsConfig);
    }

    // Start periodic cleanup
    this.startCleanup();
  }

  /**
   * OAuth authorization endpoint
   */
  async authorize(params: AuthorizationParams): Promise<Response> {
    // Validate parameters
    if (!params.client_id || !params.redirect_uri || !params.response_type) {
      throw new OAuthProxyError(
        "invalid_request",
        "Missing required parameters",
      );
    }

    if (params.response_type !== "code") {
      throw new OAuthProxyError(
        "unsupported_response_type",
        "Only 'code' response type is supported",
      );
    }

    // Validate PKCE if provided
    if (params.code_challenge && !params.code_challenge_method) {
      throw new OAuthProxyError(
        "invalid_request",
        "code_challenge_method required when code_challenge is present",
      );
    }

    // Create transaction
    const transaction = await this.createTransaction(params);

    // If consent required, show consent screen
    if (this.config.consentRequired && !transaction.consentGiven) {
      return this.consentManager.createConsentResponse(
        transaction,
        this.getProviderName(),
      );
    }

    // Redirect to upstream provider
    return this.redirectToUpstream(transaction);
  }

  /**
   * Stop cleanup interval and destroy resources
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }

    this.transactions.clear();
    this.clientCodes.clear();
    this.registeredClients.clear();
  }

  /**
   * Token endpoint - exchange authorization code for tokens
   */
  async exchangeAuthorizationCode(
    request: TokenRequest,
  ): Promise<TokenResponse> {
    if (request.grant_type !== "authorization_code") {
      throw new OAuthProxyError(
        "unsupported_grant_type",
        "Only authorization_code grant type is supported",
      );
    }

    const clientCode = this.clientCodes.get(request.code);
    if (!clientCode) {
      throw new OAuthProxyError(
        "invalid_grant",
        "Invalid or expired authorization code",
      );
    }

    // Validate client
    if (clientCode.clientId !== request.client_id) {
      throw new OAuthProxyError("invalid_client", "Client ID mismatch");
    }

    // Validate PKCE if used
    if (clientCode.codeChallenge) {
      if (!request.code_verifier) {
        throw new OAuthProxyError(
          "invalid_request",
          "code_verifier required for PKCE",
        );
      }

      const valid = PKCEUtils.validateChallenge(
        request.code_verifier,
        clientCode.codeChallenge,
        clientCode.codeChallengeMethod,
      );

      if (!valid) {
        throw new OAuthProxyError("invalid_grant", "Invalid PKCE verifier");
      }
    }

    // Check if code was already used
    if (clientCode.used) {
      throw new OAuthProxyError(
        "invalid_grant",
        "Authorization code already used",
      );
    }

    // Mark code as used
    clientCode.used = true;
    this.clientCodes.set(request.code, clientCode);

    // Return tokens based on token swap setting
    if (this.config.enableTokenSwap && this.jwtIssuer) {
      // Token swap pattern: issue short-lived JWTs and store upstream tokens
      return await this.issueSwappedTokens(
        clientCode.clientId,
        clientCode.upstreamTokens,
      );
    } else {
      // Pass-through pattern: return upstream tokens directly
      const response: TokenResponse = {
        access_token: clientCode.upstreamTokens.accessToken,
        expires_in: clientCode.upstreamTokens.expiresIn,
        token_type: clientCode.upstreamTokens.tokenType,
      };

      if (clientCode.upstreamTokens.refreshToken) {
        response.refresh_token = clientCode.upstreamTokens.refreshToken;
      }

      if (clientCode.upstreamTokens.idToken) {
        response.id_token = clientCode.upstreamTokens.idToken;
      }

      if (clientCode.upstreamTokens.scope.length > 0) {
        response.scope = clientCode.upstreamTokens.scope.join(" ");
      }

      return response;
    }
  }

  /**
   * Token endpoint - refresh access token
   */
  async exchangeRefreshToken(request: RefreshRequest): Promise<TokenResponse> {
    if (request.grant_type !== "refresh_token") {
      throw new OAuthProxyError(
        "unsupported_grant_type",
        "Only refresh_token grant type is supported",
      );
    }

    const useBasicAuth =
      this.config.upstreamTokenEndpointAuthMethod === "client_secret_basic";

    const bodyParams: Record<string, string> = {
      grant_type: "refresh_token",
      refresh_token: request.refresh_token,
      ...(request.scope && { scope: request.scope }),
    };

    // Include client credentials in body only for client_secret_post
    if (!useBasicAuth) {
      bodyParams.client_id = this.config.upstreamClientId;
      bodyParams.client_secret = this.config.upstreamClientSecret;
    }

    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };

    // Add Basic Auth header for client_secret_basic
    if (useBasicAuth) {
      headers["Authorization"] = this.getBasicAuthHeader();
    }

    // Exchange refresh token with upstream provider
    const tokenResponse = await fetch(this.config.upstreamTokenEndpoint, {
      body: new URLSearchParams(bodyParams),
      headers,
      method: "POST",
    });

    if (!tokenResponse.ok) {
      const error = (await tokenResponse.json()) as {
        error?: string;
        error_description?: string;
      };
      throw new OAuthProxyError(
        error.error || "invalid_grant",
        error.error_description,
      );
    }

    const tokens = await this.parseTokenResponse(tokenResponse);

    return {
      access_token: tokens.access_token,
      expires_in: tokens.expires_in || 3600,
      id_token: tokens.id_token,
      refresh_token: tokens.refresh_token,
      scope: tokens.scope,
      token_type: tokens.token_type || "Bearer",
    };
  }

  /**
   * Get OAuth discovery metadata
   */
  getAuthorizationServerMetadata(): {
    authorizationEndpoint: string;
    codeChallengeMethodsSupported?: string[];
    dpopSigningAlgValuesSupported?: string[];
    grantTypesSupported?: string[];
    introspectionEndpoint?: string;
    issuer: string;
    jwksUri?: string;
    opPolicyUri?: string;
    opTosUri?: string;
    registrationEndpoint?: string;
    responseModesSupported?: string[];
    responseTypesSupported: string[];
    revocationEndpoint?: string;
    scopesSupported?: string[];
    serviceDocumentation?: string;
    tokenEndpoint: string;
    tokenEndpointAuthMethodsSupported?: string[];
    tokenEndpointAuthSigningAlgValuesSupported?: string[];
    uiLocalesSupported?: string[];
  } {
    return {
      authorizationEndpoint: `${this.config.baseUrl}/oauth/authorize`,
      codeChallengeMethodsSupported: ["S256", "plain"],
      grantTypesSupported: ["authorization_code", "refresh_token"],
      issuer: this.config.baseUrl,
      registrationEndpoint: `${this.config.baseUrl}/oauth/register`,
      responseTypesSupported: ["code"],
      scopesSupported: this.config.scopes || [],
      tokenEndpoint: `${this.config.baseUrl}/oauth/token`,
      tokenEndpointAuthMethodsSupported: [
        "client_secret_basic",
        "client_secret_post",
      ],
    };
  }

  /**
   * Handle OAuth callback from upstream provider
   */
  async handleCallback(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const error = url.searchParams.get("error");

    // Check for errors from upstream
    if (error) {
      const errorDescription = url.searchParams.get("error_description");
      throw new OAuthProxyError(error, errorDescription || undefined);
    }

    if (!code || !state) {
      throw new OAuthProxyError(
        "invalid_request",
        "Missing code or state parameter",
      );
    }

    // Retrieve transaction
    const transaction = this.transactions.get(state);
    if (!transaction) {
      throw new OAuthProxyError("invalid_request", "Invalid or expired state");
    }

    // Exchange code with upstream provider
    const upstreamTokens = await this.exchangeUpstreamCode(code, transaction);

    // Generate authorization code for client
    const clientCode = this.generateAuthorizationCode(
      transaction,
      upstreamTokens,
    );

    // Clean up transaction
    this.transactions.delete(state);

    // Redirect to client callback with code
    const redirectUrl = new URL(transaction.clientCallbackUrl);
    redirectUrl.searchParams.set("code", clientCode);
    redirectUrl.searchParams.set("state", transaction.state);

    return new Response(null, {
      headers: {
        Location: redirectUrl.toString(),
      },
      status: 302,
    });
  }

  /**
   * Handle consent form submission
   */
  async handleConsent(request: Request): Promise<Response> {
    const formData = await request.formData();
    const transactionId = formData.get("transaction_id") as string;
    const action = formData.get("action") as string;

    if (!transactionId) {
      throw new OAuthProxyError("invalid_request", "Missing transaction_id");
    }

    const transaction = this.transactions.get(transactionId);
    if (!transaction) {
      throw new OAuthProxyError(
        "invalid_request",
        "Invalid or expired transaction",
      );
    }

    if (action === "deny") {
      // User denied consent
      this.transactions.delete(transactionId);
      const redirectUrl = new URL(transaction.clientCallbackUrl);
      redirectUrl.searchParams.set("error", "access_denied");
      redirectUrl.searchParams.set(
        "error_description",
        "User denied authorization",
      );
      redirectUrl.searchParams.set("state", transaction.state);

      return new Response(null, {
        headers: {
          Location: redirectUrl.toString(),
        },
        status: 302,
      });
    }

    // User approved, mark consent and redirect to upstream
    transaction.consentGiven = true;
    this.transactions.set(transactionId, transaction);

    return this.redirectToUpstream(transaction);
  }

  /**
   * Load upstream tokens from a FastMCP JWT
   */
  async loadUpstreamTokens(
    fastmcpToken: string,
  ): Promise<null | UpstreamTokenSet> {
    if (!this.jwtIssuer) {
      return null;
    }

    // Verify FastMCP JWT
    const result = await this.jwtIssuer.verify(fastmcpToken);
    if (!result.valid || !result.claims?.jti) {
      return null;
    }

    // Look up token mapping
    const mapping = (await this.tokenStorage.get(
      `mapping:${result.claims.jti}`,
    )) as {
      upstreamTokenKey: string;
    } | null;

    if (!mapping) {
      return null;
    }

    // Retrieve upstream tokens
    const upstreamTokens = (await this.tokenStorage.get(
      `upstream:${mapping.upstreamTokenKey}`,
    )) as null | UpstreamTokenSet;

    return upstreamTokens;
  }

  /**
   * RFC 7591 Dynamic Client Registration
   */
  async registerClient(request: DCRRequest): Promise<DCRResponse> {
    // Validate required fields
    if (!request.redirect_uris || request.redirect_uris.length === 0) {
      throw new OAuthProxyError(
        "invalid_client_metadata",
        "redirect_uris is required",
      );
    }

    // Validate redirect URIs
    for (const uri of request.redirect_uris) {
      if (!this.validateRedirectUri(uri)) {
        throw new OAuthProxyError(
          "invalid_redirect_uri",
          `Invalid redirect URI: ${uri}`,
        );
      }
    }

    // Store client registration (indexed by primary redirect URI)
    const clientId = this.config.upstreamClientId;
    const client: ProxyDCRClient = {
      callbackUrl: request.redirect_uris[0],
      clientId,
      clientSecret: this.config.upstreamClientSecret,
      metadata: {
        client_name: request.client_name,
        client_uri: request.client_uri,
        contacts: request.contacts,
        jwks: request.jwks,
        jwks_uri: request.jwks_uri,
        logo_uri: request.logo_uri,
        policy_uri: request.policy_uri,
        scope: request.scope,
        software_id: request.software_id,
        software_version: request.software_version,
        tos_uri: request.tos_uri,
      },
      registeredAt: new Date(),
    };

    this.registeredClients.set(request.redirect_uris[0], client);

    // Return RFC 7591 compliant response
    const response: DCRResponse = {
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      // Echo back optional metadata
      client_name: request.client_name,
      client_secret: this.config.upstreamClientSecret,
      client_secret_expires_at: 0, // Never expires
      client_uri: request.client_uri,
      contacts: request.contacts,
      grant_types: request.grant_types || [
        "authorization_code",
        "refresh_token",
      ],
      jwks: request.jwks,
      jwks_uri: request.jwks_uri,
      logo_uri: request.logo_uri,
      policy_uri: request.policy_uri,
      redirect_uris: request.redirect_uris,
      response_types: request.response_types || ["code"],
      scope: request.scope,
      software_id: request.software_id,
      software_version: request.software_version,
      token_endpoint_auth_method:
        request.token_endpoint_auth_method || "client_secret_basic",
      tos_uri: request.tos_uri,
    };

    return response;
  }

  /**
   * Clean up expired transactions and codes
   */
  private cleanup(): void {
    const now = Date.now();

    // Clean up expired transactions
    for (const [id, transaction] of this.transactions.entries()) {
      if (transaction.expiresAt.getTime() < now) {
        this.transactions.delete(id);
      }
    }

    // Clean up expired codes
    for (const [code, clientCode] of this.clientCodes.entries()) {
      if (clientCode.expiresAt.getTime() < now) {
        this.clientCodes.delete(code);
      }
    }

    // Clean up token storage
    void this.tokenStorage.cleanup();
  }

  /**
   * Create a new OAuth transaction
   */
  private async createTransaction(
    params: AuthorizationParams,
  ): Promise<OAuthTransaction> {
    const transactionId = this.generateId();
    const proxyPkce = PKCEUtils.generatePair("S256");

    const transaction: OAuthTransaction = {
      clientCallbackUrl: params.redirect_uri,
      clientCodeChallenge: params.code_challenge || "",
      clientCodeChallengeMethod: params.code_challenge_method || "plain",
      clientId: params.client_id,
      createdAt: new Date(),
      expiresAt: new Date(
        Date.now() + (this.config.transactionTtl || 600) * 1000,
      ),
      id: transactionId,
      proxyCodeChallenge: proxyPkce.challenge,
      proxyCodeVerifier: proxyPkce.verifier,
      scope: params.scope ? params.scope.split(" ") : this.config.scopes || [],
      state: params.state || this.generateId(),
    };

    this.transactions.set(transactionId, transaction);

    return transaction;
  }

  /**
   * Exchange authorization code with upstream provider
   */
  private async exchangeUpstreamCode(
    code: string,
    transaction: OAuthTransaction,
  ): Promise<UpstreamTokenSet> {
    const useBasicAuth =
      this.config.upstreamTokenEndpointAuthMethod === "client_secret_basic";

    const bodyParams: Record<string, string> = {
      code,
      code_verifier: transaction.proxyCodeVerifier,
      grant_type: "authorization_code",
      redirect_uri: `${this.config.baseUrl}${this.config.redirectPath}`,
    };

    // Include client credentials in body only for client_secret_post
    if (!useBasicAuth) {
      bodyParams.client_id = this.config.upstreamClientId;
      bodyParams.client_secret = this.config.upstreamClientSecret;
    }

    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };

    // Add Basic Auth header for client_secret_basic
    if (useBasicAuth) {
      headers["Authorization"] = this.getBasicAuthHeader();
    }

    const tokenResponse = await fetch(this.config.upstreamTokenEndpoint, {
      body: new URLSearchParams(bodyParams),
      headers,
      method: "POST",
    });

    if (!tokenResponse.ok) {
      const error = (await tokenResponse.json()) as {
        error?: string;
        error_description?: string;
      };
      throw new OAuthProxyError(
        error.error || "server_error",
        error.error_description,
      );
    }

    const tokens = await this.parseTokenResponse(tokenResponse);

    return {
      accessToken: tokens.access_token,
      expiresIn: tokens.expires_in || 3600,
      idToken: tokens.id_token,
      issuedAt: new Date(),
      refreshToken: tokens.refresh_token,
      scope: tokens.scope ? tokens.scope.split(" ") : transaction.scope,
      tokenType: tokens.token_type || "Bearer",
    };
  }

  /**
   * Extract JTI from a JWT token
   */
  private async extractJti(token: string): Promise<string> {
    if (!this.jwtIssuer) {
      throw new Error("JWT issuer not initialized");
    }

    const result = await this.jwtIssuer.verify(token);
    if (!result.valid || !result.claims?.jti) {
      throw new Error("Failed to extract JTI from token");
    }

    return result.claims.jti;
  }

  /**
   * Extract custom claims from upstream tokens
   * Combines claims from access token and ID token (if present)
   */
  private async extractUpstreamClaims(
    upstreamTokens: UpstreamTokenSet,
  ): Promise<null | Record<string, unknown>> {
    if (!this.claimsExtractor) {
      return null;
    }

    const allClaims: Record<string, unknown> = {};

    // Extract from access token (if JWT format)
    const accessClaims = await this.claimsExtractor.extract(
      upstreamTokens.accessToken,
      "access",
    );
    if (accessClaims) {
      Object.assign(allClaims, accessClaims);
    }

    // Extract from ID token (if present and JWT format)
    if (upstreamTokens.idToken) {
      const idClaims = await this.claimsExtractor.extract(
        upstreamTokens.idToken,
        "id",
      );
      if (idClaims) {
        // Access token claims take precedence over ID token claims
        for (const [key, value] of Object.entries(idClaims)) {
          if (!(key in allClaims)) {
            allClaims[key] = value;
          }
        }
      }
    }

    return Object.keys(allClaims).length > 0 ? allClaims : null;
  }

  /**
   * Generate authorization code for client
   */
  private generateAuthorizationCode(
    transaction: OAuthTransaction,
    upstreamTokens: UpstreamTokenSet,
  ): string {
    const code = this.generateId();

    const clientCode: ClientCode = {
      clientId: transaction.clientId,
      code,
      codeChallenge: transaction.clientCodeChallenge,
      codeChallengeMethod: transaction.clientCodeChallengeMethod,
      createdAt: new Date(),
      expiresAt: new Date(
        Date.now() + (this.config.authorizationCodeTtl || 300) * 1000,
      ),
      transactionId: transaction.id,
      upstreamTokens,
    };

    this.clientCodes.set(code, clientCode);

    return code;
  }

  /**
   * Generate secure random ID
   */
  private generateId(): string {
    return randomBytes(32).toString("base64url");
  }

  /**
   * Generate signing key for consent cookies
   */
  private generateSigningKey(): string {
    return randomBytes(32).toString("hex");
  }

  /**
   * Generate Basic auth header value for upstream token endpoint
   * Per RFC 6749 Section 2.3.1, credentials must be URL-encoded before base64 encoding
   */
  private getBasicAuthHeader(): string {
    const encodedClientId = encodeURIComponent(this.config.upstreamClientId);
    const encodedClientSecret = encodeURIComponent(
      this.config.upstreamClientSecret,
    );
    return `Basic ${Buffer.from(`${encodedClientId}:${encodedClientSecret}`).toString("base64")}`;
  }

  /**
   * Get provider name for display
   */
  private getProviderName(): string {
    const url = new URL(this.config.upstreamAuthorizationEndpoint);
    return url.hostname;
  }

  /**
   * Issue swapped tokens (JWT pattern)
   * Issues short-lived FastMCP JWTs and stores upstream tokens securely
   */
  private async issueSwappedTokens(
    clientId: string,
    upstreamTokens: UpstreamTokenSet,
  ): Promise<TokenResponse> {
    if (!this.jwtIssuer) {
      throw new Error("JWT issuer not initialized");
    }

    // Extract custom claims from upstream tokens
    const customClaims = await this.extractUpstreamClaims(upstreamTokens);

    // Determine access token TTL (hierarchical: upstream → config → default)
    let accessTokenTtl: number;
    if (upstreamTokens.expiresIn > 0) {
      accessTokenTtl = upstreamTokens.expiresIn;
    } else if (this.config.accessTokenTtl) {
      accessTokenTtl = this.config.accessTokenTtl;
    } else if (upstreamTokens.refreshToken) {
      accessTokenTtl = DEFAULT_ACCESS_TOKEN_TTL;
    } else {
      accessTokenTtl = DEFAULT_ACCESS_TOKEN_TTL_NO_REFRESH;
    }

    // Determine refresh token TTL early (needed for upstream storage TTL)
    const refreshTokenTtl = upstreamTokens.refreshToken
      ? (this.config.refreshTokenTtl ?? DEFAULT_REFRESH_TOKEN_TTL)
      : 0;

    // Store upstream tokens with longest-lived token TTL (min 1s for safety)
    const upstreamStorageTtl = Math.max(accessTokenTtl, refreshTokenTtl, 1);
    const upstreamTokenKey = this.generateId();
    await this.tokenStorage.save(
      `upstream:${upstreamTokenKey}`,
      upstreamTokens,
      upstreamStorageTtl,
    );

    // Issue FastMCP access token with custom claims
    const accessToken = this.jwtIssuer.issueAccessToken(
      clientId,
      upstreamTokens.scope,
      customClaims || undefined,
      accessTokenTtl,
    );

    // Decode JWT to get JTI
    const accessJti = await this.extractJti(accessToken);

    // Store token mapping
    await this.tokenStorage.save(
      `mapping:${accessJti}`,
      {
        clientId,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + accessTokenTtl * 1000),
        jti: accessJti,
        scope: upstreamTokens.scope,
        upstreamTokenKey,
      },
      accessTokenTtl,
    );

    const response: TokenResponse = {
      access_token: accessToken,
      expires_in: accessTokenTtl,
      scope: upstreamTokens.scope.join(" "),
      token_type: "Bearer",
    };

    // Issue refresh token if upstream provided one
    if (upstreamTokens.refreshToken) {
      const refreshToken = this.jwtIssuer.issueRefreshToken(
        clientId,
        upstreamTokens.scope,
        customClaims || undefined,
        refreshTokenTtl,
      );
      const refreshJti = await this.extractJti(refreshToken);

      // Store refresh token mapping
      await this.tokenStorage.save(
        `mapping:${refreshJti}`,
        {
          clientId,
          createdAt: new Date(),
          expiresAt: new Date(Date.now() + refreshTokenTtl * 1000),
          jti: refreshJti,
          scope: upstreamTokens.scope,
          upstreamTokenKey,
        },
        refreshTokenTtl,
      );

      response.refresh_token = refreshToken;
    }

    return response;
  }

  /**
   * Match URI against pattern (supports wildcards)
   */
  private matchesPattern(uri: string, pattern: string): boolean {
    const regex = new RegExp(
      "^" + pattern.replace(/\*/g, ".*").replace(/\?/g, ".") + "$",
    );
    return regex.test(uri);
  }

  /**
   * Parse token response that can be either JSON or URL-encoded
   * GitHub Apps return URL-encoded format, most providers return JSON
   */
  private async parseTokenResponse(response: Response): Promise<{
    access_token: string;
    expires_in?: number;
    id_token?: string;
    refresh_token?: string;
    scope?: string;
    token_type?: string;
  }> {
    const contentType = (
      response.headers.get("content-type") || ""
    ).toLowerCase();

    // Define Zod schema for token response validation
    const tokenResponseSchema = z.object({
      access_token: z.string().min(1, "access_token cannot be empty"),
      expires_in: z.number().int().positive().optional(),
      id_token: z.string().optional(),
      refresh_token: z.string().optional(),
      scope: z.string().optional(),
      token_type: z.string().optional(),
    });

    // Check if response is URL-encoded (e.g., GitHub Apps)
    if (contentType.includes("application/x-www-form-urlencoded")) {
      const text = await response.text();
      const params = new URLSearchParams(text);

      const rawData = {
        access_token: params.get("access_token") || "",
        expires_in: params.get("expires_in")
          ? parseInt(params.get("expires_in")!)
          : undefined,
        id_token: params.get("id_token") || undefined,
        refresh_token: params.get("refresh_token") || undefined,
        scope: params.get("scope") || undefined,
        token_type: params.get("token_type") || undefined,
      };

      return tokenResponseSchema.parse(rawData);
    }

    // Default to JSON parsing
    const rawJson = await response.json();
    return tokenResponseSchema.parse(rawJson);
  }

  /**
   * Redirect to upstream OAuth provider
   */
  private redirectToUpstream(transaction: OAuthTransaction): Response {
    const authUrl = new URL(this.config.upstreamAuthorizationEndpoint);

    authUrl.searchParams.set("client_id", this.config.upstreamClientId);
    authUrl.searchParams.set(
      "redirect_uri",
      `${this.config.baseUrl}${this.config.redirectPath}`,
    );
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("state", transaction.id);

    if (transaction.scope.length > 0) {
      authUrl.searchParams.set("scope", transaction.scope.join(" "));
    }

    // Add PKCE if not forwarding client PKCE
    if (!this.config.forwardPkce) {
      authUrl.searchParams.set(
        "code_challenge",
        transaction.proxyCodeChallenge,
      );
      authUrl.searchParams.set("code_challenge_method", "S256");
    }

    return new Response(null, {
      headers: {
        Location: authUrl.toString(),
      },
      status: 302,
    });
  }

  /**
   * Start periodic cleanup of expired transactions and codes
   */
  private startCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60000); // Run every minute
  }

  /**
   * Validate redirect URI against allowed patterns
   */
  private validateRedirectUri(uri: string): boolean {
    try {
      const url = new URL(uri);
      const patterns = this.config.allowedRedirectUriPatterns || [];

      for (const pattern of patterns) {
        if (this.matchesPattern(uri, pattern)) {
          return true;
        }
      }

      // Default: allow https and localhost
      return (
        url.protocol === "https:" ||
        url.hostname === "localhost" ||
        url.hostname === "127.0.0.1"
      );
    } catch {
      return false;
    }
  }
}

/**
 * OAuth Proxy Error
 */
export class OAuthProxyError extends Error {
  constructor(
    public code: string,
    public description?: string,
    public statusCode: number = 400,
  ) {
    super(code);
    this.name = "OAuthProxyError";
  }

  toJSON(): OAuthError {
    return {
      error: this.code,
      error_description: this.description,
    };
  }

  toResponse(): Response {
    return new Response(JSON.stringify(this.toJSON()), {
      headers: { "Content-Type": "application/json" },
      status: this.statusCode,
    });
  }
}
