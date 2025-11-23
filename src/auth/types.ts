/**
 * OAuth Proxy Types
 * Type definitions for the OAuth 2.1 Proxy implementation
 */

/**
 * OAuth authorization request parameters
 */
export interface AuthorizationParams {
  [key: string]: unknown;
  client_id: string;
  code_challenge?: string;
  code_challenge_method?: string;
  redirect_uri: string;
  response_type: string;
  scope?: string;
  state?: string;
}

/**
 * Authorization code storage with PKCE validation
 */
export interface ClientCode {
  /** Client ID that owns this code */
  clientId: string;
  /** Authorization code */
  code: string;
  /** PKCE code challenge for validation */
  codeChallenge: string;
  /** PKCE code challenge method */
  codeChallengeMethod: string;
  /** Code creation timestamp */
  createdAt: Date;
  /** Code expiration timestamp */
  expiresAt: Date;
  /** Associated transaction ID */
  transactionId: string;
  /** Upstream tokens obtained from provider */
  upstreamTokens: UpstreamTokenSet;
  /** Whether code has been used */
  used?: boolean;
}

/**
 * Consent data for user approval
 */
export interface ConsentData {
  clientName: string;
  provider: string;
  scope: string[];
  timestamp: number;
  transactionId: string;
}

/**
 * Client metadata for storage
 */
export interface DCRClientMetadata {
  client_name?: string;
  client_uri?: string;
  contacts?: string[];
  jwks?: Record<string, unknown>;
  jwks_uri?: string;
  logo_uri?: string;
  policy_uri?: string;
  scope?: string;
  software_id?: string;
  software_version?: string;
  tos_uri?: string;
}

/**
 * RFC 7591 Dynamic Client Registration Request
 */
export interface DCRRequest {
  /** Client name */
  client_name?: string;
  /** Client homepage URL */
  client_uri?: string;
  /** Contact email addresses */
  contacts?: string[];
  /** Allowed grant types */
  grant_types?: string[];
  /** JWKS object */
  jwks?: Record<string, unknown>;
  /** JWKS URI */
  jwks_uri?: string;
  /** Client logo URL */
  logo_uri?: string;
  /** Privacy policy URL */
  policy_uri?: string;
  /** REQUIRED: Array of redirect URIs */
  redirect_uris: string[];
  /** Allowed response types */
  response_types?: string[];
  /** Requested scope */
  scope?: string;
  /** Software identifier */
  software_id?: string;
  /** Software version */
  software_version?: string;
  /** Token endpoint authentication method */
  token_endpoint_auth_method?: string;
  /** Terms of service URL */
  tos_uri?: string;
}

/**
 * RFC 7591 Dynamic Client Registration Response
 */
export interface DCRResponse {
  /** REQUIRED: Client identifier */
  client_id: string;
  /** Client ID issued timestamp */
  client_id_issued_at?: number;
  client_name?: string;
  /** Client secret */
  client_secret?: string;
  /** Client secret expiration (0 = never) */
  client_secret_expires_at?: number;
  client_uri?: string;
  contacts?: string[];
  grant_types?: string[];
  jwks?: Record<string, unknown>;
  jwks_uri?: string;
  logo_uri?: string;
  policy_uri?: string;
  /** Echo back all registered metadata */
  redirect_uris: string[];
  /** Registration access token */
  registration_access_token?: string;
  /** Registration client URI */
  registration_client_uri?: string;
  response_types?: string[];
  scope?: string;
  software_id?: string;
  software_version?: string;
  token_endpoint_auth_method?: string;
  tos_uri?: string;
}

/**
 * OAuth error response
 */
export interface OAuthError {
  error: string;
  error_description?: string;
  error_uri?: string;
}

/**
 * OAuth Proxy provider for pre-configured providers
 */
export interface OAuthProviderConfig {
  baseUrl: string;
  clientId: string;
  clientSecret: string;
  consentRequired?: boolean;
  scopes?: string[];
}

/**
 * Custom claims passthrough configuration
 */
export interface CustomClaimsPassthroughConfig {
  /** Enable passthrough from upstream access token (if JWT format). Default: true */
  fromAccessToken?: boolean;

  /** Enable passthrough from upstream ID token. Default: true */
  fromIdToken?: boolean;

  /** Prefix upstream claims to prevent collisions. Default: false (no prefix) */
  claimPrefix?: string | false;

  /** Only passthrough these specific claims (allowlist). Default: undefined (allow all non-protected) */
  allowedClaims?: string[];

  /** Never passthrough these claims (blocklist, in addition to protected claims). Default: [] */
  blockedClaims?: string[];

  /** Maximum length for claim values. Default: 2000 */
  maxClaimValueSize?: number;

  /** Allow nested objects/arrays in claims. Default: false (only primitives) */
  allowComplexClaims?: boolean;
}

/**
 * Configuration for the OAuth Proxy
 */
export interface OAuthProxyConfig {
  /** Allowed redirect URI patterns for client registration */
  allowedRedirectUriPatterns?: string[];
  /** Authorization code TTL in seconds (default: 300) */
  authorizationCodeTtl?: number;
  /** Base URL of this proxy server */
  baseUrl: string;
  /** Require user consent (default: true) */
  consentRequired?: boolean;
  /** Secret key for signing consent cookies */
  consentSigningKey?: string;
  /**
   * Custom claims passthrough configuration.
   * When enabled (default), extracts custom claims from upstream access token and ID token
   * and includes them in the proxy's issued JWT tokens.
   * This enables authorization based on upstream roles, permissions, etc.
   * Set to false to disable claims passthrough entirely.
   * Default: true (enabled with default settings)
   */
  customClaimsPassthrough?: CustomClaimsPassthroughConfig | boolean;
  /** Enable token swap pattern (default: true) - issues short-lived JWTs instead of passing through upstream tokens */
  enableTokenSwap?: boolean;
  /** Encryption key for token storage (default: auto-generated). Set to false to disable encryption. */
  encryptionKey?: string | false;
  /** Forward client's PKCE to upstream (default: false) */
  forwardPkce?: boolean;
  /** Secret key for signing JWTs when token swap is enabled */
  jwtSigningKey?: string;
  /** OAuth callback path (default: /oauth/callback) */
  redirectPath?: string;
  /** Scopes to request from upstream provider */
  scopes?: string[];
  /** Custom token storage backend */
  tokenStorage?: TokenStorage;
  /** Custom token verifier for validating upstream tokens */
  tokenVerifier?: TokenVerifier;
  /** Transaction TTL in seconds (default: 600) */
  transactionTtl?: number;
  /** Upstream provider's authorization endpoint URL */
  upstreamAuthorizationEndpoint: string;
  /** Pre-registered client ID with upstream provider */
  upstreamClientId: string;
  /** Pre-registered client secret with upstream provider */
  upstreamClientSecret: string;
  /** Upstream provider's token endpoint URL */
  upstreamTokenEndpoint: string;
}

/**
 * OAuth transaction tracking active authorization flows
 */
export interface OAuthTransaction {
  /** Client's callback URL */
  clientCallbackUrl: string;
  /** Client's PKCE code challenge */
  clientCodeChallenge: string;
  /** Client's PKCE code challenge method (S256 or plain) */
  clientCodeChallengeMethod: string;
  /** Client ID from registration */
  clientId: string;
  /** Whether user consent was given */
  consentGiven?: boolean;
  /** Transaction creation timestamp */
  createdAt: Date;
  /** Transaction expiration timestamp */
  expiresAt: Date;
  /** Unique transaction ID */
  id: string;
  /** Additional state data */
  metadata?: Record<string, unknown>;
  /** Proxy-generated PKCE challenge for upstream */
  proxyCodeChallenge: string;
  /** Proxy-generated PKCE verifier for upstream */
  proxyCodeVerifier: string;
  /** Requested scopes */
  scope: string[];
  /** OAuth state parameter */
  state: string;
}

/**
 * PKCE pair
 */
export interface PKCEPair {
  challenge: string;
  verifier: string;
}

/**
 * Dynamic client registration data
 */
export interface ProxyDCRClient {
  /** Registered callback URL */
  callbackUrl: string;
  /** Generated or assigned client ID */
  clientId: string;
  /** Client secret (optional) */
  clientSecret?: string;
  /** Client metadata from registration request */
  metadata?: DCRClientMetadata;
  /** Client registration timestamp */
  registeredAt: Date;
}

/**
 * OAuth refresh token request
 */
export interface RefreshRequest {
  client_id: string;
  client_secret?: string;
  grant_type: "refresh_token";
  refresh_token: string;
  scope?: string;
}

/**
 * OAuth token request
 */
export interface TokenRequest {
  client_id: string;
  client_secret?: string;
  code: string;
  code_verifier?: string;
  grant_type: "authorization_code";
  redirect_uri: string;
}

/**
 * OAuth token response
 */
export interface TokenResponse {
  access_token: string;
  expires_in: number;
  id_token?: string;
  refresh_token?: string;
  scope?: string;
  token_type: string;
}

/**
 * Token storage interface
 */
export interface TokenStorage {
  /** Clean up expired entries */
  cleanup(): Promise<void>;
  /** Delete a value */
  delete(key: string): Promise<void>;
  /** Retrieve a value */
  get(key: string): Promise<null | unknown>;
  /** Save a value with optional TTL */
  save(key: string, value: unknown, ttl?: number): Promise<void>;
}

/**
 * Token verification result
 */
export interface TokenVerificationResult {
  claims?: Record<string, unknown>;
  error?: string;
  valid: boolean;
}

/**
 * Token verifier for validating upstream tokens
 */
export interface TokenVerifier {
  verify(token: string): Promise<TokenVerificationResult>;
}

/**
 * Token mapping for JWT swap pattern
 * Maps JTI to upstream token reference
 */
export interface TokenMapping {
  /** Client ID */
  clientId: string;
  /** Creation timestamp */
  createdAt: Date;
  /** Expiration timestamp */
  expiresAt: Date;
  /** JTI from FastMCP JWT */
  jti: string;
  /** Scopes */
  scope: string[];
  /** Reference to upstream token set */
  upstreamTokenKey: string;
}

/**
 * Token set from upstream OAuth provider
 */
export interface UpstreamTokenSet {
  /** Access token */
  accessToken: string;
  /** Token expiration in seconds */
  expiresIn: number;
  /** ID token (for OIDC) */
  idToken?: string;
  /** Token issuance timestamp */
  issuedAt: Date;
  /** Refresh token (if provided) */
  refreshToken?: string;
  /** Granted scopes */
  scope: string[];
  /** Token type (usually "Bearer") */
  tokenType: string;
}
