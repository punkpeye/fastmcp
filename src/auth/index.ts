/**
 * FastMCP Authentication Module
 * OAuth 2.1 Proxy for Dynamic Client Registration
 */

// Helper functions for canAccess and session extraction
export {
  getAuthSession,
  requireAll,
  requireAny,
  requireAuth,
  requireRole,
  requireScopes,
} from "./helpers.js";

// OAuth Proxy
export { OAuthProxy, OAuthProxyError } from "./OAuthProxy.js";

// Auth Providers
export * from "./providers/index.js";

// Constants
export {
  DEFAULT_ACCESS_TOKEN_TTL,
  DEFAULT_ACCESS_TOKEN_TTL_NO_REFRESH,
  DEFAULT_AUTHORIZATION_CODE_TTL,
  DEFAULT_REFRESH_TOKEN_TTL,
  DEFAULT_TRANSACTION_TTL,
} from "./types.js";

// Types
export type {
  AuthorizationParams,
  ClientCode,
  ConsentData,
  DCRClientMetadata,
  DCRRequest,
  DCRResponse,
  OAuthError,
  OAuthProviderConfig,
  OAuthProxyConfig,
  OAuthTransaction,
  PKCEPair,
  ProxyDCRClient,
  RefreshRequest,
  TokenMapping,
  TokenRequest,
  TokenResponse,
  TokenStorage,
  TokenVerificationResult,
  TokenVerifier,
  UpstreamTokenSet,
} from "./types.js";

// Utilities
export { ConsentManager } from "./utils/consent.js";
export { DiskStore } from "./utils/diskStore.js";
export type {
  JWKSVerificationResult,
  JWKSVerifierConfig,
} from "./utils/jwks.js";
export { JWKSVerifier } from "./utils/jwks.js";
export type { JWTClaims } from "./utils/jwtIssuer.js";
export { JWTIssuer } from "./utils/jwtIssuer.js";
export { PKCEUtils } from "./utils/pkce.js";
export {
  EncryptedTokenStorage,
  MemoryTokenStorage,
} from "./utils/tokenStore.js";
