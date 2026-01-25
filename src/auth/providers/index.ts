/**
 * OAuth Provider Implementations
 * High-level auth providers for common OAuth services
 */

// Base classes and types
export {
  AuthProvider,
  type AuthProviderConfig,
  type GenericOAuthProviderConfig,
  type OAuthSession,
} from "./AuthProvider.js";

// Pre-configured providers
export {
  AzureProvider,
  type AzureProviderConfig,
  type AzureSession,
} from "./AzureProvider.js";

export { GitHubProvider, type GitHubSession } from "./GitHubProvider.js";
export { GoogleProvider, type GoogleSession } from "./GoogleProvider.js";
// Generic OAuth provider
export { OAuthProvider } from "./OAuthProvider.js";
