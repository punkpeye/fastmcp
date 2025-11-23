# OAuth 2.1 Proxy with Custom Claims Passthrough

## Summary

This PR adds a complete **OAuth 2.1 Proxy** implementation to FastMCP with **custom claims passthrough** for authorization and RBAC support. The proxy enables FastMCP servers to authenticate with traditional OAuth providers (Google, GitHub, Azure, etc.) that don't support Dynamic Client Registration (DCR), while providing a DCR-compliant interface to MCP clients.

### Key Features

- ✅ **OAuth 2.1 Proxy Architecture** - Bridge between MCP clients and traditional OAuth providers
- ✅ **Dynamic Client Registration (DCR)** - RFC 7591 compliant
- ✅ **Custom Claims Passthrough** - RBAC & authorization support (enabled by default)
- ✅ **Two-Tier PKCE Security** - Client-to-proxy and proxy-to-upstream protection
- ✅ **Token Swap Pattern** - Enhanced security mode (default)
- ✅ **Pre-configured Providers** - Google, GitHub, Azure/Entra ID
- ✅ **Flexible Storage** - Memory, disk, encrypted, custom backends
- ✅ **User Consent Flow** - Prevents confused deputy attacks
- ✅ **Seamless FastMCP Integration** - Automatic route registration
- ✅ **Full Token Lifecycle** - Refresh token support, automatic cleanup

## Motivation

### Problem 1: OAuth Provider Compatibility

Most OAuth providers (Google, GitHub, Azure, Auth0) don't support Dynamic Client Registration (DCR), which is required by the MCP specification. This prevents MCP clients from authenticating with these providers.

### Problem 2: Authorization Without Custom Claims

Without custom claims passthrough, proxy-issued tokens lack critical information (roles, permissions, groups, etc.) from upstream identity providers, making it impossible to implement authorization and RBAC in MCP tools.

### Solution

This PR provides:

1. **OAuth Proxy** - Presents a DCR-compliant interface while managing pre-registered credentials with upstream providers
2. **Custom Claims Passthrough** - Extracts and forwards custom claims from upstream tokens to proxy-issued JWTs for downstream authorization

## Implementation Details

### Architecture

```
Client → Proxy (DCR) → Upstream Provider
   ↓         ↓              ↓
  PKCE   JWT Tokens    Access Tokens
         + Claims      + ID Tokens
```

### Custom Claims Passthrough Feature

**Enabled by default** - Essential for authorization:

- Extracts custom claims from upstream access tokens and ID tokens
- Includes claims in proxy-issued JWTs for downstream authorization
- Supports roles, permissions, groups, email, and other custom claims
- Compatible with RBAC libraries and authorization frameworks

**Security Features:**

- Protected claims filtering (aud, iss, exp, iat, nbf, jti, client_id never copied)
- JWT format detection (only extracts from 3-part base64url tokens)
- Graceful opaque token handling (silently skips without errors)
- Size limits and type validation
- Configurable allowlist/blocklist

**Configuration:**

```typescript
const authProxy = new OAuthProxy({
  // ... other config ...
  customClaimsPassthrough: {
    fromAccessToken: true, // Default: true
    fromIdToken: true, // Default: true
    claimPrefix: false, // Default: false (no prefix)
    allowedClaims: ["role", "permissions"],
    blockedClaims: ["internal_id"],
    maxClaimValueSize: 2000, // Default: 2000 chars
    allowComplexClaims: false, // Default: false (primitives only)
  },
});
```

### Files Added

#### Core Implementation

- `src/auth/OAuthProxy.ts` - Main OAuth proxy implementation (956 lines)
- `src/auth/types.ts` - Type definitions (397 lines)
- `src/auth/index.ts` - Public API exports (43 lines)

#### Custom Claims Feature

- `src/auth/utils/claimsExtractor.ts` - Claims extraction and filtering (204 lines)
- `src/auth/utils/jwtIssuer.ts` - JWT signing with custom claims support (255 lines)

#### Utilities

- `src/auth/utils/pkce.ts` - PKCE challenge/verifier generation (111 lines)
- `src/auth/utils/consent.ts` - User consent screen with HTML rendering (343 lines)
- `src/auth/utils/tokenStore.ts` - Storage backends (memory, encrypted) (185 lines)
- `src/auth/utils/diskStore.ts` - Persistent filesystem storage (210 lines)
- `src/auth/utils/jwks.ts` - JWKS endpoint support (230 lines)

#### Pre-configured Providers

- `src/auth/providers/GoogleProvider.ts` - Google OAuth (27 lines)
- `src/auth/providers/GitHubProvider.ts` - GitHub OAuth (26 lines)
- `src/auth/providers/AzureProvider.ts` - Azure/Entra ID OAuth (33 lines)

#### FastMCP Integration

- `src/FastMCP.ts` - Extended with OAuth support and automatic route registration (570+ lines added)
- `src/DiscoveryDocumentCache.ts` - OAuth discovery document caching (121 lines)

#### Tests

- `src/auth/OAuthProxy.token-swap.test.ts` - Token swap tests (326 lines)
- `src/auth/utils/jwtIssuer.test.ts` - JWT issuer tests (251 lines)
- `src/auth/utils/pkce.test.ts` - PKCE tests (119 lines)
- `src/auth/utils/tokenStore.test.ts` - Storage tests (151 lines)
- `src/auth/utils/diskStore.test.ts` - Disk storage tests (204 lines)
- `src/FastMCP.oauth-proxy.test.ts` - Integration tests (187 lines)
- `src/FastMCP.test.ts` - Extended with OAuth tests (602+ lines)
- `src/DiscoveryDocumentCache.test.ts` - Cache tests (342 lines)

#### Examples

- `src/examples/oauth-integrated-server.ts` - Complete integration example (116 lines)
- `src/examples/oauth-proxy-server.ts` - Standalone proxy (92 lines)
- `src/examples/oauth-proxy-github.ts` - GitHub provider example (56 lines)
- `src/examples/oauth-proxy-custom.ts` - Custom provider example (55 lines)
- `src/examples/oauth-jwks-example.ts` - JWKS endpoint example (257 lines)

#### Documentation

- `docs/OAUTH-PROXY.md` - Main documentation with quick start (340 lines)
- `docs/oauth-proxy-features.md` - Complete feature reference (402 lines)
- `docs/oauth-proxy-guide.md` - Implementation guide with examples (966 lines)
- `docs/oauth-advanced-features.md` - Advanced patterns (361 lines)
- `docs/oauth-python-typescript.md` - Python/TypeScript comparison (583 lines)
- `README.md` - Updated with OAuth section (144+ lines added)

### API Changes

**No breaking changes** - All changes are additive.

#### New FastMCP Configuration

```typescript
const server = new FastMCP({
  name: "My Server",
  oauth: {
    enabled: true,
    authorizationServer: authProxy.getAuthorizationServerMetadata(),
    proxy: authProxy, // Automatic route registration!
  },
});
```

#### New Public Exports

```typescript
// Main proxy
export { OAuthProxy } from "./auth/OAuthProxy.js";

// Pre-configured providers
export { GoogleProvider } from "./auth/providers/GoogleProvider.js";
export { GitHubProvider } from "./auth/providers/GitHubProvider.js";
export { AzureProvider } from "./auth/providers/AzureProvider.js";

// Utilities
export { JWTIssuer } from "./auth/utils/jwtIssuer.js";
export { DiskStore } from "./auth/utils/diskStore.js";
export {
  EncryptedTokenStorage,
  MemoryTokenStorage,
} from "./auth/utils/tokenStore.js";

// Types
export type {
  OAuthProxyConfig,
  CustomClaimsPassthroughConfig,
  TokenStorage,
  // ... other types
} from "./auth/types.js";
```

## Usage Examples

### Basic Setup with Custom Claims (Default)

```typescript
import { FastMCP } from "fastmcp";
import { GoogleProvider } from "fastmcp/auth";

// Create OAuth proxy with claims passthrough enabled by default
const authProxy = new GoogleProvider({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  baseUrl: "https://your-server.com",
});

// Configure FastMCP with OAuth
const server = new FastMCP({
  name: "My Server",
  oauth: {
    enabled: true,
    authorizationServer: authProxy.getAuthorizationServerMetadata(),
    proxy: authProxy, // Routes auto-register!
  },
});

// Use claims for authorization
server.addTool({
  name: "admin-action",
  description: "Admin-only action",
  canAccess: async ({ session }) => {
    const token = session?.headers?.["authorization"]?.replace("Bearer ", "");
    if (!token) return false;

    const payload = JSON.parse(
      Buffer.from(token.split(".")[1], "base64url").toString(),
    );

    // Check role claim from upstream IDP
    return payload.role === "admin";
  },
  execute: async () => {
    return { content: [{ type: "text", text: "Admin action completed" }] };
  },
});

await server.start({
  transportType: "httpStream",
  httpStream: { port: 3000 },
});
```

### Custom Claims Configuration

```typescript
import { OAuthProxy } from "fastmcp/auth";

const authProxy = new OAuthProxy({
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
  upstreamClientId: process.env.OAUTH_CLIENT_ID,
  upstreamClientSecret: process.env.OAUTH_CLIENT_SECRET,
  baseUrl: "https://your-server.com",

  // Configure claims passthrough
  customClaimsPassthrough: {
    fromAccessToken: true,
    fromIdToken: true,
    allowedClaims: ["role", "permissions", "email", "groups"],
    blockedClaims: ["internal_id"],
    maxClaimValueSize: 2000,
  },
});
```

### Production Setup with Encryption

```typescript
import { OAuthProxy, DiskStore, JWTIssuer } from "fastmcp/auth";

const authProxy = new OAuthProxy({
  baseUrl: "https://your-server.com",
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
  upstreamClientId: process.env.OAUTH_CLIENT_ID,
  upstreamClientSecret: process.env.OAUTH_CLIENT_SECRET,

  // Persistent storage
  tokenStorage: new DiskStore({
    directory: "/var/lib/fastmcp/oauth",
  }),

  // Custom signing key
  jwtSigningKey: await JWTIssuer.deriveKey(process.env.JWT_SECRET, 100000),

  // Custom encryption key
  encryptionKey: await JWTIssuer.deriveKey(
    process.env.ENCRYPTION_SECRET + ":storage",
    100000,
  ),

  // User consent required
  consentRequired: true,

  // Claims passthrough (enabled by default)
  customClaimsPassthrough: {
    allowedClaims: ["role", "permissions", "email", "groups", "tenant"],
  },
});
```

## Testing

### Test Coverage

- ✅ OAuth proxy core functionality (token exchange, refresh, validation)
- ✅ Custom claims extraction and filtering
- ✅ JWT token issuance with additional claims
- ✅ PKCE generation and validation
- ✅ Token storage (memory, disk, encrypted)
- ✅ FastMCP integration and route registration
- ✅ Discovery document caching
- ✅ Pre-configured providers

### Running Tests

```bash
# All tests
npm test

# OAuth tests only
npm test -- auth/

# Specific test file
npm test -- src/auth/OAuthProxy.token-swap.test.ts

# Build
npm run build
```

All tests pass ✅

## Security Considerations

### Custom Claims Passthrough Security

1. **Protected Claims Filtering** - Standard JWT claims are never copied from upstream
2. **JWT Detection** - Only extracts from JWT-format tokens (3-part base64url)
3. **Size Limits** - Configurable maximum claim value size (default: 2000 chars)
4. **Type Validation** - Validates claim values before inclusion
5. **No Signature Verification Needed** - Server-to-server trust (token received via trusted HTTPS channel)

### General OAuth Security

1. **Two-Tier PKCE** - Protection at both client-proxy and proxy-upstream levels
2. **User Consent Flow** - Prevents confused deputy attacks (can be disabled for trusted environments)
3. **Token Encryption** - AES-256-GCM encryption at rest (enabled by default)
4. **Short-lived JWTs** - 1-hour access tokens, 30-day refresh tokens
5. **One-time Codes** - Authorization codes deleted after use
6. **State Validation** - CSRF protection
7. **Redirect URI Validation** - Configurable allowlist patterns

### Production Checklist

- [ ] Use HTTPS for all endpoints (required)
- [ ] Enable consent screen (`consentRequired: true`)
- [ ] Use persistent storage (DiskStore)
- [ ] Provide custom signing/encryption keys
- [ ] Configure `allowedClaims` for claims passthrough
- [ ] Configure allowed redirect URI patterns
- [ ] Use strong secrets (minimum 32 bytes)
- [ ] Implement rate limiting
- [ ] Monitor cleanup operations

## Breaking Changes

**None** - This PR is purely additive. All new functionality is opt-in via the `oauth` configuration option.

## Documentation

Comprehensive documentation added:

- **Main Guide**: [docs/OAUTH-PROXY.md](docs/OAUTH-PROXY.md) - Quick start and overview
- **Features**: [docs/oauth-proxy-features.md](docs/oauth-proxy-features.md) - Complete feature reference
- **Implementation Guide**: [docs/oauth-proxy-guide.md](docs/oauth-proxy-guide.md) - Step-by-step setup
- **Advanced Features**: [docs/oauth-advanced-features.md](docs/oauth-advanced-features.md) - Token swap, encryption, storage
- **Python Comparison**: [docs/oauth-python-typescript.md](docs/oauth-python-typescript.md) - Migration guide

Working examples in [src/examples/](src/examples/)

## Migration Guide

Not applicable - this is a new feature with no breaking changes.

For users wanting to add OAuth to existing servers:

```typescript
// Before
const server = new FastMCP({ name: "My Server" });

// After
import { GoogleProvider } from "fastmcp/auth";

const authProxy = new GoogleProvider({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  baseUrl: "https://your-server.com",
});

const server = new FastMCP({
  name: "My Server",
  oauth: {
    enabled: true,
    authorizationServer: authProxy.getAuthorizationServerMetadata(),
    proxy: authProxy,
  },
});
```

## Related Issues

- Enables MCP servers to work with traditional OAuth providers (Google, GitHub, Azure, Auth0, etc.)
- Provides authorization and RBAC capabilities via custom claims passthrough
- Maintains FastMCP's Python-style ease of use with automatic route registration

## Checklist

- [x] Tests pass locally
- [x] Build succeeds (`npm run build`)
- [x] No breaking changes
- [x] Documentation added/updated
- [x] Examples provided
- [x] TypeScript types exported
- [x] Security considerations documented
- [x] Production checklist provided

## Future Enhancements

Potential follow-up work (not in this PR):

- [ ] RS256/ES256 JWT signing support (currently HS256 only)
- [ ] Token revocation endpoint
- [ ] Redis storage backend for distributed deployments
- [ ] Additional pre-configured providers (Auth0, Okta, Keycloak)
- [ ] Distributed locking for multi-server deployments
- [ ] OAuth 2.0 introspection endpoint
- [ ] Metrics and observability hooks

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
