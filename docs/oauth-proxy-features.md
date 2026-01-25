# OAuth Proxy Features

The FastMCP OAuth Proxy enables MCP servers to authenticate with traditional OAuth providers that don't support Dynamic Client Registration (DCR). It acts as a transparent intermediary, presenting a DCR-compliant interface to MCP clients while managing pre-registered credentials with upstream providers.

## Core Features

### 1. OAuth 2.1 Proxy Architecture

The proxy bridges the gap between:

- **MCP clients** expecting RFC 7591 Dynamic Client Registration
- **Traditional OAuth providers** (Google, GitHub, Azure, Auth0, etc.) requiring manual app registration

It transparently handles the entire OAuth flow while maintaining security and RFC compliance.

### 2. Dynamic Client Registration (DCR)

Implements RFC 7591 to provide DCR capabilities:

- Accepts client registration requests
- Returns fixed credentials (single pre-registered app)
- Stores client callback URLs for OAuth redirects
- No actual upstream registration required

### 3. Two-Tier PKCE Security

Enhanced security through dual PKCE validation:

- **Client-to-Proxy PKCE**: Validates client's code verifier
- **Proxy-to-Upstream PKCE**: Protects communication with OAuth provider
- Supports both S256 (SHA-256) and plain challenge methods
- Prevents authorization code interception attacks

### 4. User Consent Flow

Built-in consent screen prevents confused deputy attacks:

- Shows clear authorization details and requested scopes
- Signed consent cookies with HMAC-SHA256
- Configurable 5-minute consent TTL
- Can be disabled for trusted development environments
- XSS-protected HTML rendering

### 5. Token Management

#### Flexible Storage Options

- **MemoryTokenStorage**: Fast in-memory storage for development
- **DiskStore**: Persistent filesystem storage with automatic cleanup
- **EncryptedTokenStorage**: AES-256-GCM encryption wrapper
- Custom storage backends via `TokenStorage` interface

#### Token Swap Pattern (Enhanced Security - Default Mode)

Enabled by default for enhanced security:

- Issues short-lived FastMCP JWTs to clients (1 hour default)
- Stores upstream provider tokens securely on the server
- Maps JWT IDs (JTI) to upstream tokens
- Supports automatic token refresh
- Prevents token leakage to clients
- Auto-generates JWT signing key if not provided

#### Passthrough Mode (Optional)

When token swap is disabled (`enableTokenSwap: false`):

- Returns upstream provider tokens directly to clients
- Simpler architecture for trusted environments
- Client manages token lifecycle
- Useful for debugging and development

### 6. JWT Token Issuance

Built-in JWT issuer for token swap pattern:

- HMAC-SHA256 (HS256) signing
- Configurable access token TTL (default: 1 hour)
- Configurable refresh token TTL (default: 30 days)
- PBKDF2 key derivation from secrets
- Issuer/audience validation
- Automatic expiration checking
- Custom claims passthrough from upstream tokens (enabled by default)

### 6a. Custom Claims Passthrough

**Enabled by default** - Essential for authorization and RBAC:

- Extracts custom claims from upstream access tokens and ID tokens
- Includes claims in proxy-issued JWTs for downstream authorization
- Supports roles, permissions, groups, email, and other custom claims
- Compatible with RBAC libraries and authorization frameworks

#### Security Features

- **Protected claims filtering**: Standard JWT claims (aud, iss, exp, iat, nbf, jti, client_id) are never copied
- **JWT detection**: Only extracts from JWT-format tokens (3-part base64url)
- **Graceful handling**: Silently skips opaque tokens without errors
- **Size limits**: Configurable claim value size limits (default: 2000 chars)
- **Type validation**: Validates claim values before inclusion

#### Configuration Options

```typescript
const authProxy = new OAuthProxy({
  // ... other config ...
  customClaimsPassthrough: {
    // Extract from access token (default: true)
    fromAccessToken: true,

    // Extract from ID token (default: true)
    fromIdToken: true,

    // Add prefix to claim names (default: false/no prefix)
    // Example: 'upstream_' → claims become 'upstream_role', 'upstream_email'
    claimPrefix: false,

    // Only include specific claims (optional allowlist)
    allowedClaims: ['role', 'permissions', 'email', 'groups'],

    // Block specific claims (optional blocklist)
    blockedClaims: ['internal_id'],

    // Maximum size for claim values in characters (default: 2000)
    maxClaimValueSize: 2000,

    // Allow complex objects/arrays (default: false, primitives only)
    allowComplexClaims: false,
  },
});

// Shorthand: boolean enables/disables with defaults
customClaimsPassthrough: true,  // Enable with defaults
customClaimsPassthrough: false, // Disable feature
```

#### Token Precedence

When both access token and ID token contain claims:

- Access token claims take precedence
- ID token claims are merged (non-overlapping only)
- This ensures the most authoritative claims are used

#### Use Cases

- **RBAC Authorization**: Pass user roles from Entra ID/Auth0 to MCP tools
- **Permission Checks**: Use fine-grained permissions from upstream provider
- **User Context**: Include email, name, groups for audit logging
- **Multi-tenancy**: Pass tenant/organization claims for data isolation
- **Custom Attributes**: Forward any custom claims from your identity provider

#### Example: Authorization with Custom Claims

```typescript
// Tool with role-based access control
server.addTool({
  name: "admin-action",
  description: "Perform admin action",
  canAccess: async ({ session }) => {
    const token = session?.headers?.["authorization"]?.replace("Bearer ", "");
    if (!token) return false;

    // Decode proxy JWT (contains custom claims from upstream)
    const payload = JSON.parse(
      Buffer.from(token.split(".")[1], "base64url").toString(),
    );

    // Check role claim passed through from upstream IDP
    return payload.role === "admin" || payload.roles?.includes("admin");
  },
  execute: async (args) => {
    // Execute admin action
    return { content: [{ type: "text", text: "Admin action completed" }] };
  },
});
```

### 7. Pre-configured Providers

Ready-to-use provider implementations:

#### GoogleProvider

- Endpoint: `https://accounts.google.com/o/oauth2/v2/auth`
- Token: `https://oauth2.googleapis.com/token`
- Default scopes: `openid`, `profile`, `email`

#### GitHubProvider

- Endpoint: `https://github.com/login/oauth/authorize`
- Token: `https://github.com/login/oauth/access_token`
- Default scopes: `read:user`, `user:email`

#### AzureProvider (Entra ID)

- Endpoint: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize`
- Token: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`
- Default scopes: `openid`, `profile`, `email`
- Supports multi-tenant (`common`) or specific tenant IDs

### 8. Automatic Cleanup

Background processes maintain system health:

- Expired transactions automatically removed
- Authorization codes deleted after use or expiration
- Token mappings cleaned up based on TTL
- Configurable cleanup intervals (default: 60 seconds)

### 9. OAuth Endpoints

All standard OAuth 2.1 endpoints:

| Endpoint                                  | Method   | Purpose                              |
| ----------------------------------------- | -------- | ------------------------------------ |
| `/oauth/register`                         | POST     | RFC 7591 Dynamic Client Registration |
| `/oauth/authorize`                        | GET      | OAuth authorization initiation       |
| `/oauth/callback`                         | GET      | OAuth provider callback handler      |
| `/oauth/consent`                          | GET/POST | User consent screen                  |
| `/oauth/token`                            | POST     | Token exchange and refresh           |
| `/.well-known/oauth-authorization-server` | GET      | OAuth discovery metadata             |

### 10. Security Features

#### State Management

- Cryptographically secure state parameters
- State validation on callbacks
- Transaction-based flow tracking

#### Redirect URI Validation

- Configurable allowlist patterns
- Wildcard support (e.g., `https://*.example.com/*`)
- Localhost support for development

#### Token Security

- One-time authorization codes
- Secure random ID generation (crypto.randomUUID)
- TTL-based automatic expiration
- Optional encryption at rest

#### OAuth 2.1 Compliance

- PKCE required by default
- State parameter validation
- Standard error responses
- Authorization server metadata discovery

### 11. Advanced Features

#### Persistent Storage (DiskStore)

- File-based token persistence
- Survives server restarts
- Configurable directory location
- Automatic TTL-based cleanup
- Key sanitization against directory traversal

#### Encrypted Storage

- AES-256-GCM encryption
- Scrypt-based key derivation
- Authentication tag verification
- Transparent encrypt/decrypt wrapper

#### Custom Token Storage

Implement the `TokenStorage` interface:

```typescript
interface TokenStorage {
  save(key: string, value: unknown, ttl?: number): Promise<void>;
  get(key: string): Promise<unknown | null>;
  delete(key: string): Promise<void>;
  cleanup(): Promise<void>;
}
```

#### Forward PKCE Mode

Optional PKCE forwarding to upstream provider:

- `forwardPkce: false` (default): Proxy generates own PKCE
- `forwardPkce: true`: Forwards client's PKCE to upstream

### 12. Refresh Token Support

Full refresh token lifecycle:

- Exchanges refresh tokens with upstream provider
- Returns new access tokens to clients
- Maintains refresh token mappings (token swap mode)
- Automatic expiration handling

### 13. Scope Management

Flexible scope handling:

- Configure default scopes per provider
- Supports scope intersection with client requests
- Clear scope display in consent screen
- Forwards scopes to upstream provider

### 14. Error Handling

Standardized OAuth error responses:

- `OAuthProxyError` class for consistent errors
- RFC-compliant error codes and descriptions
- Clear error messages for debugging
- Proper HTTP status codes

### 15. Discovery Metadata

RFC 8414 Authorization Server Metadata:

- Advertises supported grant types
- Lists available endpoints
- Declares PKCE support
- Provides issuer information

## Performance Characteristics

- **Startup time**: Instant (no warm-up required)
- **OAuth flow latency**: <100ms (local testing)
- **Memory footprint**: Lightweight (~10MB base)
- **Storage overhead**: Minimal (transactions + tokens)
- **Cleanup efficiency**: Background process, non-blocking

## Integration Points

### FastMCP Server Integration

Use the `auth` option for seamless OAuth integration:

```typescript
import { FastMCP, GoogleProvider, requireAuth } from "fastmcp";

const server = new FastMCP({
  auth: new GoogleProvider({
    baseUrl: "https://your-server.com",
    clientId: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  }),
  name: "My Server",
  version: "1.0.0",
});
```

- No manual route setup required
- Seamless Python-style API
- Automatic endpoint registration

### Session Integration

OAuth tokens available in tool execution context via `getAuthSession`:

```typescript
import {
  requireAuth,
  requireScopes,
  requireRole,
  getAuthSession,
} from "fastmcp";

server.addTool({
  canAccess: requireAuth, // Or: requireScopes("read"), requireRole("admin")
  execute: async (_args, { session }) => {
    const { accessToken } = getAuthSession(session);
    const response = await fetch("https://api.provider.com/data", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    return JSON.stringify(await response.json());
  },
  name: "get-data",
});
```

- Use built-in helpers: `requireAuth`, `requireScopes`, `requireRole`, `getAuthSession`
- Combine with `requireAll` and `requireAny` for complex logic
- Access upstream token via `getAuthSession(session).accessToken`

### Transport Compatibility

Works with FastMCP HTTP transport:

- Requires `httpStream` transport type
- Compatible with existing MCP infrastructure
- No special middleware needed

## Extensibility

### Custom Providers

Extend `OAuthProxy` class:

- Override configuration for new providers
- Add provider-specific logic
- Maintain consistent interface

### Storage Backends

Implement `TokenStorage` for custom backends:

- Redis for distributed deployments
- Database storage for persistence
- Cloud storage services

### Token Verification

Implement `TokenVerifier` interface:

- Custom JWT validation logic
- Support for RS256/ES256 algorithms
- JWKS (JSON Web Key Set) integration

## Monitoring and Observability

Built-in debugging capabilities:

- Detailed error messages with context
- Transaction state tracking
- Token lifecycle visibility
- Cleanup operation logging

## Limitations

### Current Scope

- Server-side proxy only (no client-side OAuth handler)
- HS256 JWT signing only (no RS256/ES256 yet)
- No built-in token revocation endpoint
- No built-in distributed locking for multi-server deployments

### Storage Considerations

- In-memory storage doesn't persist across restarts
- DiskStore is single-server only (no distributed support)
- Large-scale deployments may need Redis/database backends

### Provider Support

- Pre-configured providers: Google, GitHub, Azure
- Other providers require manual configuration
- Some providers may have specific quirks requiring custom handling

## Security Considerations

### Production Checklist

- [ ] Use HTTPS for all endpoints (required for OAuth 2.0)
- [ ] Enable consent screen (`consentRequired: true`)
- [ ] Use persistent storage (DiskStore or custom)
- [ ] Wrap storage with encryption (`EncryptedTokenStorage`)
- [ ] Derive signing keys from secrets (`JWTIssuer.deriveKey()`)
- [ ] Configure allowed redirect URI patterns
- [ ] Use strong secrets (minimum 32 bytes)
- [ ] Set appropriate TTL values
- [ ] Implement rate limiting on token endpoints
- [ ] Monitor cleanup operations
- [ ] Implement proper key rotation procedures

### Threat Mitigation

- **Confused Deputy**: User consent screen
- **Code Interception**: Two-tier PKCE
- **Token Theft**: Short-lived JWTs, encryption at rest
- **XSS**: HTML escaping in consent screen
- **CSRF**: State parameter validation
- **Replay Attacks**: One-time authorization codes
- **Directory Traversal**: Key sanitization in storage

## Comparison with Other Solutions

### vs. Native DCR

**Advantage**: Works with providers that don't support DCR
**Trade-off**: Requires pre-registration and proxy management

### vs. Direct OAuth Integration

**Advantage**: Provides DCR interface to clients
**Trade-off**: Additional proxy layer

### vs. Auth Middleware

**Advantage**: MCP-specific, handles full OAuth lifecycle
**Trade-off**: Focused on MCP use case only
