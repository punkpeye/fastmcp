# OAuth Proxy for FastMCP

The OAuth Proxy enables FastMCP servers to authenticate with traditional OAuth providers that don't support Dynamic Client Registration (DCR) by presenting a DCR-compliant interface to MCP clients while using pre-registered credentials with upstream providers.

## Documentation

This is the main entry point for OAuth Proxy documentation. For detailed information, see:

### 📚 Core Documentation

1. **[OAuth Proxy Features](oauth-proxy-features.md)**
   - Complete feature overview
   - Security features and capabilities
   - Token management options
   - Storage backends
   - Advanced features

2. **[Implementation Guide](oauth-proxy-guide.md)**
   - Quick start examples
   - Provider setup (Google, GitHub, Azure)
   - Configuration options
   - Advanced features (token swap, encryption)
   - Security best practices
   - Troubleshooting

3. **[Python vs TypeScript Comparison](oauth-python-typescript.md)**
   - Feature parity matrix
   - API differences
   - Migration guide
   - Default behavior differences
   - When to choose each implementation

### 🔗 Additional Resources

- **[Advanced Features](oauth-advanced-features.md)** - Detailed coverage of:
  - Persistent token storage (DiskStore)
  - JWT token issuance
  - Token swap pattern
  - Encrypted storage

- **[Example Implementations](../src/examples/)**
  - [`oauth-integrated-server.ts`](../src/examples/oauth-integrated-server.ts) - Complete FastMCP integration
  - [`oauth-proxy-server.ts`](../src/examples/oauth-proxy-server.ts) - Standalone proxy
  - [`oauth-proxy-github.ts`](../src/examples/oauth-proxy-github.ts) - GitHub provider
  - [`oauth-proxy-custom.ts`](../src/examples/oauth-proxy-custom.ts) - Custom provider

## Quick Start

### Seamless Integration (Just 2 Steps!)

```typescript
import { FastMCP, getAuthSession, GoogleProvider, requireAuth } from "fastmcp";

// 1. Create FastMCP with OAuth provider
const server = new FastMCP({
  auth: new GoogleProvider({
    baseUrl: "https://your-server.com",
    clientId: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  }),
  name: "My Server",
  version: "1.0.0",
});

// 2. Add protected tools
server.addTool({
  canAccess: requireAuth,
  description: "Get user profile",
  execute: async (_args, { session }) => {
    const { accessToken } = getAuthSession(session);
    const response = await fetch(
      "https://www.googleapis.com/oauth2/v2/userinfo",
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      },
    );
    return JSON.stringify(await response.json());
  },
  name: "get-profile",
});

await server.start({
  transportType: "httpStream",
  httpStream: { port: 3000 },
});
```

**That's it!** All OAuth endpoints are automatically registered:

- `/oauth/register` - DCR endpoint
- `/oauth/authorize` - Authorization endpoint
- `/oauth/token` - Token exchange
- `/oauth/callback` - OAuth callback handler
- `/oauth/consent` - User consent screen

No manual route setup required - exactly like Python FastMCP! 🎉

## Available Providers

### Pre-configured Providers

#### Google

```typescript
import { FastMCP, GoogleProvider } from "fastmcp";

const server = new FastMCP({
  auth: new GoogleProvider({
    baseUrl: "https://your-server.com",
    clientId: "xxx.apps.googleusercontent.com",
    clientSecret: "your-secret",
  }),
  name: "My Server",
  version: "1.0.0",
});
```

**Setup:** [Google Cloud Console](https://console.cloud.google.com/apis/credentials)

#### GitHub

```typescript
import { FastMCP, GitHubProvider } from "fastmcp";

const server = new FastMCP({
  auth: new GitHubProvider({
    baseUrl: "https://your-server.com",
    clientId: "your-github-app-id",
    clientSecret: "your-github-app-secret",
  }),
  name: "My Server",
  version: "1.0.0",
});
```

**Setup:** [GitHub Developer Settings](https://github.com/settings/developers)

#### Azure/Entra ID

```typescript
import { FastMCP, AzureProvider } from "fastmcp";

const server = new FastMCP({
  auth: new AzureProvider({
    baseUrl: "https://your-server.com",
    clientId: "your-azure-app-id",
    clientSecret: "your-azure-app-secret",
    tenantId: "common",
  }),
  name: "My Server",
  version: "1.0.0",
});
```

**Setup:** [Azure Portal](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)

### Custom Provider

For any OAuth 2.0 provider (SAP, Auth0, Okta, etc.):

```typescript
import { FastMCP, OAuthProvider } from "fastmcp";

const server = new FastMCP({
  auth: new OAuthProvider({
    authorizationEndpoint: "https://provider.com/oauth/authorize",
    baseUrl: "https://your-server.com",
    clientId: process.env.OAUTH_CLIENT_ID!,
    clientSecret: process.env.OAUTH_CLIENT_SECRET!,
    scopes: ["openid", "profile"],
    tokenEndpoint: "https://provider.com/oauth/token",
  }),
  name: "My Server",
  version: "1.0.0",
});
```

## How It Works

```
1. Client → Proxy: DCR registration request
   Proxy responds with fixed credentials

2. Client → Proxy: Authorization request with PKCE
   Proxy generates own PKCE for upstream

3. Proxy → User: Consent screen (prevents confused deputy)
   User approves authorization

4. Proxy → Upstream: Authorization with proxy PKCE
   User authenticates with provider

5. Upstream → Proxy: Authorization code
   Proxy exchanges for tokens

6. Proxy → Client: Client authorization code
   Client exchanges for tokens

7. Client → Proxy: Token exchange with PKCE verifier
   Proxy validates and returns tokens
```

## Key Features

- ✅ **Dynamic Client Registration (DCR)** - RFC 7591 compliant
- ✅ **Two-Tier PKCE** - Client-to-proxy and proxy-to-upstream
- ✅ **User Consent Flow** - Prevents confused deputy attacks
- ✅ **Token Swap Pattern** - Enhanced security mode
- ✅ **Custom Claims Passthrough** - RBAC & authorization support (enabled by default)
- ✅ **Flexible Storage** - Memory, disk, encrypted, custom
- ✅ **OAuth 2.1 Compliance** - Modern security standards
- ✅ **Automatic Cleanup** - TTL-based expiration
- ✅ **Pre-configured Providers** - Google, GitHub, Azure
- ✅ **Refresh Token Support** - Full token lifecycle
- ✅ **FastMCP Integration** - Seamless automatic setup

## Protecting Tools with OAuth

Use the built-in authorization helpers:

```typescript
import {
  requireAuth,
  requireScopes,
  requireRole,
  requireAll,
  requireAny,
  getAuthSession,
} from "fastmcp";

// Require any authenticated user
server.addTool({
  canAccess: requireAuth,
  description: "Get authenticated user data",
  execute: async (_args, { session }) => {
    const { accessToken } = getAuthSession(session);
    const response = await fetch("https://api.provider.com/user", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    return JSON.stringify(await response.json(), null, 2);
  },
  name: "get-user-data",
});

// Require specific scopes
server.addTool({
  canAccess: requireScopes("read:data", "write:data"),
  description: "Access data with required scopes",
  execute: async () => "Scoped access granted!",
  name: "scoped-data",
});

// Require specific role
server.addTool({
  canAccess: requireRole("admin"),
  description: "Admin-only tool",
  execute: async () => "Admin access granted!",
  name: "admin-tool",
});

// Combine with AND/OR logic
server.addTool({
  canAccess: requireAll(
    requireAuth,
    requireAny(requireRole("admin"), requireRole("moderator")),
  ),
  description: "Staff-only tool",
  execute: async () => "Staff access granted!",
  name: "staff-tool",
});

// Note: getAuthSession throws if session is not authenticated,
// so it's safe to use when canAccess: requireAuth is set
```

## Security Features

### Two-Tier PKCE

- Client-to-proxy PKCE validation
- Proxy-to-upstream PKCE protection
- Prevents authorization code interception

### User Consent Flow

- Prevents confused deputy attacks
- Shows clear scope permissions
- Signed consent cookies (5-minute TTL)
- Can be disabled for trusted environments

### Token Security

- Optional encryption at rest (AES-256-GCM)
- Automatic expiration and cleanup
- Secure random ID generation
- One-time authorization codes

### OAuth 2.1 Compliance

- PKCE required by default
- State parameter validation
- Redirect URI validation
- Standard error responses

## Production Checklist

- [ ] Use HTTPS for all endpoints
- [ ] Enable consent screen (`consentRequired: true`)
- [ ] Use persistent storage (DiskStore)
- [ ] Enable encrypted storage
- [ ] Derive signing keys from secrets
- [ ] Configure allowed redirect URI patterns
- [ ] Use strong secrets (minimum 32 bytes)
- [ ] Set appropriate TTL values
- [ ] Configure custom claims passthrough (enabled by default)
- [ ] Implement rate limiting
- [ ] Monitor cleanup operations

## Testing

```bash
# All tests
npm test

# OAuth tests only
npm test -- auth/

# Build
npm run build
```

## Migration from Python FastMCP

The TypeScript implementation now matches Python FastMCP's simplicity:

**Python:**

```python
from fastmcp import FastMCP
from fastmcp.server.auth import OAuthProxy

auth = OAuthProxy(
    upstream_authorization_endpoint="...",
    upstream_token_endpoint="...",
    upstream_client_id="...",
    upstream_client_secret="...",
    base_url="..."
)
mcp = FastMCP(name="My Server", auth=auth)
```

**TypeScript:**

```typescript
import { FastMCP, OAuthProvider } from "fastmcp";

const server = new FastMCP({
  auth: new OAuthProvider({
    authorizationEndpoint: "...",
    baseUrl: "...",
    clientId: "...",
    clientSecret: "...",
    tokenEndpoint: "...",
  }),
  name: "My Server",
  version: "1.0.0",
});
```

Both approaches now:

- Use a simple `auth` option
- Auto-configure OAuth endpoints
- Provide session with upstream access token

See [Python vs TypeScript Comparison](oauth-python-typescript.md) for detailed migration guidance.

## Troubleshooting

### "Invalid redirect URI" error

Ensure the redirect URI registered with your OAuth provider matches:

```
{baseUrl}/oauth/callback
```

### "Invalid state" error

- Transaction expired (default 10 minutes)
- Server restarted (use persistent storage)
- Clock skew between client and server

### "PKCE validation failed"

Ensure client is sending the correct `code_verifier` that matches the `code_challenge`.

See [Implementation Guide](oauth-proxy-guide.md#troubleshooting) for more solutions.

## References

- [RFC 6749: OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [RFC 7591: OAuth 2.0 Dynamic Client Registration](https://tools.ietf.org/html/rfc7591)
- [RFC 7636: PKCE](https://tools.ietf.org/html/rfc7636)
- [RFC 8414: OAuth 2.0 Authorization Server Metadata](https://tools.ietf.org/html/rfc8414)
- [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-07)

## Support

For issues, questions, or contributions:

- Report bugs in the [issue tracker](https://github.com/your-org/fastmcp/issues)
- Check [examples](../src/examples/) for working code
- Review [documentation](oauth-proxy-guide.md) for detailed guidance
