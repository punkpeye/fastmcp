# OAuth Proxy Implementation Guide

This guide shows you how to implement OAuth authentication in your FastMCP server using the OAuth Proxy.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Provider Setup](#provider-setup)
3. [Configuration Options](#configuration-options)
4. [Advanced Features](#advanced-features)
5. [Security Best Practices](#security-best-practices)
6. [Troubleshooting](#troubleshooting)

## Quick Start

### Basic Setup with Pre-configured Provider

The simplest way to add OAuth is using a pre-configured provider:

```typescript
import { FastMCP } from "fastmcp";
import { GoogleProvider } from "fastmcp/auth";

const authProxy = new GoogleProvider({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  baseUrl: "https://your-server.com",
  scopes: ["openid", "profile", "email"],
});

const server = new FastMCP({
  name: "My Server",
  oauth: {
    enabled: true,
    authorizationServer: authProxy.getAuthorizationServerMetadata(),
    proxy: authProxy, // Routes automatically registered!
  },
});

await server.start({
  transportType: "httpStream",
  httpStream: { port: 3000 },
});
```

**That's it!** All OAuth endpoints are automatically available:
- `/oauth/register` - Dynamic Client Registration
- `/oauth/authorize` - Authorization endpoint
- `/oauth/callback` - OAuth callback handler
- `/oauth/consent` - User consent screen
- `/oauth/token` - Token exchange endpoint

### Custom OAuth Provider

For providers without pre-built support:

```typescript
import { FastMCP } from "fastmcp";
import { OAuthProxy } from "fastmcp/auth";

const authProxy = new OAuthProxy({
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
  upstreamClientId: process.env.OAUTH_CLIENT_ID,
  upstreamClientSecret: process.env.OAUTH_CLIENT_SECRET,
  baseUrl: "https://your-server.com",
  scopes: ["openid", "profile"],
});

const server = new FastMCP({
  name: "My Server",
  oauth: {
    enabled: true,
    authorizationServer: authProxy.getAuthorizationServerMetadata(),
    proxy: authProxy,
  },
});

await server.start({
  transportType: "httpStream",
  httpStream: { port: 3000 },
});
```

## Provider Setup

### Google OAuth

**1. Create OAuth 2.0 Credentials**
- Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
- Create OAuth 2.0 Client ID
- Application type: "Web application"
- Add authorized redirect URI: `https://your-server.com/oauth/callback`

**2. Implementation**
```typescript
import { GoogleProvider } from "fastmcp/auth";

const authProxy = new GoogleProvider({
  clientId: "xxx.apps.googleusercontent.com",
  clientSecret: "your-secret",
  baseUrl: "https://your-server.com",
  scopes: ["openid", "profile", "email"],
});
```

**Common Scopes:**
- `openid` - OpenID Connect authentication
- `profile` - Basic profile information
- `email` - Email address
- `https://www.googleapis.com/auth/userinfo.profile` - Full profile
- `https://www.googleapis.com/auth/gmail.readonly` - Gmail read access

### GitHub OAuth

**1. Create OAuth App**
- Go to [GitHub Developer Settings](https://github.com/settings/developers)
- Click "New OAuth App"
- Set Authorization callback URL: `https://your-server.com/oauth/callback`

**2. Implementation**
```typescript
import { GitHubProvider } from "fastmcp/auth";

const authProxy = new GitHubProvider({
  clientId: "your-github-app-id",
  clientSecret: "your-github-app-secret",
  baseUrl: "https://your-server.com",
  scopes: ["read:user", "user:email"],
});
```

**Common Scopes:**
- `read:user` - Read user profile data
- `user:email` - Access email addresses
- `repo` - Access repositories
- `read:org` - Read organization membership

### Azure/Entra ID

**1. Register Application**
- Go to [Azure Portal](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
- Click "New registration"
- Add redirect URI: `https://your-server.com/oauth/callback`
- Create a client secret under "Certificates & secrets"

**2. Implementation**
```typescript
import { AzureProvider } from "fastmcp/auth";

const authProxy = new AzureProvider({
  clientId: "your-azure-app-id",
  clientSecret: "your-azure-app-secret",
  baseUrl: "https://your-server.com",
  tenantId: "common", // or specific tenant ID
  scopes: ["openid", "profile", "email"],
});
```

**Tenant Options:**
- `common` - Multi-tenant, allows any Azure AD account
- `organizations` - Any organizational account
- `consumers` - Personal Microsoft accounts only
- `<tenant-id>` - Specific tenant only

**Common Scopes:**
- `openid` - OpenID Connect
- `profile` - User profile
- `email` - Email address
- `User.Read` - Read user profile
- `Mail.Read` - Read user's mail

## Configuration Options

### OAuthProxyConfig

Complete configuration reference:

```typescript
interface OAuthProxyConfig {
  // REQUIRED: Upstream provider settings
  upstreamAuthorizationEndpoint: string;
  upstreamTokenEndpoint: string;
  upstreamClientId: string;
  upstreamClientSecret: string;
  baseUrl: string;

  // OPTIONAL: OAuth behavior
  redirectPath?: string;              // default: "/oauth/callback"
  scopes?: string[];                  // provider-specific defaults
  forwardPkce?: boolean;              // default: false
  consentRequired?: boolean;          // default: true
  consentSigningKey?: string;         // auto-generated if not provided
  allowedRedirectUriPatterns?: string[];
  transactionTtl?: number;            // seconds, default: 600
  authorizationCodeTtl?: number;      // seconds, default: 300

  // OPTIONAL: Token swap pattern (enabled by default)
  enableTokenSwap?: boolean;          // default: true
  jwtSigningKey?: string;             // optional (auto-generated if not provided)
  accessTokenTtl?: number;            // seconds, default: 3600
  refreshTokenTtl?: number;           // seconds, default: 2592000

  // OPTIONAL: Storage
  tokenStorage?: TokenStorage;        // default: MemoryTokenStorage
  tokenVerifier?: TokenVerifier;      // custom JWT verification
}
```

### Redirect URI Patterns

Control which callback URIs clients can register:

```typescript
const authProxy = new OAuthProxy({
  // ... other config
  allowedRedirectUriPatterns: [
    "https://*.example.com/*",        // Wildcard subdomain
    "http://localhost:*",              // Any localhost port
    "https://app.example.com/callback", // Exact match
  ],
});
```

### TTL Configuration

Adjust timeouts for your security requirements:

```typescript
const authProxy = new OAuthProxy({
  // ... other config
  transactionTtl: 600,          // 10 minutes for authorization flow
  authorizationCodeTtl: 300,    // 5 minutes for code exchange
  accessTokenTtl: 3600,         // 1 hour for access tokens
  refreshTokenTtl: 2592000,     // 30 days for refresh tokens
});
```

## Advanced Features

### Token Swap Pattern (Enhanced Security - Enabled by Default)

Token swap prevents upstream tokens from reaching the client. This is **enabled by default** for enhanced security.

```typescript
import { OAuthProxy, DiskStore, JWTIssuer } from "fastmcp/auth";

const authProxy = new OAuthProxy({
  baseUrl: "https://your-server.com",
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
  upstreamClientId: process.env.OAUTH_CLIENT_ID,
  upstreamClientSecret: process.env.OAUTH_CLIENT_SECRET,

  // Token swap is enabled by default
  // Optionally provide your own signing key (recommended for production)
  jwtSigningKey: await JWTIssuer.deriveKey(process.env.JWT_SECRET, 100000),

  // Use persistent storage
  tokenStorage: new DiskStore({
    directory: "/var/lib/fastmcp/oauth",
  }),
});
```

**Note:** If you don't provide `jwtSigningKey`, one will be auto-generated. For production, it's recommended to provide your own derived key for consistency across server restarts.

**Loading upstream tokens in your tools:**

```typescript
server.addTool({
  name: "call-api",
  description: "Call upstream API with user's token",
  execute: async (args, { session }) => {
    const clientToken = session?.headers?.["authorization"]?.replace("Bearer ", "");

    // Load the upstream tokens
    const upstreamTokens = await authProxy.loadUpstreamTokens(clientToken);

    if (upstreamTokens) {
      const response = await fetch("https://api.provider.com/user", {
        headers: {
          Authorization: `Bearer ${upstreamTokens.accessToken}`,
        },
      });

      const data = await response.json();
      return {
        content: [{ type: "text", text: JSON.stringify(data) }],
      };
    }

    throw new Error("No valid token");
  },
});
```

### Persistent Token Storage

Use `DiskStore` for production deployments:

```typescript
import { DiskStore } from "fastmcp/auth";

const storage = new DiskStore({
  directory: "/var/lib/fastmcp/oauth",
  cleanupIntervalMs: 60000,  // Cleanup every minute
  fileExtension: ".json",
});

const authProxy = new OAuthProxy({
  // ... other config
  tokenStorage: storage,
});
```

**Benefits:**
- Tokens persist across server restarts
- Automatic cleanup of expired entries
- Thread-safe concurrent operations

### Custom Claims Passthrough (Enabled by Default)

Pass custom claims from upstream tokens (roles, permissions, etc.) to your proxy-issued JWTs for authorization in MCP tools.

**Enabled by default** - Claims are automatically passed through with secure defaults:

```typescript
import { OAuthProxy } from "fastmcp/auth";

// Default behavior - claims passthrough enabled
const authProxy = new OAuthProxy({
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
  upstreamClientId: process.env.OAUTH_CLIENT_ID,
  upstreamClientSecret: process.env.OAUTH_CLIENT_SECRET,
  baseUrl: "https://your-server.com",
  // customClaimsPassthrough is enabled by default
});
```

**Custom configuration:**

```typescript
const authProxy = new OAuthProxy({
  // ... other config ...
  customClaimsPassthrough: {
    // Extract from access token (default: true)
    fromAccessToken: true,

    // Extract from ID token (default: true)
    fromIdToken: true,

    // No prefix by default for RBAC compatibility
    claimPrefix: false,

    // Optional: Only allow specific claims
    allowedClaims: ['role', 'roles', 'permissions', 'email', 'groups'],

    // Optional: Block specific claims
    blockedClaims: ['internal_id', 'debug_info'],

    // Maximum claim value size (default: 2000 chars)
    maxClaimValueSize: 2000,

    // Allow complex objects/arrays (default: false)
    allowComplexClaims: false,
  },
});

// Or disable if not needed
const authProxyNoClaims = new OAuthProxy({
  // ... other config ...
  customClaimsPassthrough: false,
});
```

**Using claims for authorization:**

```typescript
// Example: Role-based access control
server.addTool({
  name: "admin-dashboard",
  description: "Access admin dashboard",
  canAccess: async ({ session }) => {
    const token = session?.headers?.["authorization"]?.replace("Bearer ", "");
    if (!token) return false;

    // Decode the proxy JWT
    const payload = JSON.parse(
      Buffer.from(token.split(".")[1], "base64url").toString()
    );

    // Check role claim from upstream IDP
    return payload.role === "admin" || payload.roles?.includes("admin");
  },
  execute: async () => {
    return {
      content: [{ type: "text", text: "Admin dashboard data..." }],
    };
  },
});

// Example: Permission-based access
server.addTool({
  name: "delete-resource",
  description: "Delete a resource",
  canAccess: async ({ session }) => {
    const token = session?.headers?.["authorization"]?.replace("Bearer ", "");
    if (!token) return false;

    const payload = JSON.parse(
      Buffer.from(token.split(".")[1], "base64url").toString()
    );

    // Check fine-grained permissions
    return payload.permissions?.includes("resource:delete");
  },
  execute: async (args) => {
    // Delete logic here
    return {
      content: [{ type: "text", text: "Resource deleted" }],
    };
  },
});
```

**Key features:**
- Extracts from both access tokens and ID tokens
- Protected claims (aud, iss, exp, iat, nbf, jti, client_id) never copied
- Access token claims take precedence over ID token claims
- Size limits and type validation for security
- Supports allowlist/blocklist filtering
- Optional prefix for claim names


### Encrypted Token Storage (Enabled by Default)

**Storage is automatically encrypted** with AES-256-GCM. You don't need to manually wrap with `EncryptedTokenStorage`:

```typescript
import { DiskStore, JWTIssuer } from "fastmcp/auth";

const authProxy = new OAuthProxy({
  // ... other config
  tokenStorage: new DiskStore({ directory: "/var/lib/fastmcp/oauth" }),
  // ← Automatically encrypted!

  // Optional: Provide custom encryption key (recommended for production)
  encryptionKey: await JWTIssuer.deriveKey(
    process.env.ENCRYPTION_SECRET + ":storage",
    100000
  ),
});
```

**To disable encryption** (only for development/testing):
```typescript
const authProxy = new OAuthProxy({
  // ... other config
  tokenStorage: new MemoryTokenStorage(),
  encryptionKey: false, // Explicitly disable encryption
});
```

**Encryption details:**
- AES-256-GCM encryption (enabled by default)
- Scrypt key derivation
- Authentication tag verification
- Auto-generated key if not provided (recommended to provide your own)

### Custom Token Storage

Implement your own storage backend:

```typescript
import { TokenStorage } from "fastmcp/auth";

class RedisTokenStorage implements TokenStorage {
  private redis: RedisClient;

  constructor(redisClient: RedisClient) {
    this.redis = redisClient;
  }

  async save(key: string, value: unknown, ttl?: number): Promise<void> {
    const serialized = JSON.stringify(value);
    if (ttl) {
      await this.redis.setex(key, ttl, serialized);
    } else {
      await this.redis.set(key, serialized);
    }
  }

  async get(key: string): Promise<unknown | null> {
    const value = await this.redis.get(key);
    return value ? JSON.parse(value) : null;
  }

  async delete(key: string): Promise<void> {
    await this.redis.del(key);
  }

  async cleanup(): Promise<void> {
    // Redis handles TTL automatically
  }
}

const authProxy = new OAuthProxy({
  // ... other config
  tokenStorage: new RedisTokenStorage(redisClient),
});
```

### JWKS Token Verification

For distributed systems or when you need to verify tokens using public keys (RS256/ES256), use JWKS (JSON Web Key Set) verification.

#### Installation

JWKS support requires the optional `jose` package:

```bash
npm install jose
```

#### Basic JWKS Verification

```typescript
import { JWKSVerifier } from "fastmcp/auth";

const verifier = new JWKSVerifier({
  jwksUri: "https://provider.com/.well-known/jwks.json",
  issuer: "https://provider.com",
  audience: "your-client-id",
});

// Verify a token
const result = await verifier.verify(token);
if (result.valid) {
  console.log("Token valid:", result.claims);
} else {
  console.log("Token invalid:", result.error);
}
```

#### Using JWKS with OAuth Proxy

Replace the default HS256 JWT issuer with JWKS verification:

```typescript
import { OAuthProxy, JWKSVerifier } from "fastmcp/auth";

const authProxy = new OAuthProxy({
  baseUrl: "https://your-server.com",
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
  upstreamClientId: process.env.CLIENT_ID,
  upstreamClientSecret: process.env.CLIENT_SECRET,

  // Use JWKS verification instead of HS256
  tokenVerifier: new JWKSVerifier({
    jwksUri: "https://provider.com/.well-known/jwks.json",
    issuer: "https://provider.com",
    audience: process.env.CLIENT_ID,
  }),
});
```

#### Configuration Options

```typescript
interface JWKSVerifierConfig {
  /**
   * URL to the JWKS endpoint
   */
  jwksUri: string;

  /**
   * Expected token issuer
   */
  issuer: string;

  /**
   * Expected token audience
   */
  audience: string;

  /**
   * How long to cache JWKS keys (milliseconds)
   * @default 600000 (10 minutes)
   */
  cacheDuration?: number;

  /**
   * Minimum time between JWKS refetches (milliseconds)
   * @default 30000 (30 seconds)
   */
  cooldownDuration?: number;
}
```

#### Multi-Provider JWKS Support

Verify tokens from multiple OAuth providers:

```typescript
import { JWKSVerifier } from "fastmcp/auth";

// Create verifiers for each provider
const googleVerifier = new JWKSVerifier({
  jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
  issuer: "https://accounts.google.com",
  audience: process.env.GOOGLE_CLIENT_ID,
});

const githubVerifier = new JWKSVerifier({
  jwksUri: "https://token.actions.githubusercontent.com/.well-known/jwks",
  issuer: "https://token.actions.githubusercontent.com",
  audience: "your-app",
});

// Verify based on token issuer
async function verifyToken(token: string, provider: string) {
  const verifier = provider === "google" ? googleVerifier : githubVerifier;
  return await verifier.verify(token);
}
```

#### Performance Considerations

- **Key Caching**: JWKS keys are cached automatically to reduce network requests
- **Cooldown Period**: Prevents excessive refetching during key rotation
- **Lazy Loading**: The `jose` package is only loaded when JWKSVerifier is instantiated
- **Zero Impact**: If you don't use JWKS, the jose package isn't required

#### When to Use JWKS

Use JWKS verification when:
- ✅ You need to verify tokens in multiple services (distributed systems)
- ✅ You want to use asymmetric keys (RS256/ES256)
- ✅ Your upstream provider uses JWKS for token validation
- ✅ You need public key verification without shared secrets

Use default HS256 (JWTIssuer) when:
- ✅ You have a single server verifying tokens
- ✅ You want simpler setup without additional dependencies
- ✅ You prefer symmetric key signing (faster)
- ✅ You don't need to share verification keys with external services

### Protecting Tools with OAuth

Restrict tool access to authenticated users:

```typescript
server.addTool({
  name: "protected-tool",
  description: "Requires authentication",
  canAccess: async ({ session }) => {
    // Check if user has valid authorization header
    return session?.headers?.["authorization"] !== undefined;
  },
  execute: async (args, { session }) => {
    const token = session?.headers?.["authorization"];
    // Use token to access protected resources

    return {
      content: [
        { type: "text", text: "Access granted!" },
      ],
    };
  },
});
```

### Disabling Consent for Development

For local testing environments:

```typescript
const authProxy = new GoogleProvider({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  baseUrl: "http://localhost:3000",
  consentRequired: false, // ⚠️ Development only!
});
```

**Warning:** Only disable consent in trusted development environments.

## Security Best Practices

### Production Checklist

1. **Use HTTPS**
```typescript
const authProxy = new OAuthProxy({
  baseUrl: "https://your-server.com", // Not http://
  // ...
});
```

2. **Derive Keys from Secrets**
```typescript
import { JWTIssuer } from "fastmcp/auth";

const jwtSigningKey = await JWTIssuer.deriveKey(
  process.env.JWT_SECRET,
  100000 // PBKDF2 iterations
);

const encryptionKey = await JWTIssuer.deriveKey(
  process.env.ENCRYPTION_SECRET,
  100000
);
```

3. **Use Different Keys for Different Purposes**
```typescript
const jwtKey = await JWTIssuer.deriveKey(
  process.env.SECRET + ":jwt",
  100000
);

const storageKey = await JWTIssuer.deriveKey(
  process.env.SECRET + ":storage",
  100000
);

const consentKey = await JWTIssuer.deriveKey(
  process.env.SECRET + ":consent",
  100000
);
```

4. **Enable Consent Screen**
```typescript
const authProxy = new OAuthProxy({
  consentRequired: true, // Default, but be explicit
  // ...
});
```

5. **Use Persistent Encrypted Storage**
```typescript
const storage = new EncryptedTokenStorage(
  new DiskStore({ directory: "/var/lib/fastmcp/oauth" }),
  encryptionKey
);
```

6. **Validate Redirect URIs**
```typescript
const authProxy = new OAuthProxy({
  allowedRedirectUriPatterns: [
    "https://yourdomain.com/*",
    "http://localhost:*", // Only for development
  ],
  // ...
});
```

7. **Set Appropriate TTLs**
```typescript
const authProxy = new OAuthProxy({
  transactionTtl: 600,        // 10 minutes
  authorizationCodeTtl: 300,  // 5 minutes
  accessTokenTtl: 900,        // 15 minutes (shorter = more secure)
  refreshTokenTtl: 604800,    // 7 days
  // ...
});
```

### Environment Variables

Store all secrets in environment variables:

```bash
# .env file
GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-secret-here
JWT_SECRET=generate-with-crypto-random-bytes
ENCRYPTION_SECRET=different-secret-here
```

Load them securely:

```typescript
import * as dotenv from "dotenv";
dotenv.config();

const authProxy = new GoogleProvider({
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  baseUrl: process.env.BASE_URL!,
});
```

### Secret Generation

Generate strong secrets:

```typescript
import { randomBytes } from "crypto";

// Generate a strong secret (32 bytes = 256 bits)
const secret = randomBytes(32).toString("base64");
console.log(secret);
```

Or use command line:
```bash
# Generate random secret
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

## Troubleshooting

### "Invalid redirect URI" error

**Problem:** OAuth provider rejects the redirect URI.

**Solution:** Ensure the redirect URI in provider settings matches exactly:
```
{baseUrl}/oauth/callback
```

Examples:
- `https://your-server.com/oauth/callback`
- `http://localhost:3000/oauth/callback`

### "Invalid state" error

**Causes:**
1. Transaction expired (default 10 minutes)
2. Server restarted (in-memory storage lost)
3. Clock skew between client and server

**Solutions:**
- Use persistent storage (DiskStore)
- Increase `transactionTtl` if needed
- Check system time synchronization

### "PKCE validation failed" error

**Problem:** Code verifier doesn't match the challenge.

**Solution:** Ensure client is:
1. Storing the code verifier correctly
2. Sending it in the token request
3. Using the same verifier that generated the challenge

### Consent screen not showing

**Problem:** Being redirected directly without consent.

**Solutions:**
1. Check `consentRequired` is `true`
2. Clear browser cookies for the domain
3. Check consent cookie signing key is consistent

### Server restart loses sessions

**Problem:** Using in-memory storage.

**Solution:** Use persistent storage:
```typescript
const authProxy = new OAuthProxy({
  tokenStorage: new DiskStore({
    directory: "/var/lib/fastmcp/oauth",
  }),
  // ...
});
```

### Token expired immediately

**Problem:** TTL configuration issue.

**Solution:** Check your TTL values:
```typescript
const authProxy = new OAuthProxy({
  accessTokenTtl: 3600,      // seconds, not milliseconds
  refreshTokenTtl: 2592000,  // 30 days
  // ...
});
```

### Cannot find module 'fastmcp/auth'

**Problem:** Import path issue.

**Solution:** Ensure you're importing from the correct path:
```typescript
// Correct
import { OAuthProxy } from "fastmcp/auth";

// Also correct
import { OAuthProxy } from "fastmcp";
```

Make sure `fastmcp` is properly installed:
```bash
npm install fastmcp
```

## Examples

Complete working examples are available in the repository:

- **[oauth-integrated-server.ts](../src/examples/oauth-integrated-server.ts)** - Google OAuth with FastMCP integration
- **[oauth-proxy-server.ts](../src/examples/oauth-proxy-server.ts)** - Standalone OAuth proxy
- **[oauth-proxy-github.ts](../src/examples/oauth-proxy-github.ts)** - GitHub provider example
- **[oauth-proxy-custom.ts](../src/examples/oauth-proxy-custom.ts)** - Custom provider with advanced features

## Testing

### Running Tests

```bash
# All tests
npm test

# OAuth tests only
npm test -- auth/

# Specific test file
npm test -- src/auth/OAuthProxy.test.ts
```

### Manual Testing Flow

1. Start your server:
```bash
npm run dev
```

2. Register a client:
```bash
curl -X POST http://localhost:3000/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test Client",
    "redirect_uris": ["http://localhost:8080/callback"]
  }'
```

3. Visit authorization URL in browser:
```
http://localhost:3000/oauth/authorize?client_id=<client_id>&response_type=code&redirect_uri=http://localhost:8080/callback&code_challenge=<challenge>&code_challenge_method=S256
```

4. Complete OAuth flow through consent and provider authentication

5. Exchange authorization code for token:
```bash
curl -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=<auth_code>&redirect_uri=http://localhost:8080/callback&code_verifier=<verifier>&client_id=<client_id>"
```

## Next Steps

- Review [OAuth Proxy Features](oauth-proxy-features.md) for detailed capabilities
- See [Python vs TypeScript Comparison](oauth-python-typescript.md) for migration guidance
- Check out the example implementations in [`src/examples/`](../src/examples/)
