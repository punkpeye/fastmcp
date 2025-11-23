# OAuth Advanced Features

This document covers the advanced features ported from the Python fastmcp implementation, including persistent token storage, JWT token issuance/validation, and the token swap pattern.

## Table of Contents

- [Persistent Token Storage](#persistent-token-storage)
- [JWT Issuer](#jwt-issuer)
- [Token Swap Pattern](#token-swap-pattern)
- [Migration from Basic Proxy](#migration-from-basic-proxy)

## Persistent Token Storage

The `DiskStore` class provides persistent file-based storage for OAuth tokens and transaction state, allowing data to survive server restarts.

### Basic Usage

```typescript
import { OAuthProxy, DiskStore } from "fastmcp/auth";

const proxy = new OAuthProxy({
  baseUrl: "https://your-server.com",
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
  upstreamClientId: "your-client-id",
  upstreamClientSecret: "your-client-secret",
  tokenStorage: new DiskStore({
    directory: "/var/lib/fastmcp/oauth",
  }),
});
```

### Configuration Options

```typescript
interface DiskStoreOptions {
  /**
   * Directory path for storing data
   */
  directory: string;

  /**
   * How often to run cleanup (in milliseconds)
   * @default 60000 (1 minute)
   */
  cleanupIntervalMs?: number;

  /**
   * File extension for stored files
   * @default ".json"
   */
  fileExtension?: string;
}
```

### Features

- **Automatic TTL Management**: Expired entries are automatically cleaned up
- **Crash Recovery**: Tokens persist across server restarts
- **Thread-Safe**: Safe for concurrent operations
- **Key Sanitization**: Prevents directory traversal attacks

### Encrypted Storage

For additional security, wrap `DiskStore` with `EncryptedTokenStorage`:

```typescript
import { DiskStore, EncryptedTokenStorage } from "fastmcp/auth";

const diskStore = new DiskStore({ directory: "/var/lib/fastmcp/oauth" });
const encryptedStorage = new EncryptedTokenStorage(
  diskStore,
  "your-encryption-key",
);

const proxy = new OAuthProxy({
  // ... other config
  tokenStorage: encryptedStorage,
});
```

The encrypted storage uses AES-256-GCM encryption with scrypt-derived keys.

## JWT Issuer

The `JWTIssuer` class provides JWT generation and validation using HMAC-SHA256 (HS256) signing.

### Basic Usage

```typescript
import { JWTIssuer } from "fastmcp/auth";

const issuer = new JWTIssuer({
  issuer: "https://your-server.com",
  audience: "https://your-server.com",
  signingKey: "your-secret-key",
  accessTokenTtl: 3600, // 1 hour
  refreshTokenTtl: 2592000, // 30 days
});

// Issue tokens
const accessToken = issuer.issueAccessToken("client-123", ["read", "write"]);
const refreshToken = issuer.issueRefreshToken("client-123", ["read", "write"]);

// Validate tokens
const result = await issuer.verify(accessToken);
if (result.valid) {
  console.log("Token claims:", result.claims);
}
```

### Key Derivation

For production use, derive signing keys from secrets:

```typescript
import { JWTIssuer } from "fastmcp/auth";

const signingKey = await JWTIssuer.deriveKey(
  process.env.CLIENT_SECRET,
  100000, // PBKDF2 iterations
);

const issuer = new JWTIssuer({
  issuer: "https://your-server.com",
  audience: "https://your-server.com",
  signingKey,
});
```

### JWT Claims

The issued JWTs contain the following claims:

```typescript
interface JWTClaims {
  iss: string; // Issuer
  aud: string; // Audience
  client_id: string; // Client ID
  scope: string[]; // Scopes
  exp: number; // Expiration time (seconds since epoch)
  iat: number; // Issued at time (seconds since epoch)
  jti: string; // JWT ID (unique identifier)
}
```

## Token Swap Pattern

The token swap pattern enhances security by issuing short-lived FastMCP JWTs to clients while securely storing the actual upstream provider tokens on the server.

### How It Works

1. Client exchanges authorization code for tokens
2. Proxy obtains tokens from upstream provider
3. Proxy stores upstream tokens securely with encryption
4. Proxy issues short-lived JWT to client
5. Client uses JWT for subsequent requests
6. Proxy validates JWT and retrieves upstream tokens as needed

### Benefits

- **Enhanced Security**: Upstream tokens never leave the server
- **Short-Lived Tokens**: Client tokens expire quickly (1 hour default)
- **Token Rotation**: Supports automatic refresh token rotation
- **Stateless Validation**: JWTs can be validated without database lookups
- **Provider Abstraction**: Different providers can be handled uniformly

### Configuration

```typescript
import { OAuthProxy, DiskStore } from "fastmcp/auth";

const proxy = new OAuthProxy({
  baseUrl: "https://your-server.com",
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
  upstreamClientId: "your-client-id",
  upstreamClientSecret: "your-client-secret",

  // Token swap is enabled by default
  // Optionally provide your own signing key (recommended for production)
  jwtSigningKey: "your-jwt-signing-key",

  // Use persistent storage for production
  tokenStorage: new DiskStore({
    directory: "/var/lib/fastmcp/oauth",
  }),
});
```

### Loading Upstream Tokens

When you need to use the upstream provider tokens (e.g., to make API calls):

```typescript
// Client presents their FastMCP JWT
const fastmcpToken = request.headers
  .get("Authorization")
  ?.replace("Bearer ", "");

// Load the upstream tokens
const upstreamTokens = await proxy.loadUpstreamTokens(fastmcpToken);

if (upstreamTokens) {
  // Use upstream tokens to make API calls
  const response = await fetch("https://api.provider.com/user", {
    headers: {
      Authorization: `Bearer ${upstreamTokens.accessToken}`,
    },
  });
}
```

### Storage Requirements

The token swap pattern stores:

1. **Upstream Tokens**: The actual tokens from the upstream provider
2. **Token Mappings**: Relationships between JTIs and upstream token keys

Both are automatically cleaned up based on TTL:

- Access token mappings: Same as upstream token expiration
- Refresh token mappings: 30 days default

## Switching to Passthrough Mode (Disabling Token Swap)

If you need passthrough mode for debugging or specific use cases:

### Passthrough Mode (Disabled Token Swap)

```typescript
const proxy = new OAuthProxy({
  baseUrl: "https://your-server.com",
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
  upstreamClientId: "your-client-id",
  upstreamClientSecret: "your-client-secret",

  // Explicitly disable token swap for passthrough mode
  enableTokenSwap: false,
});

// Client receives upstream tokens directly
const response = await proxy.exchangeAuthorizationCode(request);
// response.access_token === upstream provider's access token
```

### Token Swap Mode (Default)

```typescript
const proxy = new OAuthProxy({
  baseUrl: "https://your-server.com",
  upstreamAuthorizationEndpoint: "https://provider.com/oauth/authorize",
  upstreamTokenEndpoint: "https://provider.com/oauth/token",
  upstreamClientId: "your-client-id",
  upstreamClientSecret: "your-client-secret",

  // Token swap is enabled by default (no need to set enableTokenSwap: true)
  // Optionally provide your own signing key
  jwtSigningKey: await JWTIssuer.deriveKey(process.env.CLIENT_SECRET),

  // Use persistent storage
  tokenStorage: new DiskStore({
    directory: "/var/lib/fastmcp/oauth",
  }),
});

// Client receives FastMCP JWT instead
const response = await proxy.exchangeAuthorizationCode(request);
// response.access_token === FastMCP JWT (not upstream token)

// When needed, load upstream tokens
const upstreamTokens = await proxy.loadUpstreamTokens(response.access_token);
```

## Security Considerations

### Production Checklist

- [ ] Use `DiskStore` for persistent storage
- [ ] Wrap storage with `EncryptedTokenStorage`
- [ ] Derive JWT signing keys using `JWTIssuer.deriveKey()`
- [ ] Use strong secrets (minimum 32 bytes)
- [ ] Enable token swap pattern for enhanced security
- [ ] Set appropriate TTL values for your use case
- [ ] Implement proper key rotation procedures
- [ ] Monitor storage cleanup operations
- [ ] Use HTTPS for all proxy endpoints
- [ ] Implement rate limiting on token endpoints

### Key Management

```typescript
// Good: Derive key from secret
const jwtSigningKey = await JWTIssuer.deriveKey(process.env.JWT_SECRET, 100000);

// Better: Use different keys for different purposes
const jwtSigningKey = await JWTIssuer.deriveKey(
  process.env.JWT_SECRET + ":jwt",
  100000,
);

const encryptionKey = await JWTIssuer.deriveKey(
  process.env.JWT_SECRET + ":encryption",
  100000,
);
```

## Performance Considerations

### Storage Backend Selection

- **MemoryTokenStorage**: Fast but loses data on restart. Good for development.
- **DiskStore**: Persistent but slower. Good for single-server production.
- **EncryptedTokenStorage**: Additional overhead for encryption. Use when storing sensitive data.

### Cleanup Intervals

Adjust cleanup intervals based on your load:

```typescript
// High-traffic server (cleanup more frequently)
const storage = new DiskStore({
  directory: "/var/lib/fastmcp/oauth",
  cleanupIntervalMs: 30000, // 30 seconds
});

// Low-traffic server (cleanup less frequently)
const storage = new DiskStore({
  directory: "/var/lib/fastmcp/oauth",
  cleanupIntervalMs: 300000, // 5 minutes
});
```

### Token TTL Tuning

Balance security and performance:

```typescript
const issuer = new JWTIssuer({
  issuer: "https://your-server.com",
  audience: "https://your-server.com",
  signingKey: jwtSigningKey,

  // Shorter TTL = better security but more token refreshes
  accessTokenTtl: 900, // 15 minutes

  // Longer TTL = fewer refreshes but longer exposure window
  refreshTokenTtl: 604800, // 7 days
});
```

## Examples

See the [examples](../src/examples) directory for complete implementations:

- [oauth-proxy-server.ts](../src/examples/oauth-proxy-server.ts) - Basic OAuth proxy
- [oauth-integrated-server.ts](../src/examples/oauth-integrated-server.ts) - Token swap with FastMCP server
- [oauth-proxy-github.ts](../src/examples/oauth-proxy-github.ts) - GitHub provider example
- [oauth-proxy-custom.ts](../src/examples/oauth-proxy-custom.ts) - Custom provider with advanced features
