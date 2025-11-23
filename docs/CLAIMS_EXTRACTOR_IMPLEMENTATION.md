# ClaimsExtractor Implementation Plan

## Overview
This document details the implementation of the `ClaimsExtractor` class for securely extracting and filtering custom claims from upstream OAuth tokens.

## Design Decisions

### 1. Enabled by Default
- **Why**: Authorization is impossible without custom claims (roles, permissions, etc.)
- **Impact**: Downstream MCP tools can use `auth.roles`, `auth.permissions` for access control
- **Override**: Can be disabled with `customClaimsPassthrough: false`

### 2. No Prefix by Default
- **Why**: Maximum compatibility with existing RBAC libraries expecting standard claim names
- **Example**: Claims like `roles`, `permissions`, `email` work out-of-the-box
- **Override**: Can add prefix with `claimPrefix: "upstream_"` for collision prevention

### 3. Protected Claims (Always Blocked)
These claims are NEVER copied from upstream to prevent security issues:
```typescript
const PROTECTED_CLAIMS = new Set([
  'aud',       // Proxy's audience
  'iss',       // Proxy's issuer
  'exp',       // Proxy's expiration
  'iat',       // Proxy's issued-at
  'nbf',       // Proxy's not-before
  'jti',       // Proxy's JWT ID
  'client_id'  // Proxy's client ID
]);
```

## ClaimsExtractor Class

### Location
Add to `src/auth/OAuthProxy.ts` as a private class before the main `OAuthProxy` class.

### Complete Implementation

```typescript
/**
 * ClaimsExtractor
 * Securely extracts and filters custom claims from upstream OAuth tokens
 */
class ClaimsExtractor {
  private config: CustomClaimsPassthroughConfig;

  // Claims that MUST NOT be copied from upstream (protect proxy's JWT integrity)
  private readonly PROTECTED_CLAIMS = new Set([
    'aud', 'iss', 'exp', 'iat', 'nbf', 'jti', 'client_id'
  ]);

  constructor(config: CustomClaimsPassthroughConfig | boolean) {
    // Handle boolean shorthand: true = default config, false = disabled
    if (typeof config === 'boolean') {
      config = config ? {} : { fromAccessToken: false, fromIdToken: false };
    }

    // Apply defaults
    this.config = {
      fromAccessToken: config.fromAccessToken !== false,  // Default: true
      fromIdToken: config.fromIdToken !== false,          // Default: true
      claimPrefix: config.claimPrefix !== undefined ? config.claimPrefix : false, // Default: no prefix
      allowedClaims: config.allowedClaims,
      blockedClaims: config.blockedClaims || [],
      maxClaimValueSize: config.maxClaimValueSize || 2000,
      allowComplexClaims: config.allowComplexClaims || false,
    };
  }

  /**
   * Extract claims from a token (access token or ID token)
   */
  async extract(
    token: string,
    tokenType: 'access' | 'id'
  ): Promise<Record<string, unknown> | null> {
    // Check if this token type is enabled
    if (tokenType === 'access' && !this.config.fromAccessToken) {
      return null;
    }
    if (tokenType === 'id' && !this.config.fromIdToken) {
      return null;
    }

    // Detect if token is JWT format (3 parts separated by dots)
    if (!this.isJWT(token)) {
      // Opaque token - no claims to extract
      return null;
    }

    // Decode JWT payload (base64url decode only, no signature verification)
    // We trust the token because it came from upstream via server-to-server exchange
    const payload = this.decodeJWTPayload(token);
    if (!payload) {
      return null;
    }

    // Filter and validate claims
    const filtered = this.filterClaims(payload);

    // Apply prefix if configured
    return this.applyPrefix(filtered);
  }

  /**
   * Check if a token is in JWT format
   */
  private isJWT(token: string): boolean {
    return token.split('.').length === 3;
  }

  /**
   * Decode JWT payload without signature verification
   * Safe because token came from trusted upstream via server-to-server exchange
   */
  private decodeJWTPayload(token: string): Record<string, unknown> | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return null;
      }

      // Decode the payload (middle part)
      const payload = Buffer.from(parts[1], 'base64url').toString('utf-8');
      return JSON.parse(payload) as Record<string, unknown>;
    } catch (error) {
      // Invalid JWT format or JSON
      console.warn(`Failed to decode JWT payload: ${error}`);
      return null;
    }
  }

  /**
   * Filter claims based on security rules
   */
  private filterClaims(claims: Record<string, unknown>): Record<string, unknown> {
    const result: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(claims)) {
      // RULE 1: Skip protected claims (ALWAYS enforced)
      if (this.PROTECTED_CLAIMS.has(key)) {
        continue;
      }

      // RULE 2: Skip blocked claims
      if (this.config.blockedClaims?.includes(key)) {
        continue;
      }

      // RULE 3: If allowlist exists, only include allowed claims
      if (this.config.allowedClaims && !this.config.allowedClaims.includes(key)) {
        continue;
      }

      // RULE 4: Validate claim value
      if (!this.isValidClaimValue(value)) {
        console.warn(`Skipping claim '${key}' due to invalid value`);
        continue;
      }

      result[key] = value;
    }

    return result;
  }

  /**
   * Validate a claim value (type and size checks)
   */
  private isValidClaimValue(value: unknown): boolean {
    if (value === null || value === undefined) {
      return false;
    }

    const type = typeof value;

    // Primitive types (string, number, boolean) are always allowed
    if (type === 'string') {
      const maxSize = this.config.maxClaimValueSize ?? 2000;
      return (value as string).length <= maxSize;
    }

    if (type === 'number' || type === 'boolean') {
      return true;
    }

    // Arrays and objects only if explicitly allowed
    if (Array.isArray(value) || type === 'object') {
      // Complex types not allowed by default (security)
      if (!this.config.allowComplexClaims) {
        return false;
      }

      // Check serialized size
      try {
        const stringified = JSON.stringify(value);
        const maxSize = this.config.maxClaimValueSize ?? 2000;
        return stringified.length <= maxSize;
      } catch {
        // Can't serialize - reject
        return false;
      }
    }

    // Unknown type - reject
    return false;
  }

  /**
   * Apply prefix to claim names (if configured)
   */
  private applyPrefix(claims: Record<string, unknown>): Record<string, unknown> {
    const prefix = this.config.claimPrefix;

    // No prefix configured or explicitly disabled
    if (prefix === false || prefix === '' || prefix === undefined) {
      return claims;
    }

    // Apply prefix to all claim names
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(claims)) {
      result[`${prefix}${key}`] = value;
    }

    return result;
  }
}
```

## Integration into OAuthProxy

### 1. Add ClaimsExtractor instance to OAuthProxy class

```typescript
export class OAuthProxy {
  // ... existing properties ...
  private claimsExtractor: ClaimsExtractor | null = null;

  constructor(config: OAuthProxyConfig) {
    // ... existing initialization ...

    // Initialize claims extractor if feature enabled
    // Default: true (enabled with default settings)
    const claimsConfig = config.customClaimsPassthrough !== undefined
      ? config.customClaimsPassthrough
      : true; // Default to enabled

    if (claimsConfig !== false) {
      this.claimsExtractor = new ClaimsExtractor(claimsConfig);
    }
  }
}
```

### 2. Add extractUpstreamClaims method

```typescript
/**
 * Extract custom claims from upstream tokens
 * Returns merged claims from both access token and ID token
 */
private async extractUpstreamClaims(
  upstreamTokens: UpstreamTokenSet
): Promise<Record<string, unknown> | null> {
  // Feature disabled
  if (!this.claimsExtractor) {
    return null;
  }

  const allClaims: Record<string, unknown> = {};

  // Extract from access token (if enabled and present)
  try {
    const accessClaims = await this.claimsExtractor.extract(
      upstreamTokens.accessToken,
      'access'
    );
    if (accessClaims) {
      Object.assign(allClaims, accessClaims);
    }
  } catch (error) {
    console.warn('Failed to extract claims from access token:', error);
  }

  // Extract from ID token (if enabled and present)
  if (upstreamTokens.idToken) {
    try {
      const idClaims = await this.claimsExtractor.extract(
        upstreamTokens.idToken,
        'id'
      );
      if (idClaims) {
        // Merge ID token claims, but access token claims take precedence
        for (const [key, value] of Object.entries(idClaims)) {
          if (!(key in allClaims)) {
            allClaims[key] = value;
          }
        }
      }
    } catch (error) {
      console.warn('Failed to extract claims from ID token:', error);
    }
  }

  return Object.keys(allClaims).length > 0 ? allClaims : null;
}
```

### 3. Update issueSwappedTokens to use extracted claims

```typescript
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

  // Store upstream tokens
  const upstreamTokenKey = this.generateId();
  await this.tokenStorage.save(
    `upstream:${upstreamTokenKey}`,
    upstreamTokens,
    upstreamTokens.expiresIn,
  );

  // Issue FastMCP access token WITH custom claims
  const accessToken = this.jwtIssuer.issueAccessToken(
    clientId,
    upstreamTokens.scope,
    customClaims || undefined  // Pass custom claims or undefined
  );

  // ... rest of existing code (mapping storage) ...
  const accessJti = await this.extractJti(accessToken);

  await this.tokenStorage.save(
    `mapping:${accessJti}`,
    {
      clientId,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + upstreamTokens.expiresIn * 1000),
      jti: accessJti,
      scope: upstreamTokens.scope,
      upstreamTokenKey,
    },
    upstreamTokens.expiresIn,
  );

  const response: TokenResponse = {
    access_token: accessToken,
    expires_in: 3600,
    scope: upstreamTokens.scope.join(" "),
    token_type: "Bearer",
  };

  // Issue refresh token if upstream provided one
  if (upstreamTokens.refreshToken) {
    const refreshToken = this.jwtIssuer.issueRefreshToken(
      clientId,
      upstreamTokens.scope,
      customClaims || undefined  // Also pass custom claims to refresh token
    );
    const refreshJti = await this.extractJti(refreshToken);

    await this.tokenStorage.save(
      `mapping:${refreshJti}`,
      {
        clientId,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 2592000 * 1000),
        jti: refreshJti,
        scope: upstreamTokens.scope,
        upstreamTokenKey,
      },
      2592000,
    );

    response.refresh_token = refreshToken;
  }

  return response;
}
```

## Import Updates

Add to the imports at the top of `OAuthProxy.ts`:

```typescript
import type {
  // ... existing imports ...
  CustomClaimsPassthroughConfig,
} from "./types.js";
```

## Example Usage

### Default (Enabled, No Prefix)
```typescript
const proxy = new OAuthProxy({
  baseUrl: 'https://proxy.example.com',
  upstreamAuthorizationEndpoint: 'https://idp.com/authorize',
  upstreamTokenEndpoint: 'https://idp.com/token',
  upstreamClientId: 'client-123',
  upstreamClientSecret: 'secret',
  // customClaimsPassthrough is enabled by default
});

// Result: Proxy JWT will contain claims like:
// { aud, iss, exp, iat, jti, client_id, scope, email, roles, permissions }
```

### Disabled
```typescript
const proxy = new OAuthProxy({
  // ... config ...
  customClaimsPassthrough: false
});

// Result: Proxy JWT will only contain standard claims:
// { aud, iss, exp, iat, jti, client_id, scope }
```

### Custom Configuration
```typescript
const proxy = new OAuthProxy({
  // ... config ...
  customClaimsPassthrough: {
    fromAccessToken: true,
    fromIdToken: true,
    claimPrefix: false,  // No prefix
    allowedClaims: ['sub', 'email', 'name', 'roles', 'permissions', 'tenant_id'],
    maxClaimValueSize: 1000,
    allowComplexClaims: false  // Only primitives
  }
});
```

### With Prefix (for extra safety)
```typescript
const proxy = new OAuthProxy({
  // ... config ...
  customClaimsPassthrough: {
    claimPrefix: 'upstream_'
  }
});

// Result: Proxy JWT will contain:
// { aud, iss, exp, iat, jti, client_id, scope, upstream_email, upstream_roles }
```

## Security Considerations

### ✅ What's Protected
1. **Protected claims** are always blocked (aud, iss, exp, etc.)
2. **Size limits** prevent DoS via large claim values
3. **Type validation** prevents injection via complex types (unless explicitly allowed)
4. **Graceful error handling** - failures don't break token issuance
5. **No signature verification needed** - tokens from trusted server-to-server exchange

### ⚠️ What to Consider
1. **Claim collision** - If upstream has `scope` claim, it won't override proxy's scope
2. **Trust model** - We trust upstream provider completely (valid for OAuth proxy pattern)
3. **No prefix by default** - Maximizes compatibility but requires proxy to never add claims with same names

## Testing Strategy

1. **Default behavior** - Verify claims passthrough works out of box
2. **JWT vs Opaque** - Handle both token types gracefully
3. **Protected claims** - Verify they're never copied
4. **Filtering** - Test allowlist and blocklist
5. **Size limits** - Verify large claims are rejected
6. **Type validation** - Test primitives vs complex types
7. **Prefix** - Test with and without prefix
8. **Both sources** - Extract from access token and ID token
9. **Precedence** - Access token claims override ID token claims
10. **Disable** - Verify feature can be turned off

## Implementation Checklist

- [x] Define CustomClaimsPassthroughConfig interface
- [x] Update OAuthProxyConfig to include customClaimsPassthrough
- [x] Update JWTClaims interface with index signature
- [x] Update JWTIssuer.issueAccessToken() to accept additionalClaims
- [x] Update JWTIssuer.issueRefreshToken() to accept additionalClaims
- [ ] Implement ClaimsExtractor class in OAuthProxy.ts
- [ ] Add claimsExtractor initialization in OAuthProxy constructor
- [ ] Implement extractUpstreamClaims() method
- [ ] Update issueSwappedTokens() to use extracted claims
- [ ] Add import for CustomClaimsPassthroughConfig
- [ ] Write comprehensive tests
- [ ] Test with real OAuth providers (GitHub, Google, Azure)
- [ ] Update documentation

## Next Steps

1. Review this implementation plan
2. Implement ClaimsExtractor class in OAuthProxy.ts
3. Add the integration code to OAuthProxy constructor and issueSwappedTokens
4. Write comprehensive tests
5. Test with actual OAuth providers
6. Document usage examples
