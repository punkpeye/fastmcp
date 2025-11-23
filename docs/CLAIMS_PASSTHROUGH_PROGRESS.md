# Custom Claims Passthrough - Implementation Progress

## Overview
Implementing custom claims passthrough from upstream OAuth tokens to proxy-issued JWT tokens.
This enables authorization based on roles, permissions, and other custom claims from the upstream identity provider.

## Design Summary

- **Default**: ENABLED (essential for authorization use cases)
- **Prefix**: NO PREFIX by default (maximum compatibility with RBAC libraries)
- **Security**: Protected claims always blocked, size limits enforced, type validation
- **Flexibility**: Can be disabled, prefix can be added, allowlist/blocklist supported

## Completed ✅

### Commit 1: Type Definitions (20ad0a7)
**File**: `src/auth/types.ts`

Added:
- `CustomClaimsPassthroughConfig` interface with all configuration options
  - `fromAccessToken?: boolean` (default: true)
  - `fromIdToken?: boolean` (default: true)
  - `claimPrefix?: string | false` (default: false - no prefix)
  - `allowedClaims?: string[]` (default: undefined - allow all non-protected)
  - `blockedClaims?: string[]` (default: [])
  - `maxClaimValueSize?: number` (default: 2000)
  - `allowComplexClaims?: boolean` (default: false)

- Updated `OAuthProxyConfig` to include:
  - `customClaimsPassthrough?: CustomClaimsPassthroughConfig | boolean`
  - Documented as enabled by default
  - Can be disabled with `customClaimsPassthrough: false`

**Status**: ✅ Committed and ready

---

### Commit 2: JWTIssuer Updates (b47475d)
**File**: `src/auth/utils/jwtIssuer.ts`

Changes:
- Extended `JWTClaims` interface with index signature: `[key: string]: unknown`
- Updated `issueAccessToken(clientId, scope, additionalClaims?)` to accept optional additional claims
- Updated `issueRefreshToken(clientId, scope, additionalClaims?)` to accept optional additional claims
- Both methods merge additional claims using spread operator

Tests:
- ✅ All 17 existing tests pass
- ✅ Backward compatible (additionalClaims is optional)

**Status**: ✅ Committed and tested

---

## In Progress 🚧

### Implementation Document
**File**: `docs/CLAIMS_EXTRACTOR_IMPLEMENTATION.md`

Created comprehensive implementation guide including:
- Complete ClaimsExtractor class implementation (~180 lines)
- Integration points in OAuthProxy class
- Security considerations
- Usage examples
- Testing strategy

**Status**: ✅ Document created, ready for review

---

## Remaining Work 📋

### 1. Implement ClaimsExtractor Class
**File**: `src/auth/OAuthProxy.ts`

Tasks:
- [ ] Add ClaimsExtractor class before OAuthProxy class definition
- [ ] Add `claimsExtractor: ClaimsExtractor | null` property to OAuthProxy
- [ ] Initialize claimsExtractor in constructor (defaults to enabled)
- [ ] Add import for `CustomClaimsPassthroughConfig` type

**Estimated Lines**: ~180 lines for ClaimsExtractor class + initialization

---

### 2. Add extractUpstreamClaims Method
**File**: `src/auth/OAuthProxy.ts`

Tasks:
- [ ] Implement `extractUpstreamClaims(upstreamTokens)` method
- [ ] Extract claims from access token (if JWT)
- [ ] Extract claims from ID token (if present and JWT)
- [ ] Merge claims (access token takes precedence)
- [ ] Handle errors gracefully

**Estimated Lines**: ~40 lines

---

### 3. Update issueSwappedTokens Method
**File**: `src/auth/OAuthProxy.ts`

Tasks:
- [ ] Call `extractUpstreamClaims()` to get custom claims
- [ ] Pass custom claims to `jwtIssuer.issueAccessToken()`
- [ ] Pass custom claims to `jwtIssuer.issueRefreshToken()`

**Estimated Changes**: 4-6 lines (already mostly implemented in method)

---

### 4. Comprehensive Testing
**File**: `src/auth/OAuthProxy.token-swap.test.ts`

Tests to add:
- [ ] Default behavior - claims passthrough enabled
- [ ] Feature disabled - no claims in proxy token
- [ ] JWT access token - extract custom claims
- [ ] Opaque access token - graceful handling (no claims)
- [ ] ID token claims - extract from ID token
- [ ] Both tokens - merge claims from both sources
- [ ] Precedence - access token claims override ID token
- [ ] Protected claims filtering - verify never copied
- [ ] Allowlist filtering - only allowed claims pass through
- [ ] Blocklist filtering - blocked claims excluded
- [ ] Size limit enforcement - large claims rejected
- [ ] Complex claims - arrays/objects based on config
- [ ] Claim prefix - verify prefix application
- [ ] No prefix - verify direct passthrough
- [ ] Error handling - malformed JWT handled gracefully

**Estimated Lines**: ~400-500 lines of test code

---

### 5. Integration Testing
**Files**: Example OAuth servers

Tasks:
- [ ] Test with GitHub provider
- [ ] Test with Google provider
- [ ] Test with Azure provider
- [ ] Verify real claims (email, name, roles) pass through
- [ ] Test MCP tool authorization with custom claims

---

### 6. Documentation Updates
**Files**: Various docs

Tasks:
- [ ] Update `docs/OAUTH-PROXY.md` with claims passthrough section
- [ ] Add usage examples to README
- [ ] Document security considerations
- [ ] Add migration guide for existing deployments

---

## Current State

### What Works
✅ Configuration types defined and committed
✅ JWTIssuer accepts and merges additional claims
✅ All existing tests pass
✅ Backward compatible (feature can be disabled)

### What's Next
1. **Implement ClaimsExtractor** (next session)
2. **Integrate into OAuthProxy** (next session)
3. **Write comprehensive tests** (next session)
4. **Test with real providers** (next session)

---

## Git Commit History

```
b47475d feat: Update JWTIssuer to support additional custom claims
20ad0a7 feat: Add custom claims passthrough configuration types
b292375 feat: Add OAuth 2.1 Proxy implementation with FastMCP integration
```

---

## Key Decisions Made

1. **Enabled by Default** ✅
   - Rationale: Authorization impossible without custom claims
   - Impact: Works out-of-box for RBAC use cases

2. **No Prefix by Default** ✅
   - Rationale: Maximum compatibility with existing RBAC libraries
   - Impact: Claims like `roles`, `permissions` work directly
   - Trade-off: Requires proxy to never add claims with same names

3. **Protected Claims** ✅
   - Always blocked: `aud`, `iss`, `exp`, `iat`, `nbf`, `jti`, `client_id`
   - Rationale: Prevent security issues from claim collisions

4. **Graceful Degradation** ✅
   - Opaque tokens handled gracefully (no claims extracted)
   - Errors don't break token issuance
   - Missing ID token doesn't cause failures

---

## Testing Notes

All changes maintain backward compatibility:
- Existing code works without modifications
- Optional parameters default to safe values
- Feature can be completely disabled

---

## Next Session Goals

1. Implement ClaimsExtractor class (~30 minutes)
2. Integrate into OAuthProxy (~15 minutes)
3. Write basic tests (~30 minutes)
4. Test with example server (~15 minutes)
5. Commit implementation (~5 minutes)

**Total Estimated Time**: ~90 minutes for complete implementation

---

## Questions for Review

1. ✅ Should feature be enabled by default? **YES** (critical for authorization)
2. ✅ Should we use prefix by default? **NO** (maximum compatibility)
3. ✅ Should we trust upstream tokens without signature verification? **YES** (server-to-server exchange is trusted)
4. ⏳ Should we add logging for debugging? **TBD** (add console.warn for errors)
5. ⏳ Should we support JWKS verification as optional? **TBD** (future enhancement)

---

Last Updated: 2025-01-23
Status: Implementation 60% complete
