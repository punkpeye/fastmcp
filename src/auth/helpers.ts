/**
 * Authentication Helper Functions
 * Utility functions for use with canAccess on tools, resources, and prompts
 */

import type { OAuthSession } from "./providers/AuthProvider.js";

type SessionAuth = Record<string, unknown> | undefined;

/**
 * Extract and type-cast OAuth session from canAccess context.
 * Throws if session is undefined (use with canAccess: requireAuth).
 */
export function getAuthSession<T extends OAuthSession = OAuthSession>(
  session: SessionAuth,
): T {
  if (!session) {
    throw new Error("Session is not authenticated");
  }
  return session as T;
}

/**
 * Combines multiple canAccess checks with AND logic.
 */
export function requireAll<T extends SessionAuth>(
  ...checks: Array<((auth: T) => boolean) | boolean>
): (auth: T) => boolean {
  return (auth: T): boolean =>
    checks.every((check) =>
      typeof check === "function" ? check(auth) : check,
    );
}

/**
 * Combines multiple canAccess checks with OR logic.
 */
export function requireAny<T extends SessionAuth>(
  ...checks: Array<((auth: T) => boolean) | boolean>
): (auth: T) => boolean {
  return (auth: T): boolean =>
    checks.some((check) => (typeof check === "function" ? check(auth) : check));
}

/**
 * Requires any authenticated session.
 */
export function requireAuth<T extends SessionAuth>(auth: T): boolean {
  return auth !== undefined && auth !== null;
}

/**
 * Requires session to have a specific role (OR logic for multiple roles).
 */
export function requireRole<T extends SessionAuth>(
  ...allowedRoles: string[]
): (auth: T) => boolean {
  return (auth: T): boolean => {
    if (!auth) return false;
    const role = (auth as Record<string, unknown>).role;
    return typeof role === "string" && allowedRoles.includes(role);
  };
}

/**
 * Requires session to have specific scopes.
 */
export function requireScopes<T extends SessionAuth>(
  ...requiredScopes: string[]
): (auth: T) => boolean {
  return (auth: T): boolean => {
    if (!auth) return false;
    const authScopes = (auth as Record<string, unknown>).scopes;
    if (!authScopes) return false;

    const scopeSet = Array.isArray(authScopes)
      ? new Set(authScopes)
      : authScopes instanceof Set
        ? authScopes
        : new Set();

    return requiredScopes.every((scope) => scopeSet.has(scope));
  };
}
