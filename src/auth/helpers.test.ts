import { describe, expect, it } from "vitest";

import {
  getAuthSession,
  requireAll,
  requireAny,
  requireAuth,
  requireRole,
  requireScopes,
} from "./helpers.js";

describe("auth helpers", () => {
  describe("requireAuth", () => {
    it("should return true for non-null auth object", () => {
      expect(requireAuth({ userId: "123" })).toBe(true);
      expect(requireAuth({ role: "admin" })).toBe(true);
      expect(requireAuth({})).toBe(true);
    });

    it("should return false for undefined", () => {
      expect(requireAuth(undefined)).toBe(false);
    });

    it("should return false for null", () => {
      expect(requireAuth(null as unknown as undefined)).toBe(false);
    });
  });

  describe("requireScopes", () => {
    it("should return true when all required scopes are present (array)", () => {
      const check = requireScopes("read", "write");
      expect(check({ scopes: ["read", "write", "delete"] })).toBe(true);
      expect(check({ scopes: ["read", "write"] })).toBe(true);
    });

    it("should return false when some scopes are missing", () => {
      const check = requireScopes("read", "write");
      expect(check({ scopes: ["read"] })).toBe(false);
      expect(check({ scopes: ["write"] })).toBe(false);
      expect(check({ scopes: [] })).toBe(false);
    });

    it("should return true when all required scopes are present (Set)", () => {
      const check = requireScopes("read", "write");
      expect(check({ scopes: new Set(["delete", "read", "write"]) })).toBe(
        true,
      );
    });

    it("should return false for undefined auth", () => {
      const check = requireScopes("read");
      expect(check(undefined)).toBe(false);
    });

    it("should return false when scopes property is missing", () => {
      const check = requireScopes("read");
      expect(check({ userId: "123" })).toBe(false);
    });

    it("should work with single scope", () => {
      const check = requireScopes("admin");
      expect(check({ scopes: ["admin"] })).toBe(true);
      expect(check({ scopes: ["user"] })).toBe(false);
    });
  });

  describe("requireRole", () => {
    it("should return true when role matches", () => {
      const check = requireRole("admin");
      expect(check({ role: "admin" })).toBe(true);
    });

    it("should return false when role does not match", () => {
      const check = requireRole("admin");
      expect(check({ role: "user" })).toBe(false);
    });

    it("should return true when role matches any of allowed roles", () => {
      const check = requireRole("admin", "moderator");
      expect(check({ role: "admin" })).toBe(true);
      expect(check({ role: "moderator" })).toBe(true);
      expect(check({ role: "user" })).toBe(false);
    });

    it("should return false for undefined auth", () => {
      const check = requireRole("admin");
      expect(check(undefined)).toBe(false);
    });

    it("should return false when role property is missing", () => {
      const check = requireRole("admin");
      expect(check({ userId: "123" })).toBe(false);
    });

    it("should return false for non-string role", () => {
      const check = requireRole("admin");
      expect(check({ role: 123 })).toBe(false);
      expect(check({ role: null })).toBe(false);
    });
  });

  describe("requireAll", () => {
    it("should return true when all checks pass", () => {
      const check = requireAll(
        requireAuth,
        requireRole("admin"),
        requireScopes("read"),
      );
      expect(check({ role: "admin", scopes: ["read", "write"] })).toBe(true);
    });

    it("should return false when any check fails", () => {
      const check = requireAll(requireAuth, requireRole("admin"));
      expect(check({ role: "user" })).toBe(false);
    });

    it("should return false for undefined auth", () => {
      const check = requireAll(requireAuth);
      expect(check(undefined)).toBe(false);
    });

    it("should work with boolean values", () => {
      const check = requireAll(requireAuth, true);
      expect(check({ userId: "123" })).toBe(true);

      const checkFalse = requireAll(requireAuth, false);
      expect(checkFalse({ userId: "123" })).toBe(false);
    });

    it("should short-circuit on first failure", () => {
      let secondCalled = false;
      const check = requireAll(
        () => false,
        () => {
          secondCalled = true;
          return true;
        },
      );
      check({ userId: "123" });
      expect(secondCalled).toBe(false);
    });
  });

  describe("requireAny", () => {
    it("should return true when any check passes", () => {
      const check = requireAny(requireRole("admin"), requireRole("moderator"));
      expect(check({ role: "admin" })).toBe(true);
      expect(check({ role: "moderator" })).toBe(true);
    });

    it("should return false when all checks fail", () => {
      const check = requireAny(requireRole("admin"), requireRole("moderator"));
      expect(check({ role: "user" })).toBe(false);
    });

    it("should return false for undefined auth when all checks require auth", () => {
      const check = requireAny(requireRole("admin"), requireScopes("read"));
      expect(check(undefined)).toBe(false);
    });

    it("should work with boolean values", () => {
      const check = requireAny(false, requireAuth);
      expect(check({ userId: "123" })).toBe(true);

      const checkAllFalse = requireAny(false, false);
      expect(checkAllFalse({ userId: "123" })).toBe(false);
    });

    it("should short-circuit on first success", () => {
      let secondCalled = false;
      const check = requireAny(
        () => true,
        () => {
          secondCalled = true;
          return true;
        },
      );
      check({ userId: "123" });
      expect(secondCalled).toBe(false);
    });
  });

  describe("complex combinations", () => {
    it("should support nested requireAll and requireAny", () => {
      // (admin OR moderator) AND (read scope)
      const check = requireAll(
        requireAny(requireRole("admin"), requireRole("moderator")),
        requireScopes("read"),
      );

      expect(check({ role: "admin", scopes: ["read"] })).toBe(true);
      expect(check({ role: "moderator", scopes: ["read"] })).toBe(true);
      expect(check({ role: "admin", scopes: ["write"] })).toBe(false);
      expect(check({ role: "user", scopes: ["read"] })).toBe(false);
    });

    it("should support auth with multiple conditions", () => {
      // Must be authenticated AND (admin OR have both read+write scopes)
      const check = requireAll(
        requireAuth,
        requireAny(
          requireRole("admin"),
          requireAll(requireScopes("read"), requireScopes("write")),
        ),
      );

      expect(check({ role: "admin" })).toBe(true);
      expect(check({ role: "user", scopes: ["read", "write"] })).toBe(true);
      expect(check({ role: "user", scopes: ["read"] })).toBe(false);
      expect(check(undefined)).toBe(false);
    });
  });

  describe("getAuthSession", () => {
    it("should return session with OAuthSession type", () => {
      const session = { accessToken: "token123", refreshToken: "refresh123" };
      const result = getAuthSession(session);

      expect(result.accessToken).toBe("token123");
      expect(result.refreshToken).toBe("refresh123");
    });

    it("should throw for undefined session", () => {
      expect(() => getAuthSession(undefined)).toThrow(
        "Session is not authenticated",
      );
    });

    it("should throw for null session", () => {
      expect(() => getAuthSession(null as unknown as undefined)).toThrow(
        "Session is not authenticated",
      );
    });

    it("should work with minimal OAuthSession", () => {
      const session = { accessToken: "token" };
      const result = getAuthSession(session);

      expect(result.accessToken).toBe("token");
    });

    it("should preserve all session properties", () => {
      const session = {
        accessToken: "token",
        claims: { role: "admin" },
        expiresAt: 1234567890,
        idToken: "id-token",
        refreshToken: "refresh",
        scopes: ["read", "write"],
      };
      const result = getAuthSession(session);

      expect(result).toEqual(session);
    });
  });
});
