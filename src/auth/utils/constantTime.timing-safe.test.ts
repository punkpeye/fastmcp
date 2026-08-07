import { describe, expect, it, vi } from "vitest";

import type { ConsentData } from "../types.js";

// Pass-through spy: every other crypto export keeps its real implementation, so
// signing and key derivation behave normally.
//
// This lives in its own file on purpose. Mocking `crypto` is file-scoped, so
// consent.test.ts and jwtIssuer.test.ts keep running against the real module.
vi.mock("crypto", async (importOriginal) => {
  const real = await importOriginal<typeof import("crypto")>();
  return { ...real, timingSafeEqual: vi.fn(real.timingSafeEqual) };
});

import { timingSafeEqual } from "crypto";

import { ConsentManager } from "./consent.js";
import { JWTIssuer } from "./jwtIssuer.js";

/**
 * These assert the *mechanism*, and that is the point of the shared helper.
 *
 * A constant-time comparison returns exactly what `===` returned, so no
 * behavioural test can tell the two apart — pkce.timing-safe.test.ts says the
 * same thing about the PKCE challenge. The consequence is that until this file
 * existed, the cookie signature in consent.ts and the JWT signature in
 * jwtIssuer.ts could both have been reverted to `!==` with the whole suite
 * still green: their own tests are purely behavioural.
 *
 * A statistical timing assertion would be the other option and a bad one: it is
 * flaky under CI load and would fail for reasons unrelated to this code.
 */
describe("auth secret comparisons are constant-time (CWE-208)", () => {
  const consentData: ConsentData = {
    clientName: "MCP Client",
    provider: "github",
    scope: ["read"],
    timestamp: Date.now(),
    transactionId: "txn-1",
  };

  it("routes the consent cookie signature through timingSafeEqual", () => {
    vi.mocked(timingSafeEqual).mockClear();
    const manager = new ConsentManager("test-secret-key");
    const cookie = manager.signConsentCookie(consentData);

    expect(manager.validateConsentCookie(cookie)).not.toBeNull();
    expect(vi.mocked(timingSafeEqual)).toHaveBeenCalled();
  });

  it("short-circuits a consent signature of the wrong length", () => {
    vi.mocked(timingSafeEqual).mockClear();
    const manager = new ConsentManager("test-secret-key");
    const [payloadB64, signature] = manager
      .signConsentCookie(consentData)
      .split(".");

    expect(
      manager.validateConsentCookie(`${payloadB64}.${signature}extra`),
    ).toBeNull();
    expect(vi.mocked(timingSafeEqual)).not.toHaveBeenCalled();
  });

  it("routes the JWT signature through timingSafeEqual", async () => {
    const issuer = new JWTIssuer({
      audience: "https://example.com",
      issuer: "https://oauth.example.com",
      signingKey: "test-secret-key",
    });
    const token = issuer.issueAccessToken("client-123", ["read"]);

    vi.mocked(timingSafeEqual).mockClear();
    const result = await issuer.verify(token);

    expect(result.valid).toBe(true);
    expect(vi.mocked(timingSafeEqual)).toHaveBeenCalled();
  });

  it("short-circuits a JWT signature of the wrong length", async () => {
    const issuer = new JWTIssuer({
      audience: "https://example.com",
      issuer: "https://oauth.example.com",
      signingKey: "test-secret-key",
    });
    const [headerB64, payloadB64, signature] = issuer
      .issueAccessToken("client-123", ["read"])
      .split(".");

    vi.mocked(timingSafeEqual).mockClear();
    const result = await issuer.verify(
      `${headerB64}.${payloadB64}.${signature}extra`,
    );

    // The length guard has to run before timingSafeEqual, which throws on
    // buffers of different sizes.
    expect(result.valid).toBe(false);
    expect(vi.mocked(timingSafeEqual)).not.toHaveBeenCalled();
  });
});
