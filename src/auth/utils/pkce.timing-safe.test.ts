import { describe, expect, it, vi } from "vitest";

// Pass-through spy: every other crypto export keeps its real implementation, so
// generateVerifier/generateChallenge behave normally.
//
// This lives in its own file on purpose. Mocking `crypto` is file-scoped, and
// keeping it out of pkce.test.ts means the existing suite runs against the real
// module untouched.
vi.mock("crypto", async (importOriginal) => {
  const real = await importOriginal<typeof import("crypto")>();
  return { ...real, timingSafeEqual: vi.fn(real.timingSafeEqual) };
});

import { timingSafeEqual } from "crypto";

import { PKCEUtils } from "./pkce.js";

/**
 * These assert the *mechanism*, not the behaviour, and that is deliberate.
 *
 * A constant-time comparison returns exactly what `===` returned, so no
 * behavioural test can tell the two apart — I checked: the behavioural cases in
 * pkce.test.ts pass identically with and without the fix. For CWE-208 the
 * mechanism is the contract, so the mechanism is what gets pinned.
 *
 * A statistical timing assertion would be the other option and a bad one: it is
 * flaky under CI load and would fail for reasons unrelated to this code.
 */
describe("PKCEUtils.validateChallenge is constant-time (CWE-208)", () => {
  it("routes the plain branch through timingSafeEqual", () => {
    vi.mocked(timingSafeEqual).mockClear();
    const verifier = PKCEUtils.generateVerifier();

    expect(PKCEUtils.validateChallenge(verifier, verifier, "plain")).toBe(true);
    expect(vi.mocked(timingSafeEqual)).toHaveBeenCalled();
  });

  it("routes the S256 branch through timingSafeEqual", () => {
    vi.mocked(timingSafeEqual).mockClear();
    const verifier = PKCEUtils.generateVerifier();
    const challenge = PKCEUtils.generateChallenge(verifier, "S256");

    expect(PKCEUtils.validateChallenge(verifier, challenge, "S256")).toBe(true);
    expect(vi.mocked(timingSafeEqual)).toHaveBeenCalled();
  });

  // The length guard has to short-circuit: timingSafeEqual throws on buffers of
  // different sizes, which would turn an invalid_grant into a 500 at the token
  // endpoint.
  it("short-circuits on a length mismatch without reaching timingSafeEqual", () => {
    vi.mocked(timingSafeEqual).mockClear();
    const verifier = PKCEUtils.generateVerifier();

    expect(
      PKCEUtils.validateChallenge(`${verifier}extra`, verifier, "plain"),
    ).toBe(false);
    expect(vi.mocked(timingSafeEqual)).not.toHaveBeenCalled();
  });
});
