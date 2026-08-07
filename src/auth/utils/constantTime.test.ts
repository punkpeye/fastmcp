import { describe, expect, it } from "vitest";

import { equalsConstantTime } from "./constantTime.js";

describe("equalsConstantTime", () => {
  it("accepts identical strings", () => {
    expect(equalsConstantTime("abc123", "abc123")).toBe(true);
  });

  it("rejects a same-length difference", () => {
    // Same length, so this reaches timingSafeEqual rather than short-circuiting
    // on the length guard.
    expect(equalsConstantTime("abc123", "abc124")).toBe(false);
  });

  it("rejects a difference in the first byte", () => {
    expect(equalsConstantTime("abc123", "zbc123")).toBe(false);
  });

  it("returns false on a length mismatch instead of throwing", () => {
    // timingSafeEqual throws on buffers of different sizes. Callers are not all
    // inside a try/catch — PKCEUtils.validateChallenge is not, and its caller is
    // the token endpoint — so a throw here would surface as a 500.
    expect(() => equalsConstantTime("abc", "abcdef")).not.toThrow();
    expect(equalsConstantTime("abc", "abcdef")).toBe(false);
    expect(equalsConstantTime("abcdef", "abc")).toBe(false);
  });

  it("treats two empty strings as equal", () => {
    // Documented contract, not an oversight: callers must reject empty input
    // themselves rather than relying on this to fail closed.
    expect(equalsConstantTime("", "")).toBe(true);
  });

  it("rejects an empty string against a non-empty one", () => {
    expect(equalsConstantTime("", "secret")).toBe(false);
    expect(equalsConstantTime("secret", "")).toBe(false);
  });

  it("compares multi-byte characters by their utf8 bytes", () => {
    expect(equalsConstantTime("café", "café")).toBe(true);
    // "café" is 5 utf8 bytes and "cafe" is 4, so these differ in length too.
    expect(equalsConstantTime("café", "cafe")).toBe(false);
  });
});
