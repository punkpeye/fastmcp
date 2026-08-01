import { describe, expect, it } from "vitest";

import type { ConsentData } from "../types.js";

import { ConsentManager } from "./consent.js";

describe("ConsentManager.validateConsentCookie", () => {
  const manager = new ConsentManager("test-secret-key");
  const data: ConsentData = {
    clientName: "MCP Client",
    provider: "github",
    scope: ["read"],
    timestamp: Date.now(),
    transactionId: "txn-1",
  };

  it("round-trips a validly signed cookie", () => {
    const cookie = manager.signConsentCookie(data);
    const result = manager.validateConsentCookie(cookie);

    expect(result?.transactionId).toBe("txn-1");
    expect(result?.provider).toBe("github");
  });

  // Regression test for CWE-208: the cookie's HMAC signature is compared with
  // crypto.timingSafeEqual behind a length guard.
  it("rejects a same-length forged signature", () => {
    const cookie = manager.signConsentCookie(data);
    const [payloadB64, signature] = cookie.split(".");
    // Flip one hex char while preserving length → exercises timingSafeEqual.
    const forged = (signature[0] === "a" ? "b" : "a") + signature.slice(1);
    expect(forged).toHaveLength(signature.length);
    expect(forged).not.toBe(signature);

    expect(manager.validateConsentCookie(`${payloadB64}.${forged}`)).toBeNull();
  });

  it("rejects a different-length signature", () => {
    const cookie = manager.signConsentCookie(data);
    const [payloadB64, signature] = cookie.split(".");

    expect(
      manager.validateConsentCookie(`${payloadB64}.${signature}extra`),
    ).toBeNull();
  });
});
