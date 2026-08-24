import { describe, expect, it } from "vitest";

import { ClaimsExtractor } from "./claimsExtractor.js";

/** Build a JWT-format token whose payload carries the given claims. */
function jwtWith(claims: Record<string, unknown>): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "none", typ: "JWT" }),
  ).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return `${header}.${payload}.sig`;
}

describe("ClaimsExtractor custom-claims passthrough", () => {
  it("passes an ordinary custom claim through", async () => {
    const extractor = new ClaimsExtractor(true);
    const claims = await extractor.extract(
      jwtWith({ department: "eng" }),
      "access",
    );
    expect(claims).toEqual({ department: "eng" });
  });

  it("never copies the proxy-issued `scope` claim from upstream", async () => {
    // `scope` is a first-class claim the proxy issues itself as an
    // authorization decision (see JWTClaims). Letting an upstream token
    // overwrite it would silently replace the scope embedded in the signed
    // FastMCP JWT, diverging from the mapping and the token response.
    const extractor = new ClaimsExtractor(true);
    const claims = await extractor.extract(
      jwtWith({ department: "eng", scope: "admin superuser" }),
      "access",
    );
    expect(claims).not.toHaveProperty("scope");
    expect(claims).toEqual({ department: "eng" });
  });
});
