/**
 * Constant-time string comparison, shared by every secret comparison in the
 * auth module.
 */

import { timingSafeEqual } from "crypto";

/**
 * Compare two strings without leaking, through timing, how many leading bytes
 * match (CWE-208).
 *
 * A plain `===`/`!==` short-circuits on the first differing byte. Where one
 * operand is attacker-supplied and the other is a secret — a cookie HMAC, a JWT
 * signature, a PKCE challenge — that difference is an oracle for recovering the
 * secret byte by byte.
 *
 * Contract, because callers depend on all four points:
 *
 * - Operands are compared as utf8 bytes.
 * - A length mismatch returns `false`. `timingSafeEqual` throws on buffers of
 *   different sizes, so the length has to be checked first; that check is not
 *   itself constant time, so callers must be sure their operand *lengths* are
 *   not secret. At every current call site the expected value is a
 *   fixed-length digest or an RFC-bounded verifier, so the length reveals
 *   nothing.
 * - It never throws for string inputs. Not every caller is inside a try/catch —
 *   `PKCEUtils.validateChallenge` is not, and its caller is the token
 *   endpoint — so a throw here would be a 500 rather than a rejected grant.
 * - Two empty strings compare **equal**. Callers must reject empty or missing
 *   input themselves rather than relying on this to fail closed.
 */
export function equalsConstantTime(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
}
