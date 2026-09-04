/**
 * Client ID Metadata Documents (CIMD) — MCP authorization spec SEP-991.
 *
 * A client presents an HTTPS URL as its `client_id`; the authorization
 * server fetches that URL on demand to read the client's metadata instead
 * of requiring a prior POST /oauth/register call.
 */

import { cancelResponseBody } from "../../cancelResponseBody.js";
import type { DCRClientMetadata, ProxyDCRClient } from "../types.js";

const CIMD_FETCH_TIMEOUT_MS = 5000;

/**
 * How long a resolved document may be reused before it is fetched again.
 * A CIMD document is live — the client can rotate its redirect URIs or stop
 * publishing altogether — so a resolution is a short-lived snapshot, not a
 * registration.
 */
const CIMD_CLIENT_TTL_MS = 15 * 60 * 1000;

/** Max response size accepted, enforced while streaming (not after buffering). */
const CIMD_MAX_RESPONSE_BYTES = 65536;

/**
 * Resolves a CIMD `client_id` into the same shape Dynamic Client
 * Registration produces, stamped with an `expiresAt` so callers re-read the
 * document instead of trusting the snapshot forever. Callers should look up
 * `client_id` in their existing client registry first and only call this on
 * a miss.
 *
 * Never throws — anything that isn't a valid, fetchable, self-consistent
 * CIMD document resolves to `null` so callers can fall through to the
 * ordinary "Unknown client_id" error.
 *
 * @param clientId The `client_id` presented by the client.
 * @param requestedRedirectUri The `redirect_uri` from the current request,
 *   if any; when present it must appear in the document's `redirect_uris`.
 * @param validateRedirectUri The proxy's redirect-URI allow-list check —
 *   every URI in the document must pass it, exactly as DCR requires.
 */
export async function resolveCimdClient(
  clientId: string,
  requestedRedirectUri: string | undefined,
  validateRedirectUri: (uri: string) => boolean,
): Promise<null | ProxyDCRClient> {
  let url: URL;

  try {
    url = new URL(clientId);
  } catch {
    return null;
  }

  // CIMD requires an HTTPS URL with no query string.
  if (url.protocol !== "https:" || url.search) {
    return null;
  }

  if (isPrivateOrLoopbackHost(url.hostname)) {
    return null;
  }

  let response: Response;

  try {
    response = await fetch(clientId, {
      redirect: "error",
      signal: AbortSignal.timeout(CIMD_FETCH_TIMEOUT_MS),
    });
  } catch {
    return null;
  }

  if (!response.ok) {
    await cancelResponseBody(response);
    return null;
  }

  const text = await readBoundedText(response);

  if (text === null) {
    return null;
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }

  if (typeof parsed !== "object" || parsed === null) {
    return null;
  }

  const doc = parsed as Record<string, unknown>;

  // The document must self-identify by the exact URL it was fetched from,
  // or any HTTPS host could vouch for any other client_id.
  if (doc.client_id !== clientId) {
    return null;
  }

  if (!isStringArray(doc.redirect_uris) || doc.redirect_uris.length === 0) {
    return null;
  }

  const redirectUris = doc.redirect_uris;

  if (requestedRedirectUri && !redirectUris.includes(requestedRedirectUri)) {
    return null;
  }

  if (!redirectUris.every((uri) => validateRedirectUri(uri))) {
    return null;
  }

  const metadata: DCRClientMetadata = {
    client_name: optionalString(doc.client_name),
    client_uri: optionalString(doc.client_uri),
    logo_uri: optionalString(doc.logo_uri),
    policy_uri: optionalString(doc.policy_uri),
    scope: optionalString(doc.scope),
    tos_uri: optionalString(doc.tos_uri),
  };

  return {
    callbackUrl: redirectUris[0],
    clientId,
    // CIMD is a public-client mechanism secured by PKCE; there is no secret.
    clientSecret: undefined,
    expiresAt: new Date(Date.now() + CIMD_CLIENT_TTL_MS),
    metadata,
    redirectUris,
    registeredAt: new Date(),
    source: "cimd",
  };
}

/** Expands a (possibly `::`-abbreviated) IPv6 address into 8 16-bit groups. */
function expandIPv6(host: string): null | number[] {
  const sides = host.split("::");

  if (sides.length > 2) {
    return null;
  }

  const head = sides[0] ? sides[0].split(":") : [];
  const tail = sides.length === 2 && sides[1] ? sides[1].split(":") : [];

  if (sides.length === 1 && head.length !== 8) {
    return null;
  }

  const missing = 8 - head.length - tail.length;

  if (missing < 0) {
    return null;
  }

  const parts = [...head, ...Array<string>(missing).fill("0"), ...tail];

  if (parts.length !== 8) {
    return null;
  }

  const groups = parts.map((g) => Number.parseInt(g || "0", 16));
  return groups.every((g) => !Number.isNaN(g)) ? groups : null;
}

/**
 * Rejects hosts that are, by literal form, loopback/link-local/private-range
 * addresses (IPv4 and IPv6, including IPv4-mapped IPv6). Defends against a
 * CIMD `client_id` pointing the proxy's outbound fetch at internal
 * infrastructure (CWE-918 SSRF) — e.g. a cloud metadata endpoint.
 *
 * Literal-form only, not DNS-resolution-based: one layer of defence, not a
 * complete SSRF mitigation (does not defend against DNS rebinding).
 */
function isPrivateOrLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");

  if (host === "localhost" || host === "0.0.0.0") {
    return true;
  }

  if (host.includes(":")) {
    return isPrivateOrLoopbackIPv6(host);
  }

  return (
    host === "127.0.0.1" ||
    /^169\.254\./.test(host) ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host)
  );
}

function isPrivateOrLoopbackIPv6(host: string): boolean {
  const groups = expandIPv6(host);

  if (!groups) {
    return false;
  }

  if (groups.every((g) => g === 0)) {
    return true; // :: (unspecified)
  }

  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) {
    return true; // ::1 (loopback)
  }

  const [first] = groups;

  if ((first & 0xffc0) === 0xfe80) {
    return true; // fe80::/10 (link-local)
  }

  if ((first & 0xfe00) === 0xfc00) {
    return true; // fc00::/7 (unique-local)
  }

  // IPv4-mapped/-compatible (::ffff:a.b.c.d or ::a.b.c.d): check the
  // embedded IPv4 address against the same rules.
  if (
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    (groups[5] === 0 || groups[5] === 0xffff)
  ) {
    const ipv4 = `${groups[6] >> 8}.${groups[6] & 0xff}.${groups[7] >> 8}.${groups[7] & 0xff}`;
    return isPrivateOrLoopbackHost(ipv4);
  }

  return false;
}

function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((item) => typeof item === "string")
  );
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/**
 * Reads a fetch `Response` body up to `CIMD_MAX_RESPONSE_BYTES`, aborting
 * the stream (rather than buffering it fully first) once the cap is
 * exceeded. Returns `null` on any error or if the cap is hit.
 */
async function readBoundedText(response: Response): Promise<null | string> {
  const contentLength = response.headers.get("content-length");

  if (contentLength && Number(contentLength) > CIMD_MAX_RESPONSE_BYTES) {
    await cancelResponseBody(response);
    return null;
  }

  const reader = response.body?.getReader();

  if (!reader) {
    return null;
  }

  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();

      if (done) {
        break;
      }

      totalBytes += value.byteLength;

      if (totalBytes > CIMD_MAX_RESPONSE_BYTES) {
        await reader.cancel();
        return null;
      }

      chunks.push(value);
    }
  } catch {
    return null;
  }

  return Buffer.concat(chunks).toString("utf-8");
}
