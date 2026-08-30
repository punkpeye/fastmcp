/**
 * Client ID Metadata Documents (CIMD)
 *
 * Implements the client-identification mechanism introduced to the MCP
 * authorization spec by SEP-991, positioned as the successor to Dynamic
 * Client Registration: instead of calling POST /oauth/register, a client
 * presents an HTTPS URL as its `client_id`, and the authorization server
 * fetches that URL on demand to read the client's metadata. Nothing is
 * written on the server side ahead of time, so there is no registration
 * database to grow, no client to expire, and no unauthenticated /register
 * endpoint to abuse.
 */

import type { DCRClientMetadata, ProxyDCRClient } from "../types.js";

const CIMD_FETCH_TIMEOUT_MS = 5000;

/** Refuses documents larger than this before attempting to parse them. */
const CIMD_MAX_RESPONSE_BYTES = 65536;

/**
 * Resolves a CIMD `client_id` into the same shape Dynamic Client
 * Registration produces, so every downstream consumer — authorize, token
 * exchange, storage — can treat a CIMD client and a DCR client identically
 * once this returns.
 *
 * Callers are expected to try `client_id` against their existing client
 * registry first and only reach this function on a miss: a `client_id` a
 * previous CIMD or DCR call already registered is found there and should
 * never reach here again.
 *
 * Never throws. Anything that isn't a valid, fetchable, self-consistent CIMD
 * document resolves to `null`, so callers can fall through to the ordinary
 * "Unknown client_id" error rather than distinguish "not CIMD" from "invalid
 * CIMD" — RFC 6749 §5.2 gives an attacker no more information from one
 * outcome than the other anyway.
 *
 * @param clientId The `client_id` presented by the client.
 * @param requestedRedirectUri The `redirect_uri` from the current request,
 *   if any. When present, the resolved document's `redirect_uris` must
 *   include it. Token-exchange call sites that don't carry a `redirect_uri`
 *   may omit this and rely on `validateRedirectUri` plus the fact that
 *   `authorize()` already validated the pairing for this transaction.
 * @param validateRedirectUri The proxy's own redirect-URI allow-list check
 *   (`OAuthProxy.validateRedirectUri`) — every URI in the document must pass
 *   it, exactly as DCR's `registerClient` already requires. A CIMD document
 *   cannot claim a redirect URI this deployment wouldn't otherwise accept.
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
    return null;
  }

  let text: string;

  try {
    text = await response.text();
  } catch {
    return null;
  }

  if (text.length > CIMD_MAX_RESPONSE_BYTES) {
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

  // The document must identify itself by the exact URL it was fetched from —
  // otherwise it says nothing about who actually controls `clientId`, and any
  // HTTPS host could vouch for any other client_id.
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
    // CIMD is a public-client mechanism: the URL is the identity, and there
    // is no secret-issuance step for a downstream check to rely on. The flow
    // is secured by PKCE instead, exactly as for a DCR client that requested
    // `token_endpoint_auth_method: "none"`.
    clientSecret: undefined,
    metadata,
    redirectUris,
    registeredAt: new Date(),
  };
}

/**
 * Rejects hosts that are, by their literal form, loopback or link-local/
 * private-range addresses. This defends against a CIMD `client_id` pointing
 * the proxy's own outbound fetch at internal infrastructure — e.g. a cloud
 * metadata endpoint on 169.254.169.254 — which is CWE-918 Server-Side
 * Request Forgery.
 *
 * This is a literal-form check only, not DNS-resolution-based, so it does
 * not defend against DNS rebinding (a hostname that resolves to a private
 * address only after this check runs). Treat it as one layer of defence,
 * not a complete SSRF mitigation.
 */
function isPrivateOrLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase();

  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "::1" ||
    host === "0.0.0.0"
  ) {
    return true;
  }

  return (
    /^169\.254\./.test(host) || // link-local, includes cloud metadata endpoints
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host)
  );
}

function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((item) => typeof item === "string")
  );
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}
