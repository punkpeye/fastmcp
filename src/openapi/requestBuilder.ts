import type { FastMCPSessionAuth, LoadContext } from "../FastMCP.js";
import type { ParameterMapping } from "./schemas.js";
import type { FromOpenAPIOptions, HttpRoute, OpenApiServer } from "./types.js";

import { UserError } from "../FastMCP.js";

export interface ExecuteRequestOptions {
  args: Record<string, unknown>;
  baseUrlOverride?: string;
  /** Selected body encoding, including an empty required JSON object. */
  bodyEncoding?: "form" | "json";
  /** The MCP call's context, passed to a `headers` function. */
  context?: LoadContext<FastMCPSessionAuth>;
  fetchImpl: typeof fetch;
  headers?: FromOpenAPIOptions["headers"];
  origin?: string;
  parameterMap: Record<string, ParameterMapping>;
  route: HttpRoute;
  servers: OpenApiServer[] | undefined;
  signal?: AbortSignal;
  wholeBodyKey?: string;
}

export interface ExecuteRequestResult {
  /** The response body, parsed, when the response's content-type indicated JSON and it parsed successfully. */
  json?: unknown;
  /** The response body as text — pretty-printed if `json` is set. */
  text: string;
}

export async function executeRequest(
  options: ExecuteRequestOptions,
): Promise<ExecuteRequestResult> {
  const baseUrl = resolveBaseUrl(
    options.servers,
    options.origin,
    options.baseUrlOverride,
  );

  const pathParams: Record<string, string> = Object.create(null);
  const queryParts: string[] = [];
  // A plain object keys headers case-sensitively, so a caller-supplied
  // header (e.g. "Content-Type") wouldn't be recognized as the same header
  // as one this function sets internally (e.g. "content-type") — `Headers`
  // normalizes casing, so `.set()` correctly overrides rather than
  // combining into a comma-joined, malformed value.
  const headers = new Headers(
    await resolveHeaders(options.headers, options.context),
  );
  const bodyProps: Record<string, unknown> = Object.create(null);

  for (const [key, value] of Object.entries(options.args)) {
    const mapping = options.parameterMap[key];

    if (!mapping || value === undefined) {
      continue;
    }

    // RFC 6570, which OpenAPI's parameter styles follow, treats null as
    // undefined, so a null query, header or cookie value is left out rather
    // than sent as the string "null". A body property keeps its JSON null.
    if (
      value === null &&
      (mapping.in === "query" ||
        mapping.in === "header" ||
        mapping.in === "cookie")
    ) {
      continue;
    }

    switch (mapping.in) {
      case "body":
        bodyProps[mapping.name] = value;
        break;
      case "cookie": {
        const pair = `${mapping.name}=${encodeCookieValue(mapping, value)}`;
        const existing = headers.get("cookie");
        headers.set("cookie", existing ? `${existing}; ${pair}` : pair);
        break;
      }
      case "header":
        headers.set(
          mapping.name,
          serializeHeaderValue(value, mapping.style, mapping.explode),
        );
        break;
      case "path":
        pathParams[mapping.name] = encodePathValue(
          value,
          mapping.style,
          mapping.explode,
        );
        break;
      case "query": {
        const query = new URLSearchParams();
        appendQueryValue(
          query,
          mapping.name,
          mapping.style,
          value,
          mapping.explode,
        );
        if (query.size > 0) {
          queryParts.push(serializeQuery(query, mapping.allowReserved));
        }
        break;
      }
    }
  }

  let path = options.route.path;

  for (const [name, value] of Object.entries(pathParams)) {
    path = path.replaceAll(`{${name}}`, value);
  }

  assertNoSubstitutedDotSegments(options.route, path);

  const url = new URL(baseUrl.replace(/\/$/, "") + path);
  url.search = queryParts.join("&");

  let body: string | undefined;

  const requiredJsonBody =
    options.bodyEncoding === "json" &&
    options.route.requestBody?.required === true &&
    !options.wholeBodyKey;

  if (Object.keys(bodyProps).length > 0 || requiredJsonBody) {
    const payload = options.wholeBodyKey
      ? bodyProps[options.wholeBodyKey]
      : bodyProps;

    if (options.bodyEncoding === "form") {
      if (!headers.has("content-type")) {
        headers.set("content-type", "application/x-www-form-urlencoded");
      }

      body = encodeFormBody(payload);
    } else {
      if (!headers.has("content-type")) {
        headers.set("content-type", "application/json");
      }

      body = JSON.stringify(payload);
    }
  }

  const response = await options.fetchImpl(url.toString(), {
    body,
    headers,
    method: options.route.method.toUpperCase(),
    signal: options.signal,
  });

  const text = await response.text();

  if (!response.ok) {
    throw new UserError(
      `${options.route.method.toUpperCase()} ${path} failed with ${response.status}: ${text.slice(0, 2000)}`,
    );
  }

  const mediaType = response.headers.get("content-type")?.split(";")[0];

  if (mediaType?.toLowerCase().includes("json")) {
    try {
      const json: unknown = JSON.parse(text);
      return { json, text: JSON.stringify(json, null, 2) };
    } catch {
      return { text };
    }
  }

  return { text };
}

/**
 * Resolves `servers[0].url` the way a real HTTP client needs it resolved,
 * not just the way a schema validator would accept it: a relative URL (e.g.
 * Petstore's own `"/api/v3"`) is joined against the document's own origin,
 * not passed through verbatim.
 */
export function resolveBaseUrl(
  servers: OpenApiServer[] | undefined,
  origin: string | undefined,
  overrideUrl: string | undefined,
): string {
  if (overrideUrl) {
    return overrideUrl.replace(/\/$/, "");
  }

  const server = servers?.[0];

  if (!server) {
    throw new Error(
      "The OpenAPI document has no `servers` entry. Pass `baseUrl` to fromOpenAPI() explicitly.",
    );
  }

  let url = server.url;

  for (const [name, variable] of Object.entries(server.variables ?? {})) {
    url = url.replaceAll(`{${name}}`, () => variable.default);
  }

  try {
    return new URL(url).toString().replace(/\/$/, "");
  } catch {
    if (!origin) {
      throw new Error(
        `The OpenAPI document's servers[0].url ("${url}") is relative, and the spec was not loaded from an http(s) URL, so it cannot be resolved to an absolute address. Pass \`baseUrl\` to fromOpenAPI() explicitly.`,
      );
    }

    return new URL(url, origin).toString().replace(/\/$/, "");
  }
}

/**
 * Appends `value` under `key`, expanding nested structure with bracket
 * notation rather than JSON-encoding it:
 *
 * - a plain object → `key[subkey]=...` recursively;
 * - an array of scalars → repeated `key=...` entries (the existing,
 *   unchanged convention for both query arrays and form arrays);
 * - an array containing an object → each such item bracket-expands under
 *   `key[]` (PHP/Rails-style, and what Stripe's own list-of-objects form
 *   fields expect);
 * - anything else (including a scalar where an object/array was expected —
 *   e.g. a caller passing a plain value for a `deepObject`-styled query
 *   param) → `key=value` directly, rather than assuming a shape that isn't
 *   there.
 *
 * Shared between `encodeFormBody` (request bodies) and `deepObject` query
 * parameters (`appendQueryValue`) — both need the same expansion.
 */
function appendBracketPairs(
  params: URLSearchParams,
  key: string,
  value: unknown,
): void {
  if (Array.isArray(value)) {
    for (const item of value) {
      if (item !== null && typeof item === "object") {
        appendBracketPairs(params, `${key}[]`, item);
      } else {
        params.append(key, String(item));
      }
    }

    return;
  }

  if (value !== null && typeof value === "object") {
    for (const [subKey, subValue] of Object.entries(
      value as Record<string, unknown>,
    )) {
      if (subValue !== undefined) {
        appendBracketPairs(params, `${key}[${subKey}]`, subValue);
      }
    }

    return;
  }

  params.append(key, String(value));
}

/**
 * Appends a query parameter's value using the serialization its declared
 * `style` requires. `deepObject` and `spaceDelimited`/`pipeDelimited` are
 * real, if less common, OpenAPI styles — Stripe alone uses `deepObject` 354
 * times across its filter/expand-style query params. The default `form`
 * style uses repeated keys for arrays and property pairs for objects unless
 * `explode: false` requests a single comma-separated value. Empty form-style
 * arrays and objects remain omitted.
 */
function appendQueryValue(
  query: URLSearchParams,
  name: string,
  style: string | undefined,
  value: unknown,
  explode: boolean | undefined,
): void {
  if (style === "deepObject") {
    appendBracketPairs(query, name, value);
    return;
  }

  if (style === "spaceDelimited" || style === "pipeDelimited") {
    const items = Array.isArray(value) ? value : [value];
    const separator = style === "spaceDelimited" ? " " : "|";
    query.append(name, items.map(String).join(separator));
    return;
  }

  if (
    (style === undefined || style === "form") &&
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  ) {
    const entries = Object.entries(value as Record<string, unknown>);

    if (explode === false) {
      if (entries.length > 0) {
        query.append(
          name,
          entries.flatMap(([key, item]) => [key, String(item)]).join(","),
        );
      }
    } else {
      for (const [key, item] of entries) {
        query.append(key, String(item));
      }
    }

    return;
  }

  if (
    (style === undefined || style === "form") &&
    explode === false &&
    Array.isArray(value) &&
    value.length > 0
  ) {
    query.append(name, value.map(String).join(","));
    return;
  }

  for (const item of Array.isArray(value) ? value : [value]) {
    query.append(name, String(item));
  }
}

/**
 * `encodeURIComponent` leaves `.` alone, and `new URL()` collapses `.` and `..`
 * path segments, so a path parameter that fills a whole segment with `.` or
 * `..` would drop path segments from the request URL instead of being sent as
 * a value. Percent-encoding can't prevent this (the URL parser treats `%2e` as
 * a dot too, and `encodeURIComponent` already escapes the `%` of any such
 * input), so reject it. A segment the template itself spells as `.` or `..` is
 * the spec author's own and is left alone.
 */
function assertNoSubstitutedDotSegments(
  route: HttpRoute,
  resolvedPath: string,
): void {
  const templateSegments = new Set(route.path.split("/"));

  for (const segment of resolvedPath.split("/")) {
    if (
      (segment === "." || segment === "..") &&
      !templateSegments.has(segment)
    ) {
      throw new UserError(
        `${route.method.toUpperCase()} ${route.path}: path parameter values must not produce a "${segment}" path segment.`,
      );
    }
  }
}

/**
 * Form style (the cookie default) percent-encodes like RFC 6570 form
 * expansion, so `"; "` in a value cannot add cookies of its own. OAS 3.2
 * `style: cookie` sends a value as given, already escaped by the caller, so
 * one holding `;` or `,` is refused instead. Array items are encoded or
 * checked one at a time and then joined with commas, so a comma inside an
 * item stays distinct from the separator.
 */
function encodeCookieValue(mapping: ParameterMapping, value: unknown): string {
  return (Array.isArray(value) ? value : [value])
    .map((item) => {
      const text = String(item);

      if (mapping.style !== "cookie") {
        return encodePathComponent(text);
      }

      if (/[;,]/.test(text)) {
        throw new UserError(
          `Cookie parameter "${mapping.name}" uses style "cookie" and its value contains ";" or ","`,
        );
      }

      return text;
    })
    .join(",");
}

/**
 * Serializes a flattened body payload as `application/x-www-form-urlencoded`,
 * bracket-expanding nested objects/arrays (e.g. Stripe's own
 * `metadata[key]=value` style) via `appendBracketPairs` — the same helper
 * used for `deepObject`-styled query parameters, since both are the same
 * underlying problem: serializing non-scalar values into a position that
 * expects flat key/value pairs, not a JSON blob. `URLSearchParams` handles
 * percent-encoding for free.
 */
function encodeFormBody(payload: unknown): string {
  const params = new URLSearchParams();

  if (payload && typeof payload === "object" && !Array.isArray(payload)) {
    for (const [key, value] of Object.entries(
      payload as Record<string, unknown>,
    )) {
      if (value === undefined) {
        continue;
      }

      appendBracketPairs(params, key, value);
    }
  }

  return params.toString();
}

/** RFC 6570 simple and form expansion escape everything except RFC 3986 unreserved characters. */
function encodePathComponent(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

/**
 * Simple-style arrays use comma-separated items; flat objects use alternating
 * keys/values, or key=value pairs when exploded. Encode each component before
 * adding separators so commas, equals signs and slashes in the data cannot
 * become serialization structure.
 * Other styles/shapes retain their existing whole-value encoding.
 */
function encodePathValue(
  value: unknown,
  style: string | undefined,
  explode: boolean | undefined,
): string {
  if (
    (style === undefined || style === "simple") &&
    Array.isArray(value) &&
    value.every((item) => item === null || typeof item !== "object")
  ) {
    return value.map((item) => encodePathComponent(String(item))).join(",");
  }

  if (
    (style === undefined || style === "simple") &&
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  ) {
    const entries = Object.entries(value as Record<string, unknown>);

    if (
      entries.every(([, item]) => item === null || typeof item !== "object")
    ) {
      return entries
        .map(([key, item]) => {
          const encodedKey = encodePathComponent(key);
          const encodedValue = encodePathComponent(String(item));
          return explode === true
            ? `${encodedKey}=${encodedValue}`
            : `${encodedKey},${encodedValue}`;
        })
        .join(",");
    }
  }

  return encodeURIComponent(String(value));
}

async function resolveHeaders(
  headers: FromOpenAPIOptions["headers"],
  context: LoadContext<FastMCPSessionAuth> | undefined,
): Promise<Record<string, string>> {
  if (!headers) {
    return {};
  }

  return typeof headers === "function"
    ? await headers(context)
    : { ...headers };
}

/**
 * Flat simple-style header objects use alternating keys/values, or key=value
 * pairs when exploded. Unlike a path value, a header is sent as given: OpenAPI
 * 3.2 rules out percent-encoding one, and scalar and array headers are not
 * encoded either. Other styles/shapes retain their existing string conversion.
 */
function serializeHeaderValue(
  value: unknown,
  style: string | undefined,
  explode: boolean | undefined,
): string {
  if (
    (style === undefined || style === "simple") &&
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  ) {
    const entries = Object.entries(value as Record<string, unknown>);

    if (
      entries.every(([, item]) => item === null || typeof item !== "object")
    ) {
      const separator = explode === true ? "=" : ",";

      return entries
        .map(([key, item]) => `${key}${separator}${String(item)}`)
        .join(",");
    }
  }

  return String(value);
}

/**
 * Reserved expansion applies only to values. Keep query/form delimiters and
 * RFC3986-illegal query characters encoded, while preserving existing percent
 * triples. URL serialization may still encode the apostrophe in HTTP(S) URLs.
 */
function serializeQuery(
  query: URLSearchParams,
  allowReserved: boolean | undefined,
): string {
  const encoded = query.toString();

  if (!allowReserved) {
    return encoded;
  }

  return encoded
    .split("&")
    .map((pair) => {
      const [name, value] = pair.split("=");
      const expanded = value.replace(
        /\+|%25([\da-f]{2})|%(21|24|27|28|29|2c|2f|3a|3b|3f|40|7e)/gi,
        (match, triple: string | undefined) =>
          triple
            ? `%${triple}`
            : match === "+"
              ? "%20"
              : decodeURIComponent(match),
      );
      return `${name}=${expanded}`;
    })
    .join("&");
}
