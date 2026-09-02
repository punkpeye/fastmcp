import type { ParameterMapping } from "./schemas.js";
import type { FromOpenAPIOptions, HttpRoute, OpenApiServer } from "./types.js";

import { UserError } from "../FastMCP.js";

export interface ExecuteRequestOptions {
  args: Record<string, unknown>;
  baseUrlOverride?: string;
  /** How to serialize a request body, if `args` contains any body-mapped values. */
  bodyEncoding?: "form" | "json";
  fetchImpl: typeof fetch;
  headers?: FromOpenAPIOptions["headers"];
  origin?: string;
  parameterMap: Record<string, ParameterMapping>;
  route: HttpRoute;
  servers: OpenApiServer[] | undefined;
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

  const pathParams: Record<string, string> = {};
  const query = new URLSearchParams();
  // A plain object keys headers case-sensitively, so a caller-supplied
  // header (e.g. "Content-Type") wouldn't be recognized as the same header
  // as one this function sets internally (e.g. "content-type") — `Headers`
  // normalizes casing, so `.set()` correctly overrides rather than
  // combining into a comma-joined, malformed value.
  const headers = new Headers(await resolveHeaders(options.headers));
  const bodyProps: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(options.args)) {
    const mapping = options.parameterMap[key];

    if (!mapping || value === undefined) {
      continue;
    }

    switch (mapping.in) {
      case "body":
        bodyProps[mapping.name] = value;
        break;
      case "cookie": {
        const existing = headers.get("cookie");
        headers.set(
          "cookie",
          existing
            ? `${existing}; ${mapping.name}=${String(value)}`
            : `${mapping.name}=${String(value)}`,
        );
        break;
      }
      case "header":
        headers.set(mapping.name, String(value));
        break;
      case "path":
        pathParams[mapping.name] = String(value);
        break;
      case "query":
        appendQueryValue(query, mapping.name, mapping.style, value);
        break;
    }
  }

  let path = options.route.path;

  for (const [name, value] of Object.entries(pathParams)) {
    path = path.replace(`{${name}}`, encodeURIComponent(value));
  }

  const url = new URL(baseUrl.replace(/\/$/, "") + path);
  url.search = query.toString();

  let body: string | undefined;

  if (Object.keys(bodyProps).length > 0) {
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
  });

  const text = await response.text();

  if (!response.ok) {
    throw new UserError(
      `${options.route.method.toUpperCase()} ${path} failed with ${response.status}: ${text.slice(0, 2000)}`,
    );
  }

  if (response.headers.get("content-type")?.includes("json")) {
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
    url = url.replaceAll(`{${name}}`, variable.default);
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
 * times across its filter/expand-style query params. Anything else (no
 * style, or the OpenAPI default `style: "form"`) keeps the existing
 * repeated-key serialization.
 */
function appendQueryValue(
  query: URLSearchParams,
  name: string,
  style: string | undefined,
  value: unknown,
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

  for (const item of Array.isArray(value) ? value : [value]) {
    query.append(name, String(item));
  }
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

async function resolveHeaders(
  headers: FromOpenAPIOptions["headers"],
): Promise<Record<string, string>> {
  if (!headers) {
    return {};
  }

  return typeof headers === "function" ? await headers() : { ...headers };
}
