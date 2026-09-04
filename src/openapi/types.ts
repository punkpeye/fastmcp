import type { FastMCP, FastMCPSessionAuth } from "../FastMCP.js";

/**
 * A minimal, hand-typed slice of a bundled OpenAPI 3.x document — just the
 * parts this module reads. Deliberately not the full `openapi-types` shape,
 * to avoid taking on that dependency for typing alone.
 */
export interface BundledOpenApiDocument {
  components?: {
    schemas?: Record<string, OpenApiSchema>;
  };
  info?: {
    title?: string;
  };
  openapi?: string;
  paths?: Record<string, RawPathItem>;
  servers?: OpenApiServer[];
  swagger?: string;
}

export interface FromOpenAPIOptions {
  /**
   * Overrides the resolved `servers[0].url`. Required when the spec has no
   * `servers` entry, or has a relative `servers[0].url` and was not loaded
   * from an http(s) URL.
   */
  baseUrl?: string;

  /**
   * Excludes operations for which this returns `true`. Applied after
   * `include`.
   */
  exclude?: (operation: OperationSummary) => boolean;

  /**
   * HTTP client used to execute generated tool calls. Defaults to the global
   * `fetch`.
   */
  fetch?: typeof fetch;

  /**
   * Static or dynamically-resolved headers (e.g. an auth token) sent with
   * every generated tool call.
   */
  headers?:
    | (() => Promise<Record<string, string>> | Record<string, string>)
    | Record<string, string>;

  /**
   * Only keeps operations for which this returns `true`.
   */
  include?: (operation: OperationSummary) => boolean;

  /**
   * Hard cap on the number of generated tools. `fromOpenAPI` throws rather
   * than silently truncating if the operation count (after `include`/
   * `exclude`) exceeds this — or a default threshold, if neither this nor
   * `include`/`exclude` was provided.
   */
  maxTools?: number;

  /**
   * Overrides the generated tool name for a given `operationId`.
   */
  mcpNames?: Record<string, string>;

  /**
   * Name for a newly-created server. Ignored when `server` is provided.
   * @default the spec's `info.title`, or "OpenAPI Server"
   */
  name?: string;

  /**
   * When `true`, an eligible `GET` operation becomes an MCP resource (no
   * path/query parameters) or resource template (path and/or query
   * parameters) instead of a tool. A `GET` with any `header`/`cookie`
   * parameter, or any array-typed path/query parameter, stays a tool
   * regardless — see docs/openapi.md "GET → resources".
   * @default false
   */
  resources?: boolean;

  /**
   * An existing `FastMCP` server to register the generated tools onto,
   * instead of creating a new one.
   */
  server?: FastMCP<FastMCPSessionAuth>;

  /**
   * A URL, a file path, or an already-parsed OpenAPI document.
   *
   * Passing a URL or file path (rather than a parsed object) is what lets
   * external `$ref`s and a relative `servers[0].url` resolve correctly — both
   * are resolved relative to this value.
   */
  spec: Record<string, unknown> | string;

  /**
   * Version for a newly-created server. Ignored when `server` is provided.
   * @default "1.0.0"
   */
  version?: `${number}.${number}.${number}`;
}

export type HttpMethod = "delete" | "get" | "patch" | "post" | "put";

export interface HttpRoute {
  deprecated: boolean;
  method: HttpMethod;
  operationId?: string;
  parameters: OpenApiParameter[];
  path: string;
  requestBody?: OpenApiRequestBody;
  /**
   * Keyed by HTTP status code (e.g. `"200"`), as declared in the spec.
   * Populated regardless of `method` — unlike `requestBody`, there's no
   * equivalent to the GET-never-has-a-body rule for responses.
   */
  responses?: Record<string, OpenApiResponse>;
  summary?: string;
  tags: string[];
}

export interface OpenApiParameter {
  deprecated?: boolean;
  description?: string;
  in: ParameterLocation;
  name: string;
  required?: boolean;
  schema?: OpenApiSchema;
  /**
   * Only meaningful for `in: "query"`. `"deepObject"`, `"spaceDelimited"`,
   * and `"pipeDelimited"` get dedicated serialization in requestBuilder.ts;
   * anything else (including unset, which defaults to `"form"` per the
   * OpenAPI spec) uses the default repeated-key serialization.
   */
  style?: string;
}

export interface OpenApiParameterRef {
  $ref: string;
}

export interface OpenApiRequestBody {
  content?: Record<string, { schema?: OpenApiSchema }>;
  required?: boolean;
}

export interface OpenApiResponse {
  content?: Record<string, { schema?: OpenApiSchema }>;
}

/**
 * A raw OpenAPI/JSON Schema fragment as it appears inside the document
 * (a parameter's `schema`, a `components.schemas` entry, etc.). Unlike
 * `JsonSchemaObject` (jsonSchemaAdapter.ts), these are not required to carry
 * a top-level `type` — a bare `$ref`, `allOf`, or `enum`-only node is valid
 * JSON Schema and shows up constantly in real specs. Only the final,
 * assembled per-tool schema needs to satisfy `JsonSchemaObject` (see
 * `schemas.ts`).
 */
export type OpenApiSchema = Record<string, unknown>;

export interface OpenApiServer {
  url: string;
  variables?: Record<string, OpenApiServerVariable>;
}

export interface OpenApiServerVariable {
  default: string;
}

/**
 * The subset of a route's shape exposed to `include`/`exclude` predicates.
 */
export interface OperationSummary {
  deprecated: boolean;
  method: HttpMethod;
  operationId?: string;
  path: string;
  tags: string[];
}

export type ParameterLocation = "cookie" | "header" | "path" | "query";

export interface RawOperation {
  deprecated?: boolean;
  operationId?: string;
  parameters?: (OpenApiParameter | OpenApiParameterRef)[];
  requestBody?: OpenApiParameterRef | OpenApiRequestBody;
  responses?: Record<string, OpenApiParameterRef | OpenApiResponse>;
  summary?: string;
  tags?: string[];
}

export type RawPathItem = {
  parameters?: (OpenApiParameter | OpenApiParameterRef)[];
} & Partial<Record<HttpMethod, RawOperation>>;
