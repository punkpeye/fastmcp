import type { JsonSchemaObject } from "../jsonSchemaAdapter.js";
import type {
  BundledOpenApiDocument,
  HttpRoute,
  OpenApiParameter,
  OpenApiRequestBody,
  OpenApiSchema,
  ParameterLocation,
} from "./types.js";

/**
 * Keys whose values are name-to-schema maps: their child keys are
 * author-chosen names rather than JSON Schema keywords.
 */
const SCHEMA_MAP_KEYS = new Set([
  "$defs",
  "definitions",
  "dependentSchemas",
  "patternProperties",
  "properties",
]);

/**
 * Keys whose values are arbitrary instance data rather than schemas. A
 * sample payload may well contain a "$ref" or "nullable" key of its own.
 */
const DATA_KEYS = new Set(["const", "default", "enum", "example", "examples"]);

/**
 * Keys whose values are dropped entirely — not just left unwalked as
 * `DATA_KEYS` are — when building a schema that gets handed to AJV. Real
 * specs (Box) embed full, realistic sample objects under `example`, which
 * can coincidentally contain fields shaped like JSON Schema keywords (e.g.
 * Box's own `$id` concept on a metadata object, reusing the same example
 * value across multiple schemas). AJV's `$id`-discovery pass doesn't know
 * these are documentation rather than schema, and throws
 * ("reference ... resolves to more than one schema") on the collision.
 * These keys carry zero validation meaning, so dropping them removes the
 * only thing AJV could misinterpret this way — and shrinks the schema
 * advertised to clients besides.
 */
const STRIP_KEYS = new Set(["example", "examples"]);

/**
 * Request body content types this module knows how to flatten and encode.
 * `application/json` wins when a route declares both.
 */
export const SUPPORTED_BODY_CONTENT_TYPES = [
  "application/json",
  "application/x-www-form-urlencoded",
] as const;

export interface FlatSchemaResult {
  /** How the request body (if any properties were extracted) must be serialized. */
  bodyEncoding?: "form" | "json";
  flatSchema: JsonSchemaObject;
  parameterMap: Record<string, ParameterMapping>;
  /**
   * Set when `route.requestBody` declares a body this module can't carry:
   * either only in content type(s) it doesn't support (e.g.
   * `multipart/form-data`, `application/json-patch+json`,
   * `application/octet-stream`), or as `application/x-www-form-urlencoded`
   * with a schema that isn't a flat object, which form encoding can't
   * represent. Holds the content type the body was declared in. The caller
   * should not turn this route into a tool with a payload it can never
   * carry — see `fromOpenAPI.ts`.
   */
  unsupportedBodyContentType?: string;
  /**
   * Set when the request body's schema is not a flat object (e.g. an array,
   * or a bare non-object `$ref`) — the whole body is exposed as a single
   * property under this key, rather than flattened into individual
   * properties.
   */
  wholeBodyKey?: string;
}

export interface ParameterMapping {
  in: "body" | ParameterLocation;
  name: string;
  /** Only meaningful for `in: "query"` — see `OpenApiParameter.style`. */
  style?: string;
}

type WalkMode = "data" | "schema" | "schemaMap";

/**
 * Flattens a route's path/query/header/cookie parameters and request body
 * into a single tool input schema.
 *
 * Collision precedence ports the Python implementation's rule
 * (`utilities/openapi/schemas.py:_combine_schemas_and_map_params`): a name
 * that collides across path/query/header/cookie gets suffixed
 * `{name}__{location}`; a request body property with a colliding name always
 * keeps its bare name.
 *
 * `GET` never contributes a request body: `fetch` (and the Fetch spec in
 * general) rejects a body on a GET request, so a tool built from a spec's
 * (legal, if unusual) `GET` + `requestBody` operation would be permanently
 * broken. The request body is simply not flattened into the schema for such
 * a route, rather than surfacing a schema that can never actually be called.
 */
export function buildFlatSchema(
  route: HttpRoute,
  sharedDefs: Record<string, OpenApiSchema> | undefined,
): FlatSchemaResult {
  const byName = new Map<string, OpenApiParameter[]>();

  for (const param of route.parameters) {
    const list = byName.get(param.name) ?? [];
    list.push(param);
    byName.set(param.name, list);
  }

  const {
    bodyEncoding,
    properties: bodyProperties,
    unsupportedBodyContentType,
    wholeBodyKey,
  } = extractBodyProperties(
    route.method === "get" ? undefined : route.requestBody,
    sharedDefs,
  );

  const properties: Record<string, OpenApiSchema> = {};
  const required: string[] = [];
  const parameterMap: Record<string, ParameterMapping> = {};

  for (const [name, occurrences] of byName) {
    const collides = occurrences.length > 1 || bodyProperties.has(name);

    for (const param of occurrences) {
      const key = collides ? `${name}__${param.in}` : name;

      properties[key] = rewriteComponentRefs(
        param.schema ?? { type: "string" },
      );
      parameterMap[key] = { in: param.in, name, style: param.style };

      if (param.in === "path" || param.required) {
        required.push(key);
      }
    }
  }

  for (const [name, { required: isRequired, schema }] of bodyProperties) {
    properties[name] = rewriteComponentRefs(schema);
    parameterMap[name] = { in: "body", name };

    if (isRequired) {
      required.push(name);
    }
  }

  const flatSchema: JsonSchemaObject = {
    additionalProperties: false,
    properties,
    type: "object",
    ...(required.length > 0 ? { required } : {}),
  };

  // Only the definitions this tool's own schema actually (transitively)
  // references — embedding the whole document's components.schemas into
  // every single tool would multiply the tools/list payload size by the
  // tool count for no benefit.
  const usedDefs = sharedDefs && filterReferencedDefs(properties, sharedDefs);

  if (usedDefs) {
    flatSchema.$defs = usedDefs;
  }

  return {
    bodyEncoding,
    flatSchema,
    parameterMap,
    unsupportedBodyContentType,
    wholeBodyKey,
  };
}

export function buildSharedDefs(
  document: BundledOpenApiDocument,
): Record<string, OpenApiSchema> | undefined {
  const schemas = document.components?.schemas;

  if (!schemas || Object.keys(schemas).length === 0) {
    return undefined;
  }

  return rewriteNode(schemas, "schemaMap") as Record<string, OpenApiSchema>;
}

const SUCCESS_STATUS_PATTERN = /^2\d\d$/;

/**
 * Builds a tool's `outputSchema` from the route's first declared `2xx`
 * `application/json` response, or `undefined` if there isn't a usable one.
 *
 * Requires the schema to resolve to an explicit `type: "object"` — a bare
 * `$ref` (very common; a response schema is often just
 * `{ $ref: "#/components/schemas/Pet" }`) is followed via the same
 * `resolveComponentRef` chain-following already used for form-body `$ref`s,
 * so this still covers the common case without needing the schema to spell
 * out `type` inline. This is deliberately **not** "anything not explicitly
 * non-object": the MCP SDK's client-side `tools/list` response validation
 * requires an advertised `outputSchema.type` to literally be the *string*
 * `"object"` — a bare, unresolved `$ref` (no top-level `type` at all) fails
 * that validation and breaks `tools/list` for *every* tool in the response,
 * not just the one with the bad schema. Confirmed the hard way: an earlier,
 * more permissive version of this function did exactly that against a real
 * spec.
 *
 * The object-shape check happens on the schema *after* `rewriteComponentRefs`
 * (which folds `nullable: true` into `type: ["object", "null"]`), not
 * before — checking beforehand would miss that an inline `{ type: "object",
 * nullable: true }` response schema turns into an *array*-valued `type`
 * post-rewrite, which fails that same literal-string protocol requirement
 * just as a bare `$ref` does. When the resolved type is `["object", "null"]`
 * (or any array containing `"object"`), the advertised type is normalized
 * back down to the literal string `"object"` — dropping the `"null"`
 * alternative is safe because a genuinely `null` response then simply fails
 * the runtime pre-validation safety net below and falls back to plain text,
 * rather than the *type declaration itself* breaking the whole tool list.
 * `fromOpenAPI.ts`'s pre-validation against the *actual* response is what
 * that safety net is for; getting the static shape right here is purely
 * about protocol validity.
 *
 * Unlike `buildFlatSchema`'s tool input schema, this does **not** set
 * `additionalProperties: false` — an undocumented extra field in a real
 * response is the most common form of spec/API drift, and forcing strict
 * mode here would make that safety net reject constantly.
 *
 * Also skips wiring when the schema transitively references more than
 * `MAX_OUTPUT_SCHEMA_DEFS` definitions. This isn't rare: real "core"
 * response objects (Stripe's `Charge`, `Customer`, `PaymentIntent`, ...)
 * routinely embed dozens of other resource types, which themselves embed
 * more — measured directly against Stripe's real spec, the *median*
 * operation's output schema pulled in 868 definitions, and the full
 * tools/list response across all 588 operations would have been ~320MB.
 * A schema this large is also of limited practical use as structured
 * output regardless of size — an LLM isn't better served by a 900-type
 * validation schema than by the same data as text. Skipped operations
 * keep today's plain-text-only behavior; nothing breaks, they just don't
 * get `structuredContent`.
 */
const MAX_OUTPUT_SCHEMA_DEFS = 50;

export function buildOutputSchema(
  route: HttpRoute,
  sharedDefs: Record<string, OpenApiSchema> | undefined,
): JsonSchemaObject | undefined {
  const successEntry = Object.entries(route.responses ?? {}).find(([code]) =>
    SUCCESS_STATUS_PATTERN.test(code),
  );

  const declaredSchema =
    successEntry?.[1].content?.["application/json"]?.schema;

  if (!declaredSchema) {
    return undefined;
  }

  const schema = resolveComponentRef(declaredSchema, sharedDefs);
  const rewritten = rewriteComponentRefs(schema) as OpenApiSchema;
  const { type } = rewritten;

  const isObjectShaped =
    type === "object" || (Array.isArray(type) && type.includes("object"));

  if (!isObjectShaped) {
    return undefined;
  }

  // The protocol requires the literal string "object", not an array — see
  // the doc comment above for why dropping "null" here is safe.
  const normalized = { ...rewritten, type: "object" };
  const usedDefs = sharedDefs && filterReferencedDefs(normalized, sharedDefs);

  if (usedDefs && Object.keys(usedDefs).length > MAX_OUTPUT_SCHEMA_DEFS) {
    return undefined;
  }

  return {
    ...normalized,
    ...(usedDefs ? { $defs: usedDefs } : {}),
  } as JsonSchemaObject;
}

/**
 * Rewrites `$ref`s pointing at `#/components/schemas/...` to `#/$defs/...`,
 * so a per-tool schema that contains one can be handed to AJV standalone,
 * alongside a `$defs` object built from the document's `components.schemas`
 * (see `buildSharedDefs`). Ports the equivalent rewrite from the Python
 * implementation (`utilities/openapi/schemas.py:_replace_ref_with_defs`).
 *
 * Also normalizes OpenAPI 3.0's `nullable` keyword (see `normalizeNullable`),
 * since real specs carry both.
 */
export function rewriteComponentRefs<TValue>(value: TValue): TValue {
  return rewriteNode(value, "schema") as TValue;
}

function childMode(key: string): WalkMode {
  if (DATA_KEYS.has(key)) {
    return "data";
  }

  return SCHEMA_MAP_KEYS.has(key) ? "schemaMap" : "schema";
}

function componentSchemaName(ref: string): string | undefined {
  for (const prefix of ["#/components/schemas/", "#/$defs/"]) {
    if (ref.startsWith(prefix)) {
      return ref.slice(prefix.length);
    }
  }

  return undefined;
}

/**
 * Picks the request body's content type and flattens its schema.
 *
 * `application/json` wins if a route declares both it and
 * `application/x-www-form-urlencoded` (a fixed preference, not declaration
 * order — the latter isn't a reliable signal). A route whose body is only
 * declared under a content type this module doesn't handle at all (e.g.
 * `multipart/form-data`) reports `unsupportedBodyContentType` instead of
 * silently returning an empty property map — that emptiness is exactly what
 * a real Stripe/Twilio operation (both form-urlencoded-only) looked like
 * before this function read anything but JSON, and it produced a tool with
 * no way to carry its actual payload. A bare `content: {}` (no content
 * types at all) still means "no body," not "unsupported" — and so does a
 * supported content type with no `schema` at all (a legal, if unusual,
 * "any JSON body" declaration): the content type itself is fine, there's
 * just nothing to flatten.
 *
 * A form-urlencoded body is very often declared as a bare `$ref` to a
 * component schema rather than inline — FastAPI emits
 * `#/components/schemas/Body_<operation>` for every form endpoint, and
 * Box's OAuth token/refresh/revoke operations do the same. The document is
 * bundled, not dereferenced (see `loadSpec.ts`), so that `$ref` is resolved
 * here against `sharedDefs` before deciding whether the body is a flat
 * object. Only the form path needs this: a JSON body that isn't a flat
 * object falls back to a single whole-body property, which a `$ref`
 * satisfies as-is.
 *
 * A non-object body (array, `$ref` to a scalar/array, etc.) can't be
 * form-urlencoded at all — form encoding is inherently flat key/value pairs
 * — so that combination is also reported as unsupported, rather than
 * `encodeFormBody` (requestBuilder.ts) silently sending an empty body for
 * data it has no way to represent.
 */
function extractBodyProperties(
  requestBody: OpenApiRequestBody | undefined,
  sharedDefs: Record<string, OpenApiSchema> | undefined,
): {
  bodyEncoding?: "form" | "json";
  properties: Map<string, { required: boolean; schema: OpenApiSchema }>;
  unsupportedBodyContentType?: string;
  wholeBodyKey?: string;
} {
  const properties = new Map<
    string,
    { required: boolean; schema: OpenApiSchema }
  >();

  const content = requestBody?.content;

  if (!content) {
    return { properties };
  }

  const hasJson = "application/json" in content;
  const hasForm = "application/x-www-form-urlencoded" in content;

  if (!hasJson && !hasForm) {
    const contentTypes = Object.keys(content);

    return contentTypes.length > 0
      ? { properties, unsupportedBodyContentType: contentTypes[0] }
      : { properties };
  }

  const bodyEncoding: "form" | "json" = hasJson ? "json" : "form";
  const declaredSchema = hasJson
    ? content["application/json"]?.schema
    : content["application/x-www-form-urlencoded"]?.schema;

  if (!declaredSchema) {
    // The content type is declared and supported; it just has no schema
    // (an unconstrained body) — nothing to flatten, but not unsupported.
    return { bodyEncoding, properties };
  }

  const schema =
    bodyEncoding === "form"
      ? resolveComponentRef(declaredSchema, sharedDefs)
      : declaredSchema;

  const schemaProperties = schema.properties as
    | Record<string, OpenApiSchema>
    | undefined;

  if (schema.type === "object" && schemaProperties) {
    const requiredNames = new Set(
      (schema.required as string[] | undefined) ?? [],
    );

    for (const [name, propertySchema] of Object.entries(schemaProperties)) {
      properties.set(name, {
        required: requiredNames.has(name),
        schema: propertySchema,
      });
    }

    return { bodyEncoding, properties };
  }

  if (bodyEncoding === "form") {
    return {
      properties,
      unsupportedBodyContentType: "application/x-www-form-urlencoded",
    };
  }

  // Non-object JSON body (array, bare $ref to a scalar/array, etc.) — expose
  // the whole thing as a single "body" property rather than flattening it.
  properties.set("body", {
    required: requestBody?.required ?? false,
    schema,
  });

  return { bodyEncoding, properties, wholeBodyKey: "body" };
}

/**
 * Walks a schema fragment for `#/$defs/Name` refs and returns just those
 * definitions (transitively — a referenced def may itself reference
 * others), or `undefined` if none are referenced.
 */
function filterReferencedDefs(
  node: unknown,
  allDefs: Record<string, OpenApiSchema>,
): Record<string, OpenApiSchema> | undefined {
  const referenced = new Set<string>();
  const stack: unknown[] = [node];

  while (stack.length > 0) {
    const current = stack.pop();

    if (Array.isArray(current)) {
      stack.push(...current);
      continue;
    }

    if (!current || typeof current !== "object") {
      continue;
    }

    for (const [key, value] of Object.entries(
      current as Record<string, unknown>,
    )) {
      if (
        key === "$ref" &&
        typeof value === "string" &&
        value.startsWith("#/$defs/")
      ) {
        const name = value.slice("#/$defs/".length);

        if (allDefs[name] && !referenced.has(name)) {
          referenced.add(name);
          stack.push(allDefs[name]);
        }

        continue;
      }

      stack.push(value);
    }
  }

  if (referenced.size === 0) {
    return undefined;
  }

  return Object.fromEntries(
    [...referenced].map((name) => [name, allDefs[name]]),
  );
}

/**
 * OpenAPI 3.0's `nullable` keyword only makes sense alongside a sibling
 * `type`, which it widens (`nullable: true` + `type: "string"` means
 * "string or null") — but it is not itself standard JSON Schema. AJV
 * recognizes the keyword and throws ('"nullable" cannot be used without
 * "type"') if it finds one with no `type` on the same node, which real
 * specs do produce (e.g. `nullable` sibling to `oneOf`/`allOf`/`$ref`
 * instead of `type`, as in Box's API). Folded into `type` where there is
 * one to widen, dropped otherwise.
 */
function normalizeNullable(
  schema: Record<string, unknown>,
): Record<string, unknown> {
  if (!("nullable" in schema)) {
    return schema;
  }

  const { nullable, type, ...rest } = schema;

  if (nullable !== true) {
    return rest;
  }

  if (typeof type === "string") {
    return { ...rest, type: [type, "null"] };
  }

  if (Array.isArray(type)) {
    return { ...rest, type: [...new Set(["null", ...type])] };
  }

  return rest;
}

/**
 * Follows a bare `$ref` into `components.schemas` — or its rewritten
 * `#/$defs/` form, which is what `sharedDefs` entries themselves carry —
 * until it reaches a concrete schema. A dangling or cyclic reference is
 * returned as-is rather than failing the whole conversion.
 */
function resolveComponentRef(
  schema: OpenApiSchema,
  sharedDefs: Record<string, OpenApiSchema> | undefined,
): OpenApiSchema {
  const seen = new Set<string>();
  let current = schema;
  let ref = current.$ref;

  while (typeof ref === "string") {
    const name = componentSchemaName(ref);
    const target = name === undefined ? undefined : sharedDefs?.[name];

    if (name === undefined || target === undefined || seen.has(name)) {
      break;
    }

    seen.add(name);
    current = target;
    ref = current.$ref;
  }

  return current;
}

/**
 * Walks a schema fragment, distinguishing the three kinds of node it can
 * reach — because only one of them is a schema whose keys are JSON Schema
 * keywords:
 *
 * - `"schema"` — a schema object. `$ref`/`nullable` here are keywords.
 * - `"schemaMap"` — a name-to-schema map (`properties`, `$defs`, ...). Its
 *   keys are author-chosen names, so a property literally named `nullable`
 *   or `$ref` is a field, not a keyword, and must survive untouched.
 * - `"data"` — arbitrary values (`default`, `enum`, `example`, ...). Not
 *   schemas at all; passed through verbatim.
 *
 * Walking every node as a schema (as this originally did) silently deletes
 * a property named `nullable` from the generated tool schema, since
 * `normalizeNullable` cannot tell the keyword from a same-named field.
 */
function rewriteNode(value: unknown, mode: WalkMode): unknown {
  if (mode === "data") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => rewriteNode(item, "schema"));
  }

  if (!value || typeof value !== "object") {
    return value;
  }

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([key]) => mode !== "schema" || !STRIP_KEYS.has(key))
    .map(([key, entryValue]): [string, unknown] => {
      if (mode === "schemaMap") {
        return [key, rewriteNode(entryValue, "schema")];
      }

      if (
        key === "$ref" &&
        typeof entryValue === "string" &&
        entryValue.startsWith("#/components/schemas/")
      ) {
        return [key, entryValue.replace("#/components/schemas/", "#/$defs/")];
      }

      return [key, rewriteNode(entryValue, childMode(key))];
    });

  const rewritten = Object.fromEntries(entries) as Record<string, unknown>;

  return mode === "schemaMap" ? rewritten : normalizeNullable(rewritten);
}
