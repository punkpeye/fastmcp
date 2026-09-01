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
      parameterMap[key] = { in: param.in, name };

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

  const entries = Object.entries(value as Record<string, unknown>).map(
    ([key, entryValue]): [string, unknown] => {
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
    },
  );

  const rewritten = Object.fromEntries(entries) as Record<string, unknown>;

  return mode === "schemaMap" ? rewritten : normalizeNullable(rewritten);
}
