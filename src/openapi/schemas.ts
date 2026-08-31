import type { JsonSchemaObject } from "../jsonSchemaAdapter.js";
import type {
  BundledOpenApiDocument,
  HttpRoute,
  OpenApiParameter,
  OpenApiRequestBody,
  OpenApiSchema,
  ParameterLocation,
} from "./types.js";

export interface FlatSchemaResult {
  flatSchema: JsonSchemaObject;
  parameterMap: Record<string, ParameterMapping>;
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

  const { properties: bodyProperties, wholeBodyKey } = extractBodyProperties(
    route.method === "get" ? undefined : route.requestBody,
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

  return { flatSchema, parameterMap, wholeBodyKey };
}

export function buildSharedDefs(
  document: BundledOpenApiDocument,
): Record<string, OpenApiSchema> | undefined {
  const schemas = document.components?.schemas;

  if (!schemas || Object.keys(schemas).length === 0) {
    return undefined;
  }

  return rewriteComponentRefs(schemas);
}

/**
 * Rewrites `$ref`s pointing at `#/components/schemas/...` to `#/$defs/...`,
 * so a per-tool schema that contains one can be handed to AJV standalone,
 * alongside a `$defs` object built from the document's `components.schemas`
 * (see `buildSharedDefs`). Ports the equivalent rewrite from the Python
 * implementation (`utilities/openapi/schemas.py:_replace_ref_with_defs`).
 */
export function rewriteComponentRefs<TValue>(value: TValue): TValue {
  if (Array.isArray(value)) {
    return value.map((item) => rewriteComponentRefs(item)) as TValue;
  }

  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).map(
      ([key, entryValue]): [string, unknown] => {
        if (
          key === "$ref" &&
          typeof entryValue === "string" &&
          entryValue.startsWith("#/components/schemas/")
        ) {
          return [key, entryValue.replace("#/components/schemas/", "#/$defs/")];
        }

        return [key, rewriteComponentRefs(entryValue)];
      },
    );

    return Object.fromEntries(entries) as TValue;
  }

  return value;
}

function extractBodyProperties(requestBody: OpenApiRequestBody | undefined): {
  properties: Map<string, { required: boolean; schema: OpenApiSchema }>;
  wholeBodyKey?: string;
} {
  const properties = new Map<
    string,
    { required: boolean; schema: OpenApiSchema }
  >();

  const schema = requestBody?.content?.["application/json"]?.schema;

  if (!schema) {
    return { properties };
  }

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

    return { properties };
  }

  // Non-object body (array, bare $ref to a scalar/array, etc.) — expose the
  // whole thing as a single "body" property rather than flattening it.
  properties.set("body", {
    required: requestBody?.required ?? false,
    schema,
  });

  return { properties, wholeBodyKey: "body" };
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
