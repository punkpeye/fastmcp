import type { ParameterMapping } from "./schemas.js";
import type { HttpRoute, OpenApiSchema } from "./types.js";

import { resolveComponentRef } from "./schemas.js";

export type ResourceMapping =
  | {
      args: { name: string; required: boolean }[];
      kind: "template";
      uriTemplate: string;
    }
  | { kind: "resource"; uri: string };

/**
 * Builds a static resource URI, or a resource template (URI + `arguments`),
 * for an eligible `GET` route — reusing the `parameterMap` and `required`
 * list `buildFlatSchema` already produced for it (path-always-required,
 * collision-suffixed flat keys) rather than re-deriving parameter
 * flattening from scratch.
 *
 * OpenAPI's `{petId}` path-parameter syntax is already valid RFC 6570 simple
 * string expansion, so the route's own path is reused verbatim except where
 * a flat key was collision-suffixed. Query parameters are appended as an
 * RFC 6570 query-expansion segment (`{?a,b}`), which `uri-templates`
 * (already a FastMCP dependency — see its own resource-template dispatch in
 * FastMCP.ts) parses and fills the same way it does path variables.
 */
export function buildResourceMapping(
  route: HttpRoute,
  name: string,
  parameterMap: Record<string, ParameterMapping>,
  requiredKeys: string[] | undefined,
): ResourceMapping {
  const entries = Object.entries(parameterMap);

  if (entries.length === 0) {
    return { kind: "resource", uri: `openapi://${name}${route.path}` };
  }

  const required = new Set(requiredKeys ?? []);
  const args: { name: string; required: boolean }[] = [];
  const queryKeys: string[] = [];
  let path = route.path;

  for (const [flatKey, mapping] of entries) {
    if (mapping.in === "path") {
      if (flatKey !== mapping.name) {
        path = path.replaceAll(`{${mapping.name}}`, `{${flatKey}}`);
      }
    } else {
      queryKeys.push(flatKey);
    }

    args.push({ name: flatKey, required: required.has(flatKey) });
  }

  const uriTemplate =
    `openapi://${name}${path}` +
    (queryKeys.length > 0 ? `{?${queryKeys.join(",")}}` : "");

  return { args, kind: "template", uriTemplate };
}

/**
 * Whether a `GET` route can become an MCP resource/resource template
 * instead of a tool, when `resources: true` is passed to `fromOpenAPI`. See
 * docs/openapi.md "GET → resources" for the reasoning behind each carve-out:
 *
 * - `header`/`cookie` parameters can't be expressed in a resource URI, and
 *   MCP resource reads have no per-call side channel for them.
 * - An array-typed path/query parameter can't be represented consistently
 *   between OpenAPI's query serialization (repeated keys) and RFC 6570's
 *   array representation (comma-joined or `*`-exploded).
 * - An object-typed path/query parameter loses its object shape when the
 *   URI template is parsed, so its OpenAPI serialization receives strings
 *   or arrays instead of an object.
 * - A parameter declared with `content` (and no `schema`) is one media-type
 *   value, usually JSON text. The template parser cannot turn that text
 *   back into the value `encoding: "json"` would send.
 *
 * A route failing any check falls through to the existing tool path —
 * this only ever *removes* operations from the tool list in favor of a
 * resource, never breaks one.
 */
export function isEligibleForResource(
  route: HttpRoute,
  sharedDefs?: Record<string, OpenApiSchema>,
): boolean {
  return route.parameters.every((param) => {
    if (param.in === "header" || param.in === "cookie") {
      return false;
    }

    if (param.content && param.schema === undefined) {
      return false;
    }

    return !hasStructuredType(param.schema ?? {}, sharedDefs);
  });
}

function hasStructuredType(
  schema: OpenApiSchema,
  sharedDefs: Record<string, OpenApiSchema> | undefined,
  seen = new Set<OpenApiSchema>(),
): boolean {
  const resolved = resolveComponentRef(schema, sharedDefs);
  if (seen.has(resolved)) return false;
  seen.add(resolved);

  const types = Array.isArray(resolved.type) ? resolved.type : [resolved.type];
  if (types.includes("array") || types.includes("object")) return true;

  // Compositions describe the parameter itself, unlike properties/items.
  return ["allOf", "anyOf", "oneOf"].some((key) => {
    const branches = resolved[key];
    return (
      Array.isArray(branches) &&
      branches.some(
        (branch) =>
          branch !== null &&
          typeof branch === "object" &&
          !Array.isArray(branch) &&
          hasStructuredType(branch, sharedDefs, seen),
      )
    );
  });
}
