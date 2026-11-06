import SwaggerParser from "@apidevtools/swagger-parser";

import type { BundledOpenApiDocument, OpenApiSchema } from "./types.js";

export interface LoadedSpec {
  document: BundledOpenApiDocument;
  /**
   * The spec's own URL, when it was loaded from one. Used to resolve a
   * relative `servers[0].url` against the document's origin.
   */
  origin?: string;
}

/**
 * Loads and bundles an OpenAPI document, resolving local *and* external
 * `$ref`s (relative paths, absolute URLs, `other.yaml#/fragment`).
 *
 * `spec` is handed to swagger-parser as-is — a URL, file path, or object —
 * rather than being fetched and re-parsed here first. External refs resolve
 * relative to whatever document they were found in, so pre-fetching the
 * entry document and passing its parsed text as an object would resolve
 * every external ref against the wrong base (or none at all).
 */
export async function loadSpec(
  spec: Record<string, unknown> | string,
): Promise<LoadedSpec> {
  const document = (await SwaggerParser.bundle(
    spec as never,
  )) as unknown as BundledOpenApiDocument;

  if (!document.openapi?.startsWith("3.")) {
    throw new Error(
      `fromOpenAPI only supports OpenAPI 3.x documents (found ${
        document.openapi ?? document.swagger ?? "an unrecognized version"
      }). Swagger 2.0 is not supported.`,
    );
  }

  resolveBundledPointerRefs(document);

  return {
    document,
    origin: typeof spec === "string" && isHttpUrl(spec) ? spec : undefined,
  };
}

function isHttpUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
}

/**
 * Keys whose values are arbitrary instance data rather than schemas. A sample
 * payload may well contain a `"$ref"` field of its own.
 */
const SCHEMA_DATA_KEYS = new Set([
  "const",
  "default",
  "enum",
  "example",
  "examples",
]);

type PointerWalkMode =
  | "components"
  | "componentSchemas"
  | "document"
  | "schema";

/**
 * `bundle()` inlines an external `$ref` at one use site and rewrites every
 * other use of the same external ref into a local pointer at that site —
 * e.g. `#/paths/~1a/get/parameters/0/schema` — which is valid in the bundled
 * document but not in a generated tool's schema: that schema is standalone
 * and only carries `#/$defs/...`. Left alone, the tool advertises a dangling
 * `$ref` and every call fails when the validator cannot compile it
 * (JSON-RPC -32603), or — for a response schema — its `outputSchema` is
 * silently dropped.
 *
 * Move each such target into `components.schemas` under a synthetic name and
 * point the `$ref` at it, so the existing component-to-`$defs` rewriting (and
 * per-tool filtering) handles it. The synthetic name is registered before the
 * target is walked, so a recursive external schema comes out as a `$ref` to
 * that definition instead of an expansion that would never terminate.
 *
 * Only schema positions are rewritten. Bundle-generated refs in parameter,
 * response, and path-item positions are already resolved by `routes.ts`.
 */
function resolveBundledPointerRefs(document: BundledOpenApiDocument): void {
  const schemas = ((document.components ??= {}).schemas ??= {}) as Record<
    string,
    OpenApiSchema
  >;
  const hoisted = new Map<string, string>();
  let counter = 0;

  /** Resolves a same-document JSON Pointer (RFC 6901) to the node it names. */
  const resolvePointer = (pointer: string): unknown => {
    let segments: string[];

    try {
      segments = pointer
        .slice(2)
        .split("/")
        .map((segment) =>
          decodeURIComponent(
            segment.replaceAll("~1", "/").replaceAll("~0", "~"),
          ),
        );
    } catch {
      // Not a decodable URI fragment; leave the ref as it was.
      return undefined;
    }

    let node: unknown = document;

    for (const segment of segments) {
      if (!node || typeof node !== "object") {
        return undefined;
      }

      node = (node as Record<string, unknown>)[segment];
    }

    return node;
  };

  const hoist = (ref: string): string | undefined => {
    const existing = hoisted.get(ref);

    if (existing !== undefined) {
      return existing;
    }

    const target = resolvePointer(ref);

    if (!target || typeof target !== "object") {
      return undefined;
    }

    let name: string;

    do {
      name = `__bundle_${counter++}`;
    } while (Object.hasOwn(schemas, name));

    hoisted.set(ref, name);
    schemas[name] = target as OpenApiSchema;
    // Walk the target only after registering the name: a self-reference then
    // resolves to the definition above instead of recursing into itself.
    walk(target, "schema");

    return name;
  };

  const rewriteRef = (record: Record<string, unknown>): void => {
    const ref = record.$ref;

    if (
      typeof ref !== "string" ||
      !ref.startsWith("#/") ||
      ref.startsWith("#/components/") ||
      ref.startsWith("#/$defs/")
    ) {
      return;
    }

    const name = hoist(ref);

    if (name !== undefined) {
      record.$ref = `#/components/schemas/${name}`;
    }
  };

  /**
   * The only places a schema is reached from outside one: `components.schemas`
   * (a map of schemas) and a `schema` key (parameters, request bodies,
   * responses, headers). Everything below those stays a schema.
   */
  const childMode = (key: string, mode: PointerWalkMode): PointerWalkMode => {
    if (key === "schema") {
      return "schema";
    }

    if (mode === "document" && key === "components") {
      return "components";
    }

    if (mode === "components" && key === "schemas") {
      return "componentSchemas";
    }

    return mode === "componentSchemas" ? "schema" : "document";
  };

  const walk = (value: unknown, mode: PointerWalkMode): void => {
    if (Array.isArray(value)) {
      for (const item of value) {
        walk(item, mode);
      }

      return;
    }

    if (!value || typeof value !== "object") {
      return;
    }

    const record = value as Record<string, unknown>;

    for (const [key, entryValue] of Object.entries(record)) {
      if (mode === "schema") {
        if (key === "$ref") {
          rewriteRef(record);
        } else if (!SCHEMA_DATA_KEYS.has(key)) {
          walk(entryValue, "schema");
        }

        continue;
      }

      walk(entryValue, childMode(key, mode));
    }
  };

  walk(document, "document");
}
