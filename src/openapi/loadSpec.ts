import SwaggerParser from "@apidevtools/swagger-parser";

import type { BundledOpenApiDocument } from "./types.js";

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

  return {
    document,
    origin: typeof spec === "string" && isHttpUrl(spec) ? spec : undefined,
  };
}

function isHttpUrl(value: string): boolean {
  return value.startsWith("http://") || value.startsWith("https://");
}
