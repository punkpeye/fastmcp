import type {
  BundledOpenApiDocument,
  HttpMethod,
  HttpRoute,
  OpenApiParameter,
  OpenApiParameterRef,
  OpenApiRequestBody,
  OpenApiResponse,
} from "./types.js";

const HTTP_METHODS: HttpMethod[] = ["get", "put", "post", "delete", "patch"];

/**
 * Walks a bundled document's `paths` into a flat list of routes, resolving
 * any structural (non-schema) `$ref`s on parameters and request bodies —
 * e.g. `#/components/parameters/Limit` — against the same document.
 *
 * Bundling (see `loadSpec.ts`) guarantees every remaining `$ref` here is
 * local, so a plain JSON-pointer lookup is enough.
 */
export function extractRoutes(document: BundledOpenApiDocument): HttpRoute[] {
  const routes: HttpRoute[] = [];

  for (const [path, pathItem] of Object.entries(document.paths ?? {})) {
    const pathLevelParams = (pathItem.parameters ?? []).map((param) =>
      resolveRef<OpenApiParameter>(document, param),
    );

    for (const method of HTTP_METHODS) {
      const operation = pathItem[method];

      if (!operation) {
        continue;
      }

      const operationParams = (operation.parameters ?? []).map((param) =>
        resolveRef<OpenApiParameter>(document, param),
      );

      routes.push({
        deprecated: operation.deprecated ?? false,
        method,
        operationId: operation.operationId,
        parameters: mergeParameters(pathLevelParams, operationParams),
        path,
        requestBody: operation.requestBody
          ? resolveRef<OpenApiRequestBody>(document, operation.requestBody)
          : undefined,
        responses: resolveResponses(document, operation.responses),
        summary: operation.summary,
        tags: operation.tags ?? [],
      });
    }
  }

  return routes;
}

function mergeParameters(
  pathLevel: OpenApiParameter[],
  operationLevel: OpenApiParameter[],
): OpenApiParameter[] {
  const overridden = new Set(
    operationLevel.map((param) => `${param.in}:${param.name}`),
  );

  return [
    ...pathLevel.filter(
      (param) => !overridden.has(`${param.in}:${param.name}`),
    ),
    ...operationLevel,
  ];
}

function resolveRef<TValue>(
  document: BundledOpenApiDocument,
  value: OpenApiParameterRef | TValue,
): TValue {
  if (!value || typeof value !== "object" || !("$ref" in value)) {
    return value;
  }

  const pointer = value.$ref;

  if (!pointer.startsWith("#/")) {
    // Bundling should have already turned every external ref into a local
    // one — if this fires, swagger-parser's output shape has changed.
    throw new Error(`Unexpected external $ref after bundling: ${pointer}`);
  }

  // swagger-parser synthesizes these pointers as URI fragments (e.g. a path
  // like "/pets/{petId}" becomes "~1pets~1%7BpetId%7D"), so each segment
  // needs its "~1"/"~0" escapes undone *and* percent-decoding, in that order.
  const segments = pointer
    .slice(2)
    .split("/")
    .map((segment) =>
      decodeURIComponent(segment.replaceAll("~1", "/").replaceAll("~0", "~")),
    );

  let node: unknown = document;

  for (const segment of segments) {
    node = (node as Record<string, unknown> | undefined)?.[segment];
  }

  return node as TValue;
}

/** A response object can itself be `$ref`'d to `#/components/responses/X`. */
function resolveResponses(
  document: BundledOpenApiDocument,
  rawResponses:
    | Record<string, OpenApiParameterRef | OpenApiResponse>
    | undefined,
): Record<string, OpenApiResponse> | undefined {
  if (!rawResponses) {
    return undefined;
  }

  return Object.fromEntries(
    Object.entries(rawResponses).map(([code, response]) => [
      code,
      resolveRef<OpenApiResponse>(document, response),
    ]),
  );
}
