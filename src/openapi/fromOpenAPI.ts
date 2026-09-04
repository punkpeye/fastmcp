import type { ResourceResult } from "../FastMCP.js";
import type { ParameterMapping } from "./schemas.js";
import type { HttpRoute } from "./types.js";
import type { FromOpenAPIOptions } from "./types.js";

import { FastMCP } from "../FastMCP.js";
import { jsonSchemaAdapter } from "../jsonSchemaAdapter.js";
import { loadSpec } from "./loadSpec.js";
import { generateNames } from "./naming.js";
import { executeRequest, type ExecuteRequestResult } from "./requestBuilder.js";
import {
  buildResourceMapping,
  isEligibleForResource,
} from "./resourceMapping.js";
import { extractRoutes } from "./routes.js";
import {
  buildFlatSchema,
  buildOutputSchema,
  buildSharedDefs,
} from "./schemas.js";
import { selectRoutes } from "./selection.js";

/**
 * Converts an OpenAPI 3.x document into an MCP server, one tool (or, with
 * `resources: true`, resource/resource template for an eligible `GET`) per
 * operation.
 *
 * See docs/openapi.md for the full option reference and known limitations.
 */
export async function fromOpenAPI(
  options: FromOpenAPIOptions,
): Promise<FastMCP> {
  const { document, origin } = await loadSpec(options.spec);
  const routes = extractRoutes(document);
  const selected = selectRoutes(routes, options);
  const names = generateNames(selected, options.mcpNames);
  const sharedDefs = buildSharedDefs(document);

  const server =
    options.server ??
    new FastMCP({
      name: options.name ?? document.info?.title ?? "OpenAPI Server",
      version: options.version ?? "1.0.0",
    });

  const skippedOperations: {
    contentType: string;
    method: string;
    path: string;
  }[] = [];

  for (const route of selected) {
    const name = names.get(route);

    if (!name) {
      continue;
    }

    const {
      bodyEncoding,
      flatSchema,
      parameterMap,
      unsupportedBodyContentType,
      wholeBodyKey,
    } = buildFlatSchema(route, sharedDefs);

    const execOptions = {
      baseUrlOverride: options.baseUrl,
      fetchImpl: options.fetch ?? fetch,
      headers: options.headers,
      origin,
      parameterMap,
      route,
      servers: document.servers,
    };

    if (
      options.resources &&
      route.method === "get" &&
      isEligibleForResource(route)
    ) {
      registerResource(
        server,
        route,
        name,
        parameterMap,
        flatSchema.required,
        execOptions,
      );
      continue;
    }

    if (unsupportedBodyContentType) {
      skippedOperations.push({
        contentType: unsupportedBodyContentType,
        method: route.method,
        path: route.path,
      });
      continue;
    }

    const outputSchemaJson = buildOutputSchema(route, sharedDefs);
    const outputSchema = outputSchemaJson
      ? jsonSchemaAdapter(outputSchemaJson)
      : undefined;

    server.addTool({
      description:
        route.summary ?? `${route.method.toUpperCase()} ${route.path}`,
      execute: async (args) => {
        const result = await executeRequest({
          ...execOptions,
          args: args as Record<string, unknown>,
          bodyEncoding,
          wholeBodyKey,
        });

        return resolveToolResult(result, outputSchema);
      },
      name,
      parameters: jsonSchemaAdapter(flatSchema),
      ...(outputSchema ? { outputSchema } : {}),
    });
  }

  if (skippedOperations.length > 0) {
    console.warn(
      "fromOpenAPI: skipped " +
        `${skippedOperations.length} operation(s) whose request body can't be turned into tool parameters ` +
        "(supported: application/json, or application/x-www-form-urlencoded with a flat object schema): " +
        skippedOperations
          .map(
            (op) => `${op.method.toUpperCase()} ${op.path} (${op.contentType})`,
          )
          .join(", "),
    );
  }

  return server;
}

function registerResource(
  server: FastMCP,
  route: HttpRoute,
  name: string,
  parameterMap: Record<string, ParameterMapping>,
  requiredKeys: string[] | undefined,
  execOptions: Omit<
    Parameters<typeof executeRequest>[0],
    "args" | "bodyEncoding" | "wholeBodyKey"
  >,
): void {
  const mapping = buildResourceMapping(route, name, parameterMap, requiredKeys);
  const description = route.summary ?? `GET ${route.path}`;

  if (mapping.kind === "resource") {
    server.addResource({
      description,
      load: async () =>
        wrapAsResourceResult(
          await executeRequest({ ...execOptions, args: {} }),
        ),
      name,
      uri: mapping.uri,
    });

    return;
  }

  server.addResourceTemplate({
    arguments: mapping.args,
    description,
    load: async (args) =>
      wrapAsResourceResult(
        await executeRequest({
          ...execOptions,
          args: args as Record<string, unknown>,
        }),
      ),
    name,
    uriTemplate: mapping.uriTemplate,
  });
}

/**
 * Decides whether a tool call returns the parsed response object (letting
 * FastMCP populate `structuredContent` against `outputSchema`) or the plain
 * text fallback that always works.
 *
 * Real API responses commonly drift from their declared OpenAPI schema, and
 * FastMCP treats an `outputSchema` mismatch as a hard tool error (not a
 * silent fallback) — so a successful HTTP call could otherwise turn into a
 * failed MCP tool call purely from schema drift. This pre-validates against
 * the *exact same* schema instance that's attached as `Tool.outputSchema`
 * (AJV compilation is memoized and deterministic, so this agrees with
 * FastMCP's own re-validation), and only returns the object when it passes.
 *
 * The `Array.isArray` guard is required independently of AJV validation: a
 * schema describing array-shaped data can validate successfully, but
 * FastMCP's `structuredContent` is a plain-object field (`z.record(...)`)
 * that rejects an array at the `ContentResultZodSchema.parse` step — a
 * *different* check than AJV's, positioned after our pre-validation would
 * already have said "fine." Without this guard, an array-typed response
 * schema reintroduces exactly the failure mode this function exists to
 * prevent.
 */
async function resolveToolResult(
  result: ExecuteRequestResult,
  outputSchema: ReturnType<typeof jsonSchemaAdapter> | undefined,
): Promise<unknown> {
  const { json, text } = result;

  if (
    !outputSchema ||
    json === null ||
    typeof json !== "object" ||
    Array.isArray(json)
  ) {
    return text;
  }

  const validation = await outputSchema["~standard"].validate(json);

  return validation.issues ? text : json;
}

function wrapAsResourceResult({ text }: ExecuteRequestResult): ResourceResult {
  // Content-sniffed rather than relying on executeRequest's header-gated
  // `json` field (which exists for the tool/outputSchema path): a server
  // that returns valid JSON without a matching content-type header should
  // still be recognized here, same as before this field existed.
  try {
    JSON.parse(text);
    return { mimeType: "application/json", text };
  } catch {
    return { mimeType: "text/plain", text };
  }
}
