import type { FromOpenAPIOptions } from "./types.js";

import { FastMCP } from "../FastMCP.js";
import { jsonSchemaAdapter } from "../jsonSchemaAdapter.js";
import { loadSpec } from "./loadSpec.js";
import { generateToolNames } from "./naming.js";
import { executeRequest } from "./requestBuilder.js";
import { extractRoutes } from "./routes.js";
import { buildFlatSchema, buildSharedDefs } from "./schemas.js";
import { selectRoutes } from "./selection.js";

/**
 * Converts an OpenAPI 3.x document into an MCP server, one tool per
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
  const names = generateToolNames(selected, options.mcpNames);
  const sharedDefs = buildSharedDefs(document);

  const server =
    options.server ??
    new FastMCP({
      name: options.name ?? document.info?.title ?? "OpenAPI Server",
      version: options.version ?? "1.0.0",
    });

  for (const route of selected) {
    const name = names.get(route);

    if (!name) {
      continue;
    }

    const { flatSchema, parameterMap, wholeBodyKey } = buildFlatSchema(
      route,
      sharedDefs,
    );

    server.addTool({
      description:
        route.summary ?? `${route.method.toUpperCase()} ${route.path}`,
      execute: async (args) =>
        executeRequest({
          args: args as Record<string, unknown>,
          baseUrlOverride: options.baseUrl,
          fetchImpl: options.fetch ?? fetch,
          headers: options.headers,
          origin,
          parameterMap,
          route,
          servers: document.servers,
          wholeBodyKey,
        }),
      name,
      parameters: jsonSchemaAdapter(flatSchema),
    });
  }

  return server;
}
