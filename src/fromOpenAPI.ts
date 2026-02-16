import {
  buildToolParameters,
  classifyRoute,
  extractRoutes,
} from "./openapi.js";
import type { OpenAPIDocument, OpenAPIRoute } from "./openapi.js";

type HttpClient = {
  request: (config: {
    body?: unknown;
    headers?: Record<string, string>;
    method: string;
    url: string;
  }) => Promise<{ data: unknown; status: number }>;
};

type FromOpenAPIOptions = {
  /**
   * HTTP client to use for making API requests.
   * Must implement a request() method.
   */
  client: HttpClient;

  /**
   * Headers to include with every request (e.g., auth).
   */
  headers?: Record<string, string>;

  /**
   * Base URL for the API.
   * If not provided, uses the first server URL from the spec.
   */
  baseUrl?: string;

  /**
   * OpenAPI specification object (parsed JSON).
   */
  spec: OpenAPIDocument;
};

/**
 * Substitute path parameters into a URL template.
 * e.g., "/pets/{petId}" + {petId: "123"} -> "/pets/123"
 */
function substitutePathParams(
  pathTemplate: string,
  params: Record<string, unknown>,
): string {
  return pathTemplate.replace(/\{(\w+)\}/g, (_, key) => {
    const value = params[key];
    return value !== undefined ? encodeURIComponent(String(value)) : `{${key}}`;
  });
}

/**
 * Build the full URL for a route, including query parameters.
 */
function buildUrl(
  baseUrl: string,
  route: OpenAPIRoute,
  args: Record<string, unknown>,
): string {
  const path = substitutePathParams(route.path, args);
  const url = new URL(path, baseUrl);

  for (const param of route.parameters) {
    if (param.in === "query" && args[param.name] !== undefined) {
      url.searchParams.set(param.name, String(args[param.name]));
    }
  }

  return url.toString();
}

/**
 * Extract headers from route parameters and arguments.
 */
function extractHeaders(
  route: OpenAPIRoute,
  args: Record<string, unknown>,
): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const param of route.parameters) {
    if (param.in === "header" && args[param.name] !== undefined) {
      headers[param.name] = String(args[param.name]);
    }
  }
  return headers;
}

/**
 * Extract body fields from arguments.
 * Body fields are prefixed with "body_" when flattened.
 */
function extractBody(
  args: Record<string, unknown>,
): Record<string, unknown> | undefined {
  const bodyFields: Record<string, unknown> = {};
  let hasBody = false;

  for (const [key, value] of Object.entries(args)) {
    if (key === "body") {
      return value as Record<string, unknown>;
    }
    if (key.startsWith("body_")) {
      bodyFields[key.slice(5)] = value;
      hasBody = true;
    }
  }

  return hasBody ? bodyFields : undefined;
}

/**
 * Create an MCP tool handler for an OpenAPI route.
 */
function createToolHandler(
  route: OpenAPIRoute,
  baseUrl: string,
  client: HttpClient,
  defaultHeaders: Record<string, string>,
) {
  return async (args: Record<string, unknown>) => {
    const url = buildUrl(baseUrl, route, args);
    const routeHeaders = extractHeaders(route, args);
    const body = extractBody(args);

    const response = await client.request({
      body: body,
      headers: {
        "Content-Type": "application/json",
        ...defaultHeaders,
        ...routeHeaders,
      },
      method: route.method.toUpperCase(),
      url,
    });

    return {
      content: [
        {
          text:
            typeof response.data === "string"
              ? response.data
              : JSON.stringify(response.data, null, 2),
          type: "text" as const,
        },
      ],
    };
  };
}

/**
 * Create an MCP resource handler for an OpenAPI GET route.
 */
function createResourceHandler(
  route: OpenAPIRoute,
  baseUrl: string,
  client: HttpClient,
  defaultHeaders: Record<string, string>,
) {
  return async () => {
    const url = buildUrl(baseUrl, route, {});

    const response = await client.request({
      headers: {
        "Content-Type": "application/json",
        ...defaultHeaders,
      },
      method: "GET",
      url,
    });

    return {
      text:
        typeof response.data === "string"
          ? response.data
          : JSON.stringify(response.data, null, 2),
    };
  };
}

/**
 * Convert an OpenAPI spec into FastMCP-compatible tool, resource,
 * and resource template definitions.
 *
 * @example
 * ```ts
 * import { FastMCP } from "fastmcp";
 * import { fromOpenAPI } from "fastmcp/openapi";
 *
 * const spec = JSON.parse(fs.readFileSync("openapi.json", "utf-8"));
 * const { tools, resources, resourceTemplates } = fromOpenAPI({
 *   spec,
 *   client: { request: (config) => fetch(config.url, config).then(async r => ({ status: r.status, data: await r.json() })) },
 * });
 *
 * const mcp = new FastMCP({ name: "My API", version: "1.0.0" });
 * tools.forEach(t => mcp.addTool(t));
 * resources.forEach(r => mcp.addResource(r));
 * ```
 */
export function fromOpenAPI(options: FromOpenAPIOptions) {
  const { client, headers = {}, spec } = options;
  const baseUrl =
    options.baseUrl ??
    (spec as Record<string, unknown> & { servers?: Array<{ url: string }> })
      .servers?.[0]?.url ??
    "http://localhost";

  const routes = extractRoutes(spec);
  const tools: Array<{
    description: string;
    execute: (
      args: Record<string, unknown>,
    ) => Promise<{ content: Array<{ text: string; type: "text" }> }>;
    name: string;
    parameters: ReturnType<typeof buildToolParameters>["jsonSchema"];
  }> = [];

  const resources: Array<{
    description: string;
    name: string;
    read: () => Promise<{ text: string }>;
    uri: string;
  }> = [];

  const resourceTemplates: Array<{
    description: string;
    name: string;
    read: (args: Record<string, unknown>) => Promise<{ text: string }>;
    uriTemplate: string;
  }> = [];

  for (const route of routes) {
    const classification = classifyRoute(route);
    const params = buildToolParameters(spec, route);

    switch (classification) {
      case "tool": {
        tools.push({
          description: route.description,
          execute: createToolHandler(route, baseUrl, client, headers),
          name: route.operationId,
          parameters: params.jsonSchema,
        });
        break;
      }
      case "resource": {
        resources.push({
          description: route.description,
          name: route.operationId,
          read: createResourceHandler(route, baseUrl, client, headers),
          uri: `api://${route.path}`,
        });
        break;
      }
      case "resourceTemplate": {
        const templateUri = route.path.replace(/\{(\w+)\}/g, "{$1}");
        resourceTemplates.push({
          description: route.description,
          name: route.operationId,
          read: async (args: Record<string, unknown>) => {
            const url = buildUrl(baseUrl, route, args);
            const response = await client.request({
              headers: {
                "Content-Type": "application/json",
                ...headers,
              },
              method: "GET",
              url,
            });
            return {
              text:
                typeof response.data === "string"
                  ? response.data
                  : JSON.stringify(response.data, null, 2),
            };
          },
          uriTemplate: `api://${templateUri}`,
        });
        break;
      }
    }
  }

  return { resources, resourceTemplates, tools };
}

export type { FromOpenAPIOptions, HttpClient };
