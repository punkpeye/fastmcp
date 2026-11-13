/**
 * FastMCP Edge Runtime Support
 *
 * This module provides edge runtime compatibility for FastMCP, enabling
 * deployment to Cloudflare Workers, Deno Deploy, and other edge platforms.
 *
 * @example
 * ```typescript
 * // Cloudflare Workers
 * import { EdgeFastMCP } from "fastmcp/edge";
 * import { z } from "zod";
 *
 * const server = new EdgeFastMCP({ name: "MyMCP", version: "1.0.0" });
 *
 * server.addTool({
 *   name: "hello",
 *   description: "Say hello",
 *   parameters: z.object({ name: z.string() }),
 *   execute: async ({ name }) => `Hello, ${name}!`,
 * });
 *
 * export default server;
 * ```
 */

import type { JsonSchema } from "xsschema";

import {
  ErrorCode,
  isInitializeRequest,
  JSONRPCMessage,
  LATEST_PROTOCOL_VERSION,
  SUPPORTED_PROTOCOL_VERSIONS,
} from "@modelcontextprotocol/sdk/types.js";
import { StandardSchemaV1 } from "@standard-schema/spec";
import { type Context, Hono, type MiddlewareHandler } from "hono";
import { matchedRoutes } from "hono/route";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";

import { strictInputSchema, zodInputSchema } from "../strictInputSchema.js";
import {
  MAXIMUM_MESSAGE_SIZE,
  readBodyWithLimit,
  unsupportedProtocolVersion,
} from "./WebStreamableHTTPServerTransport.js";

export { WebStreamableHTTPServerTransport } from "./WebStreamableHTTPServerTransport.js";
export type {
  EventStore,
  WebStreamableHTTPServerTransportOptions,
} from "./WebStreamableHTTPServerTransport.js";

/**
 * Options for EdgeFastMCP
 */
export interface EdgeFastMCPOptions {
  description?: string;
  logger?: EdgeLogger;
  /**
   * Base path for MCP endpoints (default: "/mcp")
   */
  mcpPath?: string;
  name: string;
  version: string;
}

/**
 * Type for edge runtime fetch handler
 */
export type EdgeFetchHandler = (request: Request) => Promise<Response>;

/**
 * Logger interface for edge environments
 */
export interface EdgeLogger {
  debug(...args: unknown[]): void;
  error(...args: unknown[]): void;
  info(...args: unknown[]): void;
  log(...args: unknown[]): void;
  warn(...args: unknown[]): void;
}

/**
 * Prompt definition for EdgeFastMCP
 */
export interface EdgePrompt {
  arguments?: Array<{ description?: string; name: string; required?: boolean }>;
  description?: string;
  load: (args: Record<string, string>) => Promise<
    | {
        messages: Array<{
          content: { text: string; type: string };
          role: string;
        }>;
      }
    | string
  >;
  name: string;
}

/**
 * Resource definition for EdgeFastMCP
 */
export interface EdgeResource {
  description?: string;
  load: () => Promise<
    { blob?: string; mimeType?: string; text?: string } | string
  >;
  mimeType?: string;
  name: string;
  uri: string;
}

/**
 * Tool definition for EdgeFastMCP
 */
export interface EdgeTool<TParams = unknown> {
  description: string;
  execute: (params: TParams) => Promise<
    | {
        _meta?: Record<string, unknown>;
        content: Array<{
          data?: string;
          mimeType?: string;
          text?: string;
          type: string;
        }>;
        isError?: boolean;
        structuredContent?: Record<string, unknown>;
      }
    | string
  >;
  name: string;
  parameters?: StandardSchemaV1<TParams> | z.ZodType<TParams>;
}

/**
 * Edge-compatible FastMCP server for Cloudflare Workers, Deno, and Bun
 *
 * This is a simplified implementation optimized for stateless edge environments.
 * It uses web-standard APIs only (no Node.js dependencies).
 */
export class EdgeFastMCP {
  #honoApp = new Hono();
  #logger: EdgeLogger;
  #mcpPath: string;
  #name: string;
  #prompts: EdgePrompt[] = [];
  #resources: EdgeResource[] = [];
  #tools: EdgeTool[] = [];
  #version: string;

  constructor(options: EdgeFastMCPOptions) {
    this.#name = options.name;
    this.#version = options.version;
    this.#logger = options.logger ?? console;
    this.#mcpPath = options.mcpPath ?? "/mcp";

    this.#setupRoutes();
  }

  /**
   * Add a prompt to the server
   */
  addPrompt(prompt: EdgePrompt): this {
    this.#prompts = this.#prompts.filter((p) => p.name !== prompt.name);
    this.#prompts.push(prompt);
    return this;
  }

  /**
   * Add a resource to the server
   */
  addResource(resource: EdgeResource): this {
    this.#resources = this.#resources.filter((r) => r.uri !== resource.uri);
    this.#resources.push(resource);
    return this;
  }

  /**
   * Add a tool to the server
   */
  addTool<TParams>(tool: EdgeTool<TParams>): this {
    this.#tools = this.#tools.filter((t) => t.name !== tool.name);
    this.#tools.push(tool as EdgeTool);
    return this;
  }

  /**
   * Handle an incoming request (main entry point for edge runtimes)
   *
   * The runtime's bindings and execution context are passed on to the app, so
   * middleware can read them: on Cloudflare Workers `c.env` is where a secret
   * to check a request against comes from.
   */
  async fetch(
    request: Request,
    env?: unknown,
    executionContext?: unknown,
  ): Promise<Response> {
    return this.#honoApp.fetch(
      request,
      env as Parameters<Hono["fetch"]>[1],
      executionContext as Parameters<Hono["fetch"]>[2],
    );
  }

  /**
   * Get the Hono app for adding custom routes and middleware. Middleware runs
   * in front of the MCP endpoint as well.
   */
  getApp(): Hono {
    return this.#honoApp;
  }

  /**
   * Wraps an MCP route so that middleware registered on the app runs in front
   * of it.
   *
   * Hono runs what matches a request in the order it was registered, and the
   * MCP routes are registered in the constructor, before `getApp()` can be
   * called. They answer without calling `next()`, so middleware registered
   * afterwards never ran for them: an auth check on the MCP path let every
   * request through. The route runs that middleware itself instead, with the
   * MCP response where the rest of the chain would be.
   */
  #behindMiddleware(
    respond: (request: Request) => Promise<Response> | Response,
  ): (c: Context) => Promise<Response> {
    return async (c) => {
      const middleware = laterMiddleware(c);

      if (middleware.length === 0) {
        return respond(c.req.raw);
      }

      const routeIndex = c.req.routeIndex;
      let reached = -1;

      // As Hono's own compose runs a chain, ending in the MCP response.
      const dispatch = async (position: number): Promise<void> => {
        if (position <= reached) {
          throw new Error("next() called multiple times");
        }

        reached = position;

        if (position === middleware.length) {
          // Middleware that answered and called next() all the same keeps its
          // answer, as it would in front of any route. The request it turned
          // away is not run.
          if (!c.finalized) {
            c.res = await respond(await readableRequest(c));
          }

          return;
        }

        const { handler, index } = middleware[position];

        c.req.routeIndex = index;

        const response = await handler(c, () => dispatch(position + 1));

        if (response && !c.finalized) {
          c.res = response;
        }
      };

      try {
        await dispatch(0);
      } finally {
        c.req.routeIndex = routeIndex;
      }

      if (!c.finalized) {
        throw new Error(
          "Context is not finalized. Did you forget to return a Response object or `await next()`?",
        );
      }

      return c.res;
    };
  }

  /**
   * Create an error HTTP response
   */
  #errorResponse(status: number, code: number, message: string): Response {
    return new Response(
      JSON.stringify({
        error: { code, message },
        id: null,
        jsonrpc: "2.0",
      }),
      {
        headers: { "Content-Type": "application/json" },
        status,
      },
    );
  }

  /**
   * Handle initialize request
   */
  #handleInitialize(
    id: number | string,
    params?: Record<string, unknown>,
  ): JSONRPCMessage {
    // Answer with the client's version when we support it, as the SDK's
    // Server does. A client refuses any version it does not know, so always
    // answering with the latest one locks out every older client.
    const requestedVersion = params?.protocolVersion;
    const protocolVersion =
      typeof requestedVersion === "string" &&
      SUPPORTED_PROTOCOL_VERSIONS.includes(requestedVersion)
        ? requestedVersion
        : LATEST_PROTOCOL_VERSION;

    return {
      id,
      jsonrpc: "2.0",
      result: {
        capabilities: {
          prompts: this.#prompts.length > 0 ? {} : undefined,
          resources: this.#resources.length > 0 ? {} : undefined,
          tools: this.#tools.length > 0 ? {} : undefined,
        },
        protocolVersion,
        serverInfo: {
          name: this.#name,
          version: this.#version,
        },
      },
    } as JSONRPCMessage;
  }

  /**
   * Handle MCP POST requests
   */
  async #handleMcpRequest(request: Request): Promise<Response> {
    // Validate headers
    const acceptHeader = request.headers.get("accept");
    if (
      !acceptHeader?.includes("application/json") &&
      !acceptHeader?.includes("text/event-stream")
    ) {
      return this.#errorResponse(
        406,
        -32000,
        "Not Acceptable: Client must accept application/json or text/event-stream",
      );
    }

    const contentType = request.headers.get("content-type");
    if (!contentType?.includes("application/json")) {
      return this.#errorResponse(
        415,
        -32000,
        "Unsupported Media Type: Content-Type must be application/json",
      );
    }

    // Parse request body, capped as the edge transport caps it. The
    // Content-Length check answers early; a chunked body has none, so the
    // bytes actually read are counted as well.
    const tooLarge = `Request body too large. Maximum size is ${MAXIMUM_MESSAGE_SIZE} bytes`;
    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (contentLength > MAXIMUM_MESSAGE_SIZE) {
      return this.#errorResponse(413, -32000, tooLarge);
    }
    let body: unknown;
    try {
      const text = await readBodyWithLimit(request);
      if (text === null) {
        return this.#errorResponse(413, -32000, tooLarge);
      }
      body = JSON.parse(text);
    } catch {
      return this.#errorResponse(400, -32700, "Parse error: Invalid JSON");
    }

    // Handle single or batch requests
    const isBatch = Array.isArray(body);
    const messages = Array.isArray(body) ? body : [body];

    if (isBatch && messages.length === 0) {
      return this.#errorResponse(
        400,
        ErrorCode.InvalidRequest,
        "Invalid Request: Batch must contain at least one message",
      );
    }

    // initialize negotiates the version in its body, as in the SDK's transport.
    const unsupported = messages.some((message) => isInitializeRequest(message))
      ? undefined
      : unsupportedProtocolVersion(request);
    if (unsupported) {
      return this.#errorResponse(400, -32000, unsupported);
    }

    const responses: JSONRPCMessage[] = [];

    for (const message of messages) {
      const response = await this.#handleMessage(message);
      if (response) {
        responses.push(response);
      }
    }

    // Return appropriate response format
    if (responses.length === 0) {
      return new Response(null, { status: 202 });
    }

    const responseBody = JSON.stringify(isBatch ? responses : responses[0]);

    return new Response(responseBody, {
      headers: {
        "Content-Type": "application/json",
      },
      status: 200,
    });
  }

  /**
   * Handle SSE GET requests
   */
  async #handleMcpSseRequest(request: Request): Promise<Response> {
    const acceptHeader = request.headers.get("accept");
    if (!acceptHeader?.includes("text/event-stream")) {
      return this.#errorResponse(
        406,
        -32000,
        "Not Acceptable: Client must accept text/event-stream",
      );
    }

    const unsupported = unsupportedProtocolVersion(request);
    if (unsupported) {
      return this.#errorResponse(400, -32000, unsupported);
    }

    // In stateless mode, GET requests are not supported (no server-initiated messages)
    return this.#errorResponse(
      405,
      -32000,
      "Method Not Allowed: SSE streams not supported in stateless mode",
    );
  }

  /**
   * Handle individual MCP messages
   */
  async #handleMessage(message: unknown): Promise<JSONRPCMessage | null> {
    if (!message || typeof message !== "object") {
      return this.#rpcError(null, -32700, "Parse error: Invalid message");
    }

    const msg = message as {
      id?: number | string;
      jsonrpc?: string;
      method?: string;
      params?: unknown;
    };

    if (msg.jsonrpc !== "2.0") {
      return this.#rpcError(
        msg.id ?? null,
        -32600,
        "Invalid Request: jsonrpc must be 2.0",
      );
    }

    // Handle notifications (no response expected)
    if (!("id" in msg) || msg.id === undefined) {
      return null;
    }

    const method = msg.method;
    const id = msg.id;
    const params = msg.params as Record<string, unknown> | undefined;

    try {
      switch (method) {
        case "initialize":
          return this.#handleInitialize(id, params);

        case "ping":
          return { id, jsonrpc: "2.0", result: {} } as JSONRPCMessage;

        case "prompts/get":
          return this.#handlePromptsGet(id, params);

        case "prompts/list":
          return this.#handlePromptsList(id);

        case "resources/list":
          return this.#handleResourcesList(id);

        case "resources/read":
          return this.#handleResourcesRead(id, params);

        case "resources/templates/list":
          return {
            id,
            jsonrpc: "2.0",
            result: { resourceTemplates: [] },
          } as JSONRPCMessage;

        case "tools/call":
          return this.#handleToolsCall(id, params);

        case "tools/list":
          return this.#handleToolsList(id);

        default:
          return this.#rpcError(id, -32601, `Method not found: ${method}`);
      }
    } catch (error) {
      this.#logger.error(`Error handling ${method}:`, error);
      return this.#rpcError(
        id,
        -32603,
        `Internal error: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  /**
   * Handle prompts/get request
   */
  async #handlePromptsGet(
    id: number | string,
    params?: Record<string, unknown>,
  ): Promise<JSONRPCMessage> {
    const promptName = params?.name as string;
    const promptArgs = params?.arguments as Record<string, string> | undefined;

    const prompt = this.#prompts.find((p) => p.name === promptName);
    if (!prompt) {
      return this.#rpcError(
        id,
        ErrorCode.InvalidParams,
        `Prompt not found: ${promptName}`,
      );
    }

    for (const arg of prompt.arguments ?? []) {
      if (
        arg.required &&
        !(promptArgs && Object.hasOwn(promptArgs, arg.name))
      ) {
        return this.#rpcError(
          id,
          ErrorCode.InvalidParams,
          `Prompt '${promptName}' requires argument '${arg.name}': ${
            arg.description || "No description provided"
          }`,
        );
      }
    }

    try {
      const result = await prompt.load(promptArgs ?? {});
      const messages =
        typeof result === "string"
          ? [{ content: { text: result, type: "text" }, role: "user" }]
          : result.messages;

      return {
        id,
        jsonrpc: "2.0",
        result: { messages },
      } as JSONRPCMessage;
    } catch (error) {
      return this.#rpcError(
        id,
        ErrorCode.InternalError,
        `Prompt load failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  /**
   * Handle prompts/list request
   */
  #handlePromptsList(id: number | string): JSONRPCMessage {
    return {
      id,
      jsonrpc: "2.0",
      result: {
        prompts: this.#prompts.map((p) => ({
          arguments: p.arguments,
          description: p.description,
          name: p.name,
        })),
      },
    } as JSONRPCMessage;
  }

  /**
   * Handle resources/list request
   */
  #handleResourcesList(id: number | string): JSONRPCMessage {
    return {
      id,
      jsonrpc: "2.0",
      result: {
        resources: this.#resources.map((r) => ({
          description: r.description,
          mimeType: r.mimeType,
          name: r.name,
          uri: r.uri,
        })),
      },
    } as JSONRPCMessage;
  }

  /**
   * Handle resources/read request
   */
  async #handleResourcesRead(
    id: number | string,
    params?: Record<string, unknown>,
  ): Promise<JSONRPCMessage> {
    const uri = params?.uri as string;
    const resource = this.#resources.find((r) => r.uri === uri);

    if (!resource) {
      return this.#rpcError(
        id,
        ErrorCode.InvalidParams,
        `Resource not found: ${uri}`,
      );
    }

    try {
      const result = await resource.load();
      const content =
        typeof result === "string"
          ? { mimeType: resource.mimeType ?? "text/plain", text: result, uri }
          : {
              uri,
              ...result,
              mimeType: result.mimeType ?? resource.mimeType,
            };

      return {
        id,
        jsonrpc: "2.0",
        result: { contents: [content] },
      } as JSONRPCMessage;
    } catch (error) {
      return this.#rpcError(
        id,
        ErrorCode.InternalError,
        `Resource load failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  /**
   * Handle tools/call request
   */
  async #handleToolsCall(
    id: number | string,
    params?: Record<string, unknown>,
  ): Promise<JSONRPCMessage> {
    const toolName = params?.name as string;
    const toolArgs = params?.arguments as Record<string, unknown> | undefined;

    const tool = this.#tools.find((t) => t.name === toolName);
    if (!tool) {
      return this.#rpcError(
        id,
        ErrorCode.InvalidParams,
        `Tool not found: ${toolName}`,
      );
    }

    let args: unknown = toolArgs ?? {};

    if (tool.parameters) {
      let parsed: StandardSchemaV1.Result<unknown>;

      try {
        parsed = await tool.parameters["~standard"].validate(args);
      } catch (error) {
        return this.#rpcError(
          id,
          ErrorCode.InternalError,
          `Tool '${toolName}' parameter validation failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }

      if (parsed.issues) {
        const friendlyErrors = parsed.issues
          .map((issue) => {
            const path =
              issue.path
                ?.map((segment) =>
                  String(
                    typeof segment === "object" && segment !== null
                      ? segment.key
                      : segment,
                  ),
                )
                .join(".") || "root";
            return `${path}: ${issue.message}`;
          })
          .join(", ");

        // A tool execution error, not a protocol error, as in the Node path.
        return {
          id,
          jsonrpc: "2.0",
          result: {
            content: [
              {
                text: `Tool '${toolName}' parameter validation failed: ${friendlyErrors}. Please check the parameter types and values according to the tool's schema.`,
                type: "text",
              },
            ],
            isError: true,
          },
        } as JSONRPCMessage;
      }

      args = parsed.value;
    }

    try {
      const result = await tool.execute(args);

      // Normalize string results while preserving explicit tool results.
      // Copy the result's fields rather than the object itself, so a tool
      // that returns nothing still fails below instead of answering with no
      // result.
      const toolResult =
        typeof result === "string"
          ? { content: [{ text: result, type: "text" }] }
          : {
              _meta: result._meta,
              content: result.content,
              isError: result.isError,
              structuredContent: result.structuredContent,
            };

      return {
        id,
        jsonrpc: "2.0",
        result: toolResult,
      } as JSONRPCMessage;
    } catch (error) {
      // A tool that throws is a tool execution error: the MCP specification
      // reports it in the result with `isError`, so the model can read it,
      // as the Node FastMCP path does.
      return {
        id,
        jsonrpc: "2.0",
        result: {
          content: [
            {
              text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
              type: "text",
            },
          ],
          isError: true,
        },
      } as JSONRPCMessage;
    }
  }

  /**
   * Handle tools/list request
   */
  #handleToolsList(id: number | string): JSONRPCMessage {
    return {
      id,
      jsonrpc: "2.0",
      result: {
        tools: this.#tools.map((tool) => ({
          description: tool.description,
          inputSchema: tool.parameters
            ? this.#schemaToJsonSchema(tool.parameters)
            : { type: "object" },
          name: tool.name,
        })),
      },
    } as JSONRPCMessage;
  }

  /**
   * Create an RPC error message
   */
  #rpcError(
    id: null | number | string,
    code: number,
    message: string,
  ): JSONRPCMessage {
    return {
      error: { code, message },
      id,
      jsonrpc: "2.0",
    } as JSONRPCMessage;
  }

  /**
   * Convert schema to JSON Schema
   */
  #schemaToJsonSchema(
    schema: StandardSchemaV1 | z.ZodType,
  ): Record<string, unknown> {
    try {
      if (schema["~standard"].vendor === "zod") {
        // Zod 3 goes straight to zod-to-json-schema, as xsschema does for
        // FastMCP. Importing xsschema here would put its optional peers
        // (effect, sury, ...) into edge bundles, which then fail to build.
        const jsonSchema =
          "_zod" in schema
            ? zodInputSchema(schema as z.ZodType)
            : zodToJsonSchema(schema as Parameters<typeof zodToJsonSchema>[0]);
        return strictInputSchema(jsonSchema as JsonSchema) as Record<
          string,
          unknown
        >;
      }
      // For StandardSchema, fall back to a generic object schema
      return { type: "object" };
    } catch {
      return { type: "object" };
    }
  }

  /**
   * Set up MCP and health routes
   */
  #setupRoutes(): void {
    // Health endpoint
    this.#honoApp.get("/health", (c) => c.text("✓ Ok"));

    // MCP endpoint - handles all MCP protocol messages
    this.#honoApp.post(
      this.#mcpPath,
      this.#behindMiddleware((request) => this.#handleMcpRequest(request)),
    );

    // MCP GET endpoint for SSE streams (server-initiated messages)
    this.#honoApp.get(
      this.#mcpPath,
      this.#behindMiddleware((request) => this.#handleMcpSseRequest(request)),
    );

    // MCP DELETE endpoint for session termination
    this.#honoApp.delete(
      this.#mcpPath,
      this.#behindMiddleware((request) => {
        const unsupported = unsupportedProtocolVersion(request);
        if (unsupported) {
          return this.#errorResponse(400, -32000, unsupported);
        }

        return new Response(null, { status: 204 });
      }),
    );
  }
}

/**
 * The middleware Hono matched for this request that was registered after the
 * route now running, however it was registered: with `use()`, on a route
 * group, or under a method.
 *
 * Middleware is what takes `next`. A handler that takes only the context
 * cannot let a request through, so it is a route of its own — a fallback, a
 * custom 404 — and is left out: it does not replace the MCP endpoint.
 */
function laterMiddleware(
  c: Context,
): { handler: MiddlewareHandler; index: number }[] {
  let routes: { handler: unknown }[];

  try {
    // Read from the request first. An app mounted in one that was built from
    // another copy of hono is handed that copy's request, which this copy's
    // helper cannot read.
    routes = c.req.matchedRoutes ?? matchedRoutes(c);
  } catch {
    return [];
  }

  return routes
    .map((route, index) => ({
      handler: route.handler as MiddlewareHandler,
      index,
    }))
    .filter(
      ({ handler, index }) =>
        index > c.req.routeIndex && registeredHandler(handler).length !== 1,
    );
}

/**
 * The request with a body that can still be read. Middleware that read it
 * through `c.req` used the original up, and left Hono's copy of it behind.
 */
async function readableRequest(c: Context): Promise<Request> {
  const request = c.req.raw;

  if (!request.bodyUsed) {
    return request;
  }

  return new Request(request.url, {
    body: await c.req.arrayBuffer(),
    headers: request.headers,
    method: request.method,
  });
}

/**
 * The handler a route was registered with. Mounting an app that has its own
 * error handler into another one (`route()`) wraps each of its handlers, once
 * per mount, and keeps the one it wrapped under this key.
 */
function registeredHandler(handler: MiddlewareHandler): MiddlewareHandler {
  const wrapped = (handler as { __COMPOSED_HANDLER?: MiddlewareHandler })
    .__COMPOSED_HANDLER;

  return typeof wrapped === "function" ? registeredHandler(wrapped) : handler;
}
