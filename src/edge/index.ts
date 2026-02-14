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

import {
  ErrorCode,
  JSONRPCMessage,
  LATEST_PROTOCOL_VERSION,
} from "@modelcontextprotocol/sdk/types.js";
import { StandardSchemaV1 } from "@standard-schema/spec";
import { Hono } from "hono";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";

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
        content: Array<{
          data?: string;
          mimeType?: string;
          text?: string;
          type: string;
        }>;
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
    this.#prompts.push(prompt);
    return this;
  }

  /**
   * Add a resource to the server
   */
  addResource(resource: EdgeResource): this {
    this.#resources.push(resource);
    return this;
  }

  /**
   * Add a tool to the server
   */
  addTool<TParams>(tool: EdgeTool<TParams>): this {
    this.#tools.push(tool as EdgeTool);
    return this;
  }

  /**
   * Handle an incoming request (main entry point for edge runtimes)
   */
  async fetch(request: Request): Promise<Response> {
    return this.#honoApp.fetch(request);
  }

  /**
   * Get the Hono app for adding custom routes
   */
  getApp(): Hono {
    return this.#honoApp;
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
  #handleInitialize(id: number | string): JSONRPCMessage {
    return {
      id,
      jsonrpc: "2.0",
      result: {
        capabilities: {
          prompts: this.#prompts.length > 0 ? {} : undefined,
          resources: this.#resources.length > 0 ? {} : undefined,
          tools: this.#tools.length > 0 ? {} : undefined,
        },
        protocolVersion: LATEST_PROTOCOL_VERSION,
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

    // Parse request body
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return this.#errorResponse(400, -32700, "Parse error: Invalid JSON");
    }

    // Handle single or batch requests
    const messages = Array.isArray(body) ? body : [body];
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

    const responseBody =
      responses.length === 1
        ? JSON.stringify(responses[0])
        : JSON.stringify(responses);

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
          return this.#handleInitialize(id);

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
          : { uri, ...result };

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

    try {
      const result = await tool.execute(toolArgs ?? {});

      // Normalize result to content array
      const content =
        typeof result === "string"
          ? [{ text: result, type: "text" }]
          : result.content;

      return {
        id,
        jsonrpc: "2.0",
        result: { content },
      } as JSONRPCMessage;
    } catch (error) {
      return this.#rpcError(
        id,
        ErrorCode.InternalError,
        `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
      );
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
      // Zod 4+: use native toJSONSchema if available
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      if (typeof (z as any).toJSONSchema === "function") {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return (z as any).toJSONSchema(schema) as Record<string, unknown>;
      }
      // Zod 3 fallback: use zod-to-json-schema
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      if ("_def" in (schema as any) || schema instanceof z.ZodType) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return zodToJsonSchema(schema as any, { target: "openApi3" }) as Record<
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
    this.#honoApp.post(this.#mcpPath, async (c) => {
      return this.#handleMcpRequest(c.req.raw);
    });

    // MCP GET endpoint for SSE streams (server-initiated messages)
    this.#honoApp.get(this.#mcpPath, async (c) => {
      return this.#handleMcpSseRequest(c.req.raw);
    });

    // MCP DELETE endpoint for session termination
    this.#honoApp.delete(this.#mcpPath, async () => {
      return new Response(null, { status: 204 });
    });
  }
}
