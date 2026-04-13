/**
 * Web-standard Streamable HTTP Server Transport for MCP
 *
 * This transport implements the MCP Streamable HTTP specification using
 * web standard APIs (Request, Response, TransformStream) for compatibility
 * with edge runtimes like Cloudflare Workers, Deno, and Bun.
 */

import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  isInitializeRequest,
  isJSONRPCNotification,
  isJSONRPCResponse,
  JSONRPCMessage,
  JSONRPCMessageSchema,
  MessageExtraInfo,
  RequestId,
} from "@modelcontextprotocol/sdk/types.js";

export type EventId = string;
/**
 * Interface for resumability support via event storage
 */
export interface EventStore {
  getStreamIdForEventId?(eventId: EventId): Promise<StreamId | undefined>;
  replayEventsAfter(
    lastEventId: EventId,
    options: {
      send: (eventId: EventId, message: JSONRPCMessage) => Promise<void>;
    },
  ): Promise<StreamId>;
  storeEvent(streamId: StreamId, message: JSONRPCMessage): Promise<EventId>;
}

export type StreamId = string;

/**
 * Configuration options for WebStreamableHTTPServerTransport
 */
export interface WebStreamableHTTPServerTransportOptions {
  /**
   * If true, return JSON responses instead of SSE streams
   */
  enableJsonResponse?: boolean;

  /**
   * Event store for resumability support
   */
  eventStore?: EventStore;

  /**
   * Callback for session close events
   */
  onsessionclosed?: (sessionId: string) => Promise<void> | void;

  /**
   * Callback for session initialization events
   */
  onsessioninitialized?: (sessionId: string) => Promise<void> | void;

  /**
   * Function that generates a session ID for the transport.
   * Return undefined to disable session management (stateless mode).
   */
  sessionIdGenerator: (() => string) | undefined;
}

const MAXIMUM_MESSAGE_SIZE = 4 * 1024 * 1024; // 4MB

/**
 * Web-standard Server transport for Streamable HTTP.
 * Uses web APIs (Request, Response, TransformStream) for edge runtime compatibility.
 */
export class WebStreamableHTTPServerTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage, extra?: MessageExtraInfo) => void;
  sessionId?: string;
  private _enableJsonResponse = false;
  private _encoder = new TextEncoder();
  private _eventStore?: EventStore;
  private _onsessionclosed?: (sessionId: string) => Promise<void> | void;
  private _onsessioninitialized?: (sessionId: string) => Promise<void> | void;
  private _pendingResponses: JSONRPCMessage[] = [];
  private _requestToStreamMapping = new Map<RequestId, StreamId>();

  private _standaloneSseStreamId = "_GET_stream";
  private _started = false;
  private _streamMapping = new Map<
    StreamId,
    WritableStreamDefaultWriter<Uint8Array>
  >();
  private sessionIdGenerator: (() => string) | undefined;

  constructor(options: WebStreamableHTTPServerTransportOptions) {
    this.sessionIdGenerator = options.sessionIdGenerator;
    this._enableJsonResponse = options.enableJsonResponse ?? false;
    this._eventStore = options.eventStore;
    this._onsessioninitialized = options.onsessioninitialized;
    this._onsessionclosed = options.onsessionclosed;
  }

  /**
   * Close the transport
   */
  async close(): Promise<void> {
    for (const writer of this._streamMapping.values()) {
      try {
        await writer.close();
      } catch {
        // Ignore close errors
      }
    }
    this._streamMapping.clear();
    this._started = false;
    this.onclose?.();
  }

  /**
   * Handles an incoming web Request and returns a Response
   */
  async handleRequest(
    request: Request,
    parsedBody?: unknown,
  ): Promise<Response> {
    const method = request.method;

    if (method === "POST") {
      return this.handlePostRequest(request, parsedBody);
    } else if (method === "GET") {
      return this.handleGetRequest(request);
    } else if (method === "DELETE") {
      return this.handleDeleteRequest(request);
    } else {
      return this.handleUnsupportedRequest();
    }
  }

  /**
   * Send a message to connected clients
   */
  async send(
    message: JSONRPCMessage,
    options?: { relatedRequestId?: RequestId },
  ): Promise<void> {
    // Store for pending responses (used in JSON response mode)
    this._pendingResponses.push(message);

    // Send to SSE streams
    const streamId = options?.relatedRequestId
      ? this._requestToStreamMapping.get(options.relatedRequestId)
      : this._standaloneSseStreamId;

    if (streamId) {
      const writer = this._streamMapping.get(streamId);
      if (writer) {
        try {
          if (this._eventStore) {
            const eventId = await this._eventStore.storeEvent(
              streamId,
              message,
            );
            await this.writeSSEEventWithId(writer, eventId, message);
          } else {
            await this.writeSSEEvent(writer, message);
          }
        } catch (error) {
          this.onerror?.(
            error instanceof Error ? error : new Error(String(error)),
          );
        }
      }
    }
  }

  async start(): Promise<void> {
    if (this._started) {
      throw new Error("Transport already started");
    }
    this._started = true;
  }

  /**
   * Create an error response
   */
  private createErrorResponse(
    status: number,
    code: number,
    message: string,
  ): Response {
    return new Response(
      JSON.stringify({
        error: { code, message },
        id: null,
        jsonrpc: "2.0",
      }),
      {
        headers: {
          ...this.getResponseHeaders(),
          "Content-Type": "application/json",
        },
        status,
      },
    );
  }

  /**
   * Get common response headers
   */
  private getResponseHeaders(): Record<string, string> {
    const headers: Record<string, string> = {};
    if (this.sessionId) {
      headers["mcp-session-id"] = this.sessionId;
    }
    return headers;
  }

  /**
   * Handles DELETE requests to terminate sessions
   */
  private async handleDeleteRequest(request: Request): Promise<Response> {
    const sessionId = request.headers.get("mcp-session-id");

    if (this.sessionIdGenerator) {
      if (!sessionId) {
        return this.createErrorResponse(
          400,
          -32000,
          "Bad Request: Mcp-Session-Id header is required",
        );
      }

      if (this.sessionId !== sessionId) {
        return this.createErrorResponse(404, -32001, "Session not found");
      }
    }

    // Close all streams
    for (const writer of this._streamMapping.values()) {
      try {
        await writer.close();
      } catch {
        // Ignore close errors
      }
    }
    this._streamMapping.clear();

    await this._onsessionclosed?.(this.sessionId ?? "");
    this.sessionId = undefined;

    return new Response(null, {
      headers: this.getResponseHeaders(),
      status: 204,
    });
  }

  /**
   * Handles GET requests for SSE stream
   */
  private async handleGetRequest(request: Request): Promise<Response> {
    const acceptHeader = request.headers.get("accept");
    if (!acceptHeader?.includes("text/event-stream")) {
      return this.createErrorResponse(
        406,
        -32000,
        "Not Acceptable: Client must accept text/event-stream",
      );
    }

    // Validate session
    const sessionId = request.headers.get("mcp-session-id");
    if (this.sessionIdGenerator && !sessionId) {
      return this.createErrorResponse(
        400,
        -32000,
        "Bad Request: Mcp-Session-Id header is required",
      );
    }

    if (this.sessionIdGenerator && this.sessionId !== sessionId) {
      return this.createErrorResponse(404, -32001, "Session not found");
    }

    // Check for existing standalone stream
    if (this._streamMapping.has(this._standaloneSseStreamId)) {
      return this.createErrorResponse(
        409,
        -32000,
        "Conflict: SSE stream already exists for this session",
      );
    }

    // Handle resumability
    if (this._eventStore) {
      const lastEventId = request.headers.get("last-event-id");
      if (lastEventId) {
        return this.handleReplayEvents(lastEventId);
      }
    }

    // Create SSE stream
    const { readable, writable } = new TransformStream<Uint8Array>();
    const writer = writable.getWriter();
    this._streamMapping.set(this._standaloneSseStreamId, writer);

    return new Response(readable, {
      headers: {
        ...this.getResponseHeaders(),
        "Cache-Control": "no-cache, no-transform",
        Connection: "keep-alive",
        "Content-Type": "text/event-stream",
      },
      status: 200,
    });
  }

  /**
   * Handles POST requests containing JSON-RPC messages
   */
  private async handlePostRequest(
    request: Request,
    parsedBody?: unknown,
  ): Promise<Response> {
    // Validate Accept header
    const acceptHeader = request.headers.get("accept");
    if (
      !acceptHeader?.includes("application/json") &&
      !acceptHeader?.includes("text/event-stream")
    ) {
      return this.createErrorResponse(
        406,
        -32000,
        "Not Acceptable: Client must accept application/json or text/event-stream",
      );
    }

    // Validate Content-Type
    const contentType = request.headers.get("content-type");
    if (!contentType?.includes("application/json")) {
      return this.createErrorResponse(
        415,
        -32000,
        "Unsupported Media Type: Content-Type must be application/json",
      );
    }

    // Validate Content-Length
    const contentLength = parseInt(
      request.headers.get("content-length") ?? "0",
      10,
    );
    if (contentLength > MAXIMUM_MESSAGE_SIZE) {
      return this.createErrorResponse(
        413,
        -32000,
        `Request body too large. Maximum size is ${MAXIMUM_MESSAGE_SIZE} bytes`,
      );
    }

    // Parse body
    let rawMessage: unknown;
    try {
      rawMessage = parsedBody ?? (await request.json());
    } catch {
      return this.createErrorResponse(400, -32700, "Parse error: Invalid JSON");
    }

    // Handle batch or single message
    const arrayMessage: unknown[] = Array.isArray(rawMessage)
      ? rawMessage
      : [rawMessage];

    // Validate messages
    const messages: JSONRPCMessage[] = [];
    for (const msg of arrayMessage) {
      const result = JSONRPCMessageSchema.safeParse(msg);
      if (!result.success) {
        return this.createErrorResponse(
          400,
          -32700,
          "Parse error: Invalid JSON-RPC message",
        );
      }
      messages.push(result.data);
    }

    // Handle session ID
    const requestSessionId = request.headers.get("mcp-session-id");
    const hasInitRequest = messages.some((msg) => isInitializeRequest(msg));

    // Validate session requirements
    if (hasInitRequest && requestSessionId) {
      return this.createErrorResponse(
        400,
        -32600,
        "Invalid Request: Initialization requests must not include a sessionId",
      );
    }

    if (hasInitRequest && messages.length > 1) {
      return this.createErrorResponse(
        400,
        -32600,
        "Invalid Request: Only one initialization request is allowed",
      );
    }

    if (!hasInitRequest && !requestSessionId && this.sessionIdGenerator) {
      return this.createErrorResponse(
        400,
        -32000,
        "Bad Request: Mcp-Session-Id header is required",
      );
    }

    // Generate or validate session ID
    if (hasInitRequest && this.sessionIdGenerator) {
      this.sessionId = this.sessionIdGenerator();
      await this._onsessioninitialized?.(this.sessionId);
    } else if (requestSessionId) {
      if (this.sessionIdGenerator && this.sessionId !== requestSessionId) {
        return this.createErrorResponse(404, -32001, "Session not found");
      }
    }

    // Process messages through the transport
    this._pendingResponses = [];
    for (const message of messages) {
      this.onmessage?.(message, { authInfo: undefined });
    }

    // If all messages are notifications/responses, return 202
    if (
      messages.every(
        (msg) => isJSONRPCNotification(msg) || isJSONRPCResponse(msg),
      )
    ) {
      return new Response(null, {
        headers: this.getResponseHeaders(),
        status: 202,
      });
    }

    // Return JSON response if enabled and client accepts it
    if (
      this._enableJsonResponse &&
      acceptHeader?.includes("application/json")
    ) {
      // Wait a tick for responses to be collected
      await new Promise((resolve) => setTimeout(resolve, 0));

      const responseBody =
        this._pendingResponses.length === 1
          ? JSON.stringify(this._pendingResponses[0])
          : JSON.stringify(this._pendingResponses);

      return new Response(responseBody, {
        headers: {
          ...this.getResponseHeaders(),
          "Content-Type": "application/json",
        },
        status: 200,
      });
    }

    // Return SSE stream
    const { readable, writable } = new TransformStream<Uint8Array>();
    const writer = writable.getWriter();
    const streamId = `post_${Date.now()}`;
    this._streamMapping.set(streamId, writer);

    // Send any pending responses as SSE events
    (async () => {
      try {
        for (const response of this._pendingResponses) {
          await this.writeSSEEvent(writer, response);
        }
      } catch (error) {
        this.onerror?.(
          error instanceof Error ? error : new Error(String(error)),
        );
      }
    })();

    return new Response(readable, {
      headers: {
        ...this.getResponseHeaders(),
        "Cache-Control": "no-cache, no-transform",
        Connection: "keep-alive",
        "Content-Type": "text/event-stream",
      },
      status: 200,
    });
  }

  /**
   * Replay events for resumability
   */
  private async handleReplayEvents(lastEventId: string): Promise<Response> {
    if (!this._eventStore) {
      return this.createErrorResponse(
        400,
        -32000,
        "Resumability not supported",
      );
    }

    const { readable, writable } = new TransformStream<Uint8Array>();
    const writer = writable.getWriter();

    try {
      const streamId = await this._eventStore.replayEventsAfter(lastEventId, {
        send: async (eventId, message) => {
          await this.writeSSEEventWithId(writer, eventId, message);
        },
      });
      this._streamMapping.set(streamId, writer);
    } catch (error) {
      await writer.close();
      return this.createErrorResponse(500, -32000, `Replay failed: ${error}`);
    }

    return new Response(readable, {
      headers: {
        ...this.getResponseHeaders(),
        "Cache-Control": "no-cache, no-transform",
        Connection: "keep-alive",
        "Content-Type": "text/event-stream",
      },
      status: 200,
    });
  }

  /**
   * Handles unsupported HTTP methods
   */
  private handleUnsupportedRequest(): Response {
    return this.createErrorResponse(405, -32000, "Method not allowed");
  }

  /**
   * Write an SSE event to the stream
   */
  private async writeSSEEvent(
    writer: WritableStreamDefaultWriter<Uint8Array>,
    message: JSONRPCMessage,
  ): Promise<void> {
    const data = `data: ${JSON.stringify(message)}\n\n`;
    await writer.write(this._encoder.encode(data));
  }

  /**
   * Write an SSE event with ID to the stream
   */
  private async writeSSEEventWithId(
    writer: WritableStreamDefaultWriter<Uint8Array>,
    eventId: string,
    message: JSONRPCMessage,
  ): Promise<void> {
    const data = `id: ${eventId}\ndata: ${JSON.stringify(message)}\n\n`;
    await writer.write(this._encoder.encode(data));
  }
}
