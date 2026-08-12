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
  isJSONRPCError,
  isJSONRPCRequest,
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

/**
 * Collects the responses to every request that arrived on a single POST, so
 * that JSON mode can answer once all of them are in.
 */
interface PendingJsonResponse {
  expectedIds: RequestId[];
  resolve: (responses: JSONRPCMessage[]) => void;
  responses: Map<RequestId, JSONRPCMessage>;
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
  private _jsonResponseCollectors = new Map<StreamId, PendingJsonResponse>();
  private _onsessionclosed?: (sessionId: string) => Promise<void> | void;
  private _onsessioninitialized?: (sessionId: string) => Promise<void> | void;
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
    this.releasePendingRequests();
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
    let requestId = options?.relatedRequestId;
    const isResponse = isJSONRPCResponse(message) || isJSONRPCError(message);
    if (isResponse) {
      // Responses are routed by the id of the request they answer
      requestId = message.id;
    }

    const streamId =
      requestId === undefined
        ? this._standaloneSseStreamId
        : this._requestToStreamMapping.get(requestId);

    if (streamId) {
      // JSON mode has no stream to write to: collect the responses instead and
      // let handlePostRequest answer once every request on this POST is done.
      const collector = this._jsonResponseCollectors.get(streamId);
      if (collector) {
        if (isResponse && requestId !== undefined) {
          collector.responses.set(requestId, message);
          this.settleJsonResponse(streamId, collector);
        }
        return;
      }

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

          // Close the POST stream once all of its requests are answered
          if (requestId !== undefined && isResponse) {
            this._requestToStreamMapping.delete(requestId);
            const streamInUse = Array.from(
              this._requestToStreamMapping.values(),
            ).includes(streamId);
            if (!streamInUse) {
              this._streamMapping.delete(streamId);
              await writer.close();
            }
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
    this.releasePendingRequests();

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
    this.trackStream(this._standaloneSseStreamId, writer);

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

    // Handle batch or single message. The original shape decides the response
    // envelope: a batch always answers with an array, even when only one
    // response survives.
    const isBatch = Array.isArray(rawMessage);
    const arrayMessage: unknown[] = Array.isArray(rawMessage)
      ? rawMessage
      : [rawMessage];

    if (isBatch && arrayMessage.length === 0) {
      return this.createErrorResponse(
        400,
        -32600,
        "Invalid Request: Batch must contain at least one message",
      );
    }

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

    const requestIds = messages
      .filter((msg) => isJSONRPCRequest(msg))
      .map((msg) => msg.id);
    const useJsonResponse =
      this._enableJsonResponse &&
      Boolean(acceptHeader?.includes("application/json"));

    // Register the response sink before dispatching: the SDK produces
    // responses asynchronously and send() routes them back by request id.
    let jsonResponses: Promise<JSONRPCMessage[]> | undefined;
    let sseReadable: ReadableStream<Uint8Array> | undefined;
    if (requestIds.length > 0) {
      // Must be unique: a wall-clock id collides between two POSTs issued in
      // the same millisecond, which would cross-deliver their responses.
      const streamId = crypto.randomUUID();
      for (const id of requestIds) {
        this._requestToStreamMapping.set(id, streamId);
      }

      if (useJsonResponse) {
        jsonResponses = new Promise((resolve) => {
          this._jsonResponseCollectors.set(streamId, {
            expectedIds: requestIds,
            resolve,
            responses: new Map(),
          });
        });
      } else {
        const { readable, writable } = new TransformStream<Uint8Array>();
        this.trackStream(streamId, writable.getWriter());
        sseReadable = readable;
      }
    }

    // Process messages through the transport
    for (const message of messages) {
      this.onmessage?.(message, { authInfo: undefined });
    }

    // Nothing to answer: the batch was only notifications and/or responses
    if (requestIds.length === 0) {
      return new Response(null, {
        headers: this.getResponseHeaders(),
        status: 202,
      });
    }

    // Return JSON response if enabled and client accepts it
    if (jsonResponses) {
      // Wait for the handlers to actually answer, however long they take
      const responses = await jsonResponses;

      const responseBody = JSON.stringify(isBatch ? responses : responses[0]);

      return new Response(responseBody, {
        headers: {
          ...this.getResponseHeaders(),
          "Content-Type": "application/json",
        },
        status: 200,
      });
    }

    // Return SSE stream
    return new Response(sseReadable ?? null, {
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
      this.trackStream(streamId, writer);
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
   * Drop the routing state left over once every stream is gone, answering any
   * POST still waiting on a JSON response with whatever arrived rather than
   * leaving the request hanging.
   */
  private releasePendingRequests(): void {
    for (const collector of this._jsonResponseCollectors.values()) {
      collector.resolve(
        collector.expectedIds
          .map((id) => collector.responses.get(id))
          .filter((response) => response !== undefined),
      );
    }
    this._jsonResponseCollectors.clear();
    this._requestToStreamMapping.clear();
  }

  /**
   * Answer a JSON-mode POST once every request it carried has a response
   */
  private settleJsonResponse(
    streamId: StreamId,
    collector: PendingJsonResponse,
  ): void {
    const responses: JSONRPCMessage[] = [];
    for (const id of collector.expectedIds) {
      const response = collector.responses.get(id);
      if (!response) {
        // Still waiting on at least one of this POST's requests
        return;
      }
      responses.push(response);
    }

    this._jsonResponseCollectors.delete(streamId);
    for (const id of collector.expectedIds) {
      this._requestToStreamMapping.delete(id);
    }
    collector.resolve(responses);
  }

  private trackStream(
    streamId: StreamId,
    writer: WritableStreamDefaultWriter<Uint8Array>,
  ): void {
    this._streamMapping.set(streamId, writer);
    const removeStreamIfCurrent = () => {
      if (this._streamMapping.get(streamId) !== writer) {
        return;
      }
      this._streamMapping.delete(streamId);
      // Drop the routing entries that pointed at this stream, so a response
      // arriving after the client gave up is not looked up against a writer
      // that no longer exists. No-op for the standalone GET stream, which is
      // never a request target.
      for (const [requestId, mappedStreamId] of this._requestToStreamMapping) {
        if (mappedStreamId === streamId) {
          this._requestToStreamMapping.delete(requestId);
        }
      }
    };
    void writer.closed.then(removeStreamIfCurrent, removeStreamIfCurrent);
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
