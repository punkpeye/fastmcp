/**
 * Web-standard Streamable HTTP Server Transport for MCP
 *
 * This transport implements the MCP Streamable HTTP specification using
 * web standard APIs (Request, Response, TransformStream) for compatibility
 * with edge runtimes like Cloudflare Workers, Deno, and Bun.
 */

import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  CancelledNotificationSchema,
  ErrorCode,
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
  /**
   * Replays whose stream id is still being resolved. `replayEventsAfter` only
   * reveals which stream it was replaying once it settles, so a standalone
   * send during that window has nothing to test against; persist rather than
   * drop, since over-storing for the length of a replay beats losing an event.
   */
  private _replaysInFlight = 0;

  private _requestToStreamMapping = new Map<RequestId, StreamId>();

  private _standaloneSseStreamId = "_GET_stream";
  /**
   * Whether a client has held the standalone GET stream during this session.
   * Latched rather than read from `_streamMapping`, so persistence survives
   * the disconnect window the store exists to cover while still telling a
   * dropped stream apart from one that was never opened. Reset with the rest
   * of the per-session state, since the next session starts with no stream.
   */
  private _standaloneStreamOpened = false;
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
    this._standaloneStreamOpened = false;
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
      // With an event store the message must be persisted even if the client
      // has already disconnected, so a reconnect with Last-Event-Id can replay
      // it. The live write to the SSE stream is best-effort on top of that.
      const store = this.shouldPersist(streamId, writer)
        ? this._eventStore
        : undefined;

      if (writer || store) {
        try {
          let eventId: string | undefined;
          if (store) {
            eventId = await store.storeEvent(streamId, message);
          }
          if (writer) {
            if (eventId === undefined) {
              await this.writeSSEEvent(writer, message);
            } else {
              await this.writeSSEEventWithId(writer, eventId, message);
            }
          }
        } catch (error) {
          this.onerror?.(
            error instanceof Error ? error : new Error(String(error)),
          );
        }

        // Close the POST stream once all of its requests are answered. Drained
        // whether or not the store and the socket cooperated: with an event
        // store configured `trackStream` deliberately leaves routing entries
        // alone on disconnect, so this is the only thing that reclaims them,
        // and giving up on a failed write strands the entry until the session
        // ends.
        if (requestId !== undefined && isResponse) {
          this._requestToStreamMapping.delete(requestId);
          const streamInUse = Array.from(
            this._requestToStreamMapping.values(),
          ).includes(streamId);
          if (!streamInUse) {
            this._streamMapping.delete(streamId);
            if (writer) {
              try {
                await writer.close();
              } catch (error) {
                this.onerror?.(
                  error instanceof Error ? error : new Error(String(error)),
                );
              }
            }
          }
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
    // Per-session, like the session id below: this instance stays usable, and
    // the next session starts having opened no standalone stream of its own.
    this._standaloneStreamOpened = false;
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

    // A cancelled request is never answered — the SDK suppresses the response
    // of a request whose abort signal fired — so send() never runs for its id
    // and nothing else would ever drop its routing entry. Release it here.
    for (const message of messages) {
      const cancelled = CancelledNotificationSchema.safeParse(message);
      if (cancelled.success) {
        await this.releaseCancelledRequest(cancelled.data.params.requestId);
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

      // Every request this POST carried was cancelled, so there is nothing to
      // put in the body — and an empty body is not a JSON-RPC message. Answer
      // the way a POST that carried no requests at all does.
      if (responses.length === 0) {
        return new Response(null, {
          headers: this.getResponseHeaders(),
          status: 202,
        });
      }

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

    // `getStreamIdForEventId` is optional, so this only asks stores that can
    // answer which stream the reconnect would land on before any work is done.
    // Unlike the SDK's Node transport, an event id the store does not
    // recognise is not rejected outright here: that store may still resolve it
    // in `replayEventsAfter`, and answering 400 for it would turn reconnects
    // that work today into errors.
    if (this._eventStore.getStreamIdForEventId) {
      const existingStreamId =
        await this._eventStore.getStreamIdForEventId(lastEventId);
      if (
        existingStreamId !== undefined &&
        this._streamMapping.has(existingStreamId)
      ) {
        return this.createErrorResponse(
          409,
          -32000,
          "Conflict: SSE stream already exists for this replay",
        );
      }
    }

    const { readable, writable } = new TransformStream<Uint8Array>();
    const writer = writable.getWriter();

    this._replaysInFlight += 1;
    try {
      const streamId = await this._eventStore.replayEventsAfter(lastEventId, {
        send: async (eventId, message) => {
          await this.writeSSEEventWithId(writer, eventId, message);
        },
      });

      // The check above runs against the id the store predicts, and only for
      // stores that implement the optional lookup. This one runs against the
      // id the writer is about to be registered under, with no await between
      // it and the `set` inside `trackStream` — so it also covers stores
      // without `getStreamIdForEventId` (the common case), a store whose two
      // methods disagree, and a second reconnect that raced past the check
      // above while this one was awaiting its replay.
      if (this._streamMapping.has(streamId)) {
        await writer.close();
        return this.createErrorResponse(
          409,
          -32000,
          "Conflict: SSE stream already exists for this replay",
        );
      }

      this.trackStream(streamId, writer);
    } catch (error) {
      await writer.close();
      return this.createErrorResponse(500, -32000, `Replay failed: ${error}`);
    } finally {
      this._replaysInFlight -= 1;
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
   * Settle the routing state of a request the client cancelled, which will
   * therefore never produce a response: the same drain `send()` performs once
   * a response has been written, minus the response. Idempotent, so it is a
   * no-op if the response won the race against the cancellation.
   */
  private async releaseCancelledRequest(requestId: RequestId): Promise<void> {
    const streamId = this._requestToStreamMapping.get(requestId);
    if (streamId === undefined) {
      return;
    }

    // A JSON-mode POST has no stream to close: it is parked on its collector,
    // which would keep waiting for a response that is never coming. Stop
    // expecting that one and answer with whatever the POST's other requests
    // produce.
    const collector = this._jsonResponseCollectors.get(streamId);
    if (collector) {
      collector.expectedIds = collector.expectedIds.filter(
        (id) => id !== requestId,
      );
      this._requestToStreamMapping.delete(requestId);
      this.settleJsonResponse(streamId, collector);
      return;
    }

    this._requestToStreamMapping.delete(requestId);
    const streamInUse = Array.from(
      this._requestToStreamMapping.values(),
    ).includes(streamId);
    if (streamInUse) {
      return;
    }

    // Nothing will ever be written to this stream again; close it rather than
    // leaving the client reading a stream that can only hang.
    const writer = this._streamMapping.get(streamId);
    this._streamMapping.delete(streamId);
    if (writer) {
      try {
        await writer.close();
      } catch (error) {
        this.onerror?.(
          error instanceof Error ? error : new Error(String(error)),
        );
      }
    }
  }

  /**
   * Drop the routing state left over once every stream is gone, answering any
   * POST still waiting on a JSON response with whatever arrived rather than
   * leaving the request hanging.
   */
  private releasePendingRequests(): void {
    for (const collector of this._jsonResponseCollectors.values()) {
      collector.resolve(
        collector.expectedIds.map(
          (id) =>
            collector.responses.get(id) ??
            // Nobody can answer this one now. Dropping it silently would leave
            // the POST with an empty body for a single request and an empty
            // array for a batch, neither of which a client can read as a
            // result.
            ({
              error: {
                code: ErrorCode.ConnectionClosed,
                message:
                  "Connection closed: the session ended before this request was answered",
              },
              id,
              jsonrpc: "2.0",
            } satisfies JSONRPCMessage),
        ),
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

  /**
   * Whether an event addressed to `streamId` should go to the event store.
   *
   * Everything but the standalone stream is persisted whenever a store is
   * configured: those ids exist only because their stream did. The standalone
   * id is a constant, so it resolves whether or not a client ever opened that
   * stream, and storing before the first GET writes events nothing can reach —
   * replay is keyed off Last-Event-Id, and a client that never held the stream
   * was never handed an id to resume from.
   */
  private shouldPersist(
    streamId: StreamId,
    writer: undefined | WritableStreamDefaultWriter<Uint8Array>,
  ): boolean {
    if (this._eventStore === undefined) {
      return false;
    }

    if (streamId !== this._standaloneSseStreamId) {
      return true;
    }

    return (
      this._standaloneStreamOpened ||
      // A live writer means the stream is open now, which is stronger evidence
      // than the latch. Belt and braces: it keeps a writer reaching this point
      // without `trackStream` from producing an SSE event with no `id:`.
      writer !== undefined ||
      this._replaysInFlight > 0
    );
  }

  private trackStream(
    streamId: StreamId,
    writer: WritableStreamDefaultWriter<Uint8Array>,
  ): void {
    // Latched here rather than at each call site so a new way of opening the
    // standalone stream cannot forget to record it.
    if (streamId === this._standaloneSseStreamId) {
      this._standaloneStreamOpened = true;
    }
    this._streamMapping.set(streamId, writer);
    const removeStreamIfCurrent = () => {
      if (this._streamMapping.get(streamId) !== writer) {
        return;
      }
      this._streamMapping.delete(streamId);
      // With an event store, a response can still arrive after the client gave
      // up, and it must be persisted for replay. Keep the routing entry so
      // send() can resolve the stream id and store under it; send() drops the
      // entry once the response has been stored.
      if (this._eventStore) {
        return;
      }
      // No event store: nothing will be persisted for this stream, so drop the
      // routing entries now rather than leaking them. No-op for the standalone
      // GET stream, which is never a request target.
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
