import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  LATEST_PROTOCOL_VERSION,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { WebStreamableHTTPServerTransport } from "./WebStreamableHTTPServerTransport.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type JsonResponse = any;

type TransportInternals = {
  _jsonResponseCollectors: Map<string, unknown>;
  _requestToStreamMapping: Map<number | string, string>;
  _streamMapping: Map<string, WritableStreamDefaultWriter<Uint8Array>>;
};

/** Let a settled `writer.closed` run its cleanup before asserting on it. */
const flushMicrotasks = () => new Promise((resolve) => setTimeout(resolve, 0));

const createGetRequest = (lastEventId?: string) =>
  new Request("http://localhost/mcp", {
    headers: {
      Accept: "text/event-stream",
      "mcp-session-id": "test-session",
      ...(lastEventId ? { "last-event-id": lastEventId } : {}),
    },
  });

const createDeleteRequest = () =>
  new Request("http://localhost/mcp", {
    headers: { "mcp-session-id": "test-session" },
    method: "DELETE",
  });

const createPostRequest = (body: unknown, accept: string, sessionId?: string) =>
  new Request("http://localhost/mcp", {
    body: JSON.stringify(body),
    headers: {
      Accept: accept,
      "Content-Type": "application/json",
      ...(sessionId ? { "mcp-session-id": sessionId } : {}),
    },
    method: "POST",
  });

const createInitializeRequest = (accept: string) =>
  createPostRequest(
    {
      id: 1,
      jsonrpc: "2.0",
      method: "initialize",
      params: {
        capabilities: {},
        clientInfo: { name: "test-client", version: "1.0.0" },
        protocolVersion: LATEST_PROTOCOL_VERSION,
      },
    },
    accept,
  );

const createServer = () =>
  new Server({ name: "TestServer", version: "1.0.0" }, { capabilities: {} });

/**
 * Server whose only tool answers after `delayMs`, i.e. well after the tick that
 * dispatching the request runs on.
 */
const createSlowToolServer = (delayMs: number) => {
  const server = new Server(
    { name: "TestServer", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    return { content: [{ text: `done:${request.params.name}`, type: "text" }] };
  });
  return server;
};

/**
 * Server whose only tool never answers on its own: the request stays open until
 * something aborts it, which is what a client cancellation or a terminated
 * session does.
 */
const createHangingToolServer = () => {
  const server = new Server(
    { name: "TestServer", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(CallToolRequestSchema, (_request, extra) => {
    return new Promise<never>((_resolve, reject) => {
      extra.signal.addEventListener("abort", () =>
        reject(extra.signal.reason ?? new Error("aborted")),
      );
    });
  });
  return server;
};

const createCancelledNotification = (requestId: number) => ({
  jsonrpc: "2.0",
  method: "notifications/cancelled",
  params: { reason: "client gave up", requestId },
});

const createToolCall = (id: number, name: string) => ({
  id,
  jsonrpc: "2.0",
  method: "tools/call",
  params: { arguments: {}, name },
});

/**
 * Reads an SSE body to completion, resolving to null if the stream never
 * finishes, so a routing regression fails the test rather than hanging it.
 */
const readSSEBody = async (response: Response, timeoutMs = 2000) => {
  const stream = response.body;
  if (!stream) {
    throw new Error("Expected an SSE stream body");
  }

  const readBody = async (): Promise<string> => {
    const reader = stream.getReader();
    const decoder = new TextDecoder();
    let text = "";
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      text += decoder.decode(value, { stream: true });
    }
    return text;
  };

  return Promise.race([
    readBody(),
    new Promise<null>((resolve) => setTimeout(() => resolve(null), timeoutMs)),
  ]);
};

describe("WebStreamableHTTPServerTransport", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should deliver the response on the SSE stream", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      sessionIdGenerator: () => "test-session",
    });
    await createServer().connect(transport);

    const response = await transport.handleRequest(
      createInitializeRequest("application/json, text/event-stream"),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");

    // The SDK produces the response asynchronously; the stream must deliver
    // it and then close instead of hanging forever.
    const body = await readSSEBody(response);

    expect(body).not.toBeNull();
    expect(body).toContain("data: ");
    expect(body).toContain('"serverInfo"');
    expect(body).toContain("TestServer");
  });

  it("should respond with JSON when enableJsonResponse is set", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => "test-session",
    });
    await createServer().connect(transport);

    const response = await transport.handleRequest(
      createInitializeRequest("application/json"),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.jsonrpc).toBe("2.0");
    expect(body.id).toBe(1);
    expect(body.result.serverInfo.name).toBe("TestServer");
  });

  it("should release the standalone SSE stream when the client cancels", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => "test-session",
    });
    await createServer().connect(transport);
    await transport.handleRequest(createInitializeRequest("application/json"));

    const first = await transport.handleRequest(createGetRequest());
    expect(first.status).toBe(200);

    const whileActive = await transport.handleRequest(createGetRequest());
    expect(whileActive.status).toBe(409);

    await first.body?.cancel("client disconnected");

    const afterCancel = await transport.handleRequest(createGetRequest());
    expect(afterCancel.status).toBe(200);
    await afterCancel.body?.cancel();
  });

  it("should release a resumed SSE stream when the client cancels", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      enableJsonResponse: true,
      eventStore: {
        replayEventsAfter: async () => "_GET_stream",
        storeEvent: async () => "evt-1",
      },
      sessionIdGenerator: () => "test-session",
    });
    await createServer().connect(transport);
    await transport.handleRequest(createInitializeRequest("application/json"));

    const resumed = await transport.handleRequest(createGetRequest("evt-0"));
    expect(resumed.status).toBe(200);
    await resumed.body?.cancel("client disconnected");

    const afterCancel = await transport.handleRequest(createGetRequest());
    expect(afterCancel.status).toBe(200);
    await afterCancel.body?.cancel();
  });

  it("should reject a replayed stream that collides with one already live", async () => {
    // Two reconnects with Last-Event-Id can resolve to the same streamId (the
    // event store groups events by stream, not by connection). The second one
    // must not silently overwrite the first writer in `_streamMapping` — that
    // orphans the first connection's stream forever and hands its future
    // events to the second writer instead. `getStreamIdForEventId` exists
    // precisely so this can be checked before the swap happens.
    const transport = new WebStreamableHTTPServerTransport({
      enableJsonResponse: true,
      eventStore: {
        getStreamIdForEventId: async () => "resumed-stream",
        replayEventsAfter: async () => "resumed-stream",
        storeEvent: async () => "evt-1",
      },
      sessionIdGenerator: () => "test-session",
    });
    await createServer().connect(transport);
    await transport.handleRequest(createInitializeRequest("application/json"));

    const internals = transport as unknown as TransportInternals;

    const first = await transport.handleRequest(createGetRequest("evt-0"));
    expect(first.status).toBe(200);
    const firstWriter = internals._streamMapping.get("resumed-stream");
    expect(firstWriter).toBeDefined();

    const second = await transport.handleRequest(createGetRequest("evt-0"));
    expect(second.status).toBe(409);
    // The first writer must still be the one tracked for this streamId.
    expect(internals._streamMapping.get("resumed-stream")).toBe(firstWriter);

    await first.body?.cancel("test cleanup");
  });

  it("should not remove a replacement stream when an old writer closes", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => "test-session",
    });
    await createServer().connect(transport);
    await transport.handleRequest(createInitializeRequest("application/json"));

    const first = await transport.handleRequest(createGetRequest());
    const streamMapping = (transport as unknown as TransportInternals)
      ._streamMapping;
    const replacementStream = new TransformStream<Uint8Array>();
    const replacementWriter = replacementStream.writable.getWriter();
    streamMapping.set("_GET_stream", replacementWriter);

    await first.body?.cancel("old client disconnected");
    await Promise.resolve();

    expect(streamMapping.get("_GET_stream")).toBe(replacementWriter);
    streamMapping.delete("_GET_stream");
    await replacementWriter.abort();
  });

  it("should release a POST SSE stream when the client cancels", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      sessionIdGenerator: () => "test-session",
    });
    await createSlowToolServer(50).connect(transport);
    // Read the initialize stream to completion so only the tool call below is
    // left in the mappings.
    await readSSEBody(
      await transport.handleRequest(
        createInitializeRequest("application/json, text/event-stream"),
      ),
    );

    const internals = transport as unknown as TransportInternals;
    const response = await transport.handleRequest(
      createPostRequest(
        createToolCall(2, "one"),
        "text/event-stream",
        "test-session",
      ),
    );

    expect(response.status).toBe(200);
    expect(internals._streamMapping.size).toBe(1);
    expect(internals._requestToStreamMapping.size).toBe(1);

    await response.body?.cancel("client disconnected");
    await flushMicrotasks();

    expect(internals._streamMapping.size).toBe(0);
    expect(internals._requestToStreamMapping.size).toBe(0);
  });

  it("stores a response produced after the client disconnected, for later replay", async () => {
    const stored: {
      eventId: string;
      message: JsonResponse;
      streamId: string;
    }[] = [];
    const transport = new WebStreamableHTTPServerTransport({
      eventStore: {
        replayEventsAfter: async () => "unused",
        storeEvent: async (streamId, message) => {
          const eventId = `evt-${stored.length + 1}`;
          stored.push({ eventId, message, streamId });
          return eventId;
        },
      },
      sessionIdGenerator: () => "test-session",
    });
    await createSlowToolServer(50).connect(transport);
    // Consume initialize so only the tool call is left in the mappings.
    await readSSEBody(
      await transport.handleRequest(
        createInitializeRequest("application/json, text/event-stream"),
      ),
    );

    const before = stored.length;
    const response = await transport.handleRequest(
      createPostRequest(
        createToolCall(2, "one"),
        "text/event-stream",
        "test-session",
      ),
    );
    expect(response.status).toBe(200);

    // The client gives up before the 50 ms tool answers.
    await response.body?.cancel("client disconnected");
    await new Promise((resolve) => setTimeout(resolve, 100));

    // The event store is the durable side of resumability: a reconnect with
    // Last-Event-Id replays from it. If the response never reaches storeEvent,
    // it is lost for good even though the socket is what actually failed.
    const toolResponse = stored
      .slice(before)
      .find((event) => event.message.id === 2 && "result" in event.message);
    expect(toolResponse).toBeDefined();
  });

  it("stores a notification produced after the client dropped the GET stream", async () => {
    // The POST-response arm above rides `_requestToStreamMapping`; this one rides
    // the standalone GET stream, whose id is a constant (`_GET_stream`) with no
    // routing entry. A refactor that gates persistence on "was this actually
    // requested" (e.g. `requestId !== undefined`) keeps every other test green
    // and silently drops server-initiated notifications after a GET disconnect —
    // which is the #322 regression on the path where Last-Event-Id replay of
    // server pushes matters most. This pins that arm on its own.
    const stored: {
      eventId: string;
      message: JsonResponse;
      streamId: string;
    }[] = [];
    const transport = new WebStreamableHTTPServerTransport({
      eventStore: {
        replayEventsAfter: async () => "unused",
        storeEvent: async (streamId, message) => {
          const eventId = `evt-${stored.length + 1}`;
          stored.push({ eventId, message, streamId });
          return eventId;
        },
      },
      sessionIdGenerator: () => "test-session",
    });
    await createSlowToolServer(10).connect(transport);
    await readSSEBody(
      await transport.handleRequest(
        createInitializeRequest("application/json, text/event-stream"),
      ),
    );

    const get = await transport.handleRequest(createGetRequest());
    expect(get.status).toBe(200);
    // The client opens the standalone stream and then drops it.
    await get.body?.cancel("client disconnected");
    await flushMicrotasks();

    // `send()` is awaited, so the store call has happened by the time it returns:
    // no sleep needed here, unlike the wall-clock POST-response arm.
    const before = stored.length;
    await transport.send({
      jsonrpc: "2.0",
      method: "notifications/message",
      params: { data: "after the disconnect", level: "info" },
    });

    const notification = stored
      .slice(before)
      .find((event) => event.message.method === "notifications/message");
    expect(notification).toBeDefined();
  });

  it("does not store standalone-stream events before any client opens one", async () => {
    // The counterpart to the test above. `_GET_stream` is a constant, so it
    // resolves even when no GET stream has ever existed, and persisting there
    // writes events nothing can ever read: replay is keyed off Last-Event-Id,
    // and a client that never held the stream was never handed an id to resume
    // from. The GET stream is optional in the spec, so a client that only ever
    // POSTs would otherwise grow the store for the life of the session.
    const stored: {
      message: JsonResponse;
      streamId: string;
    }[] = [];
    const transport = new WebStreamableHTTPServerTransport({
      eventStore: {
        replayEventsAfter: async () => "unused",
        storeEvent: async (streamId, message) => {
          stored.push({ message, streamId });
          return `evt-${stored.length}`;
        },
      },
      sessionIdGenerator: () => "test-session",
    });
    await createServer().connect(transport);
    await readSSEBody(
      await transport.handleRequest(
        createInitializeRequest("application/json, text/event-stream"),
      ),
    );

    // Guards against the assertion below passing because the store was never
    // wired up at all: the initialize response is persisted on its POST stream.
    expect(stored.length).toBeGreaterThan(0);

    // No GET stream is ever opened.
    await transport.send({
      jsonrpc: "2.0",
      method: "notifications/message",
      params: { data: "nobody is listening", level: "info" },
    });

    expect(stored.filter((event) => event.streamId === "_GET_stream")).toEqual(
      [],
    );
  });

  it("re-arms the standalone guard for the next session on the same instance", async () => {
    // A DELETE ends the session but leaves the instance usable, so it can serve
    // a fresh initialize. A latch that outlived the session would treat session
    // two as though it had already opened a GET stream, reopening the hole the
    // test above closes.
    const stored: { streamId: string }[] = [];
    const transport = new WebStreamableHTTPServerTransport({
      eventStore: {
        replayEventsAfter: async () => "unused",
        storeEvent: async (streamId) => {
          stored.push({ streamId });
          return `evt-${stored.length}`;
        },
      },
      sessionIdGenerator: () => "test-session",
    });
    await createServer().connect(transport);
    await readSSEBody(
      await transport.handleRequest(
        createInitializeRequest("application/json, text/event-stream"),
      ),
    );

    // Session one opens the standalone stream, then drops it.
    const get = await transport.handleRequest(createGetRequest());
    await get.body?.cancel("client disconnected");
    await flushMicrotasks();

    const deleted = await transport.handleRequest(
      new Request("http://localhost/mcp", {
        headers: { "mcp-session-id": "test-session" },
        method: "DELETE",
      }),
    );
    expect(deleted.status).toBe(204);

    // Session two, on the same instance, never opens a GET stream.
    await readSSEBody(
      await transport.handleRequest(
        createInitializeRequest("application/json, text/event-stream"),
      ),
    );

    const before = stored.length;
    await transport.send({
      jsonrpc: "2.0",
      method: "notifications/message",
      params: { data: "session two, nobody listening", level: "info" },
    });

    expect(stored.slice(before)).toEqual([]);
  });

  it("stores a standalone event sent while a replay is still resolving", async () => {
    // `replayEventsAfter` only reveals which stream it replayed once it
    // settles, so during the await the stream is neither in `_streamMapping`
    // nor latched. Dropping the event there would lose it outright: it is not
    // written live either, because the writer is not yet reachable.
    const stored: { streamId: string }[] = [];
    let releaseReplay: (() => void) | undefined;
    const replayGate = new Promise<void>((resolve) => {
      releaseReplay = resolve;
    });

    const transport = new WebStreamableHTTPServerTransport({
      eventStore: {
        replayEventsAfter: async () => {
          await replayGate;
          return "_GET_stream";
        },
        storeEvent: async (streamId) => {
          stored.push({ streamId });
          return `evt-${stored.length}`;
        },
      },
      // Stateless: handleGetRequest skips the session check, so a resume can
      // land on an instance that never served the original GET.
      sessionIdGenerator: undefined,
    });
    await createServer().connect(transport);

    const resuming = transport.handleRequest(createGetRequest("evt-0"));
    await flushMicrotasks();

    const before = stored.length;
    await transport.send({
      jsonrpc: "2.0",
      method: "notifications/message",
      params: { data: "sent mid-replay", level: "info" },
    });
    expect(stored.slice(before)).toHaveLength(1);

    releaseReplay?.();
    await (await resuming).body?.cancel("done");
  });

  it("releases the routing entry of a request the client cancelled", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      eventStore: {
        replayEventsAfter: async () => "unused",
        storeEvent: async () => "evt-1",
      },
      sessionIdGenerator: () => "test-session",
    });
    await createSlowToolServer(50).connect(transport);
    // Consume initialize so only the tool call is left in the mappings.
    await readSSEBody(
      await transport.handleRequest(
        createInitializeRequest("application/json, text/event-stream"),
      ),
    );

    const internals = transport as unknown as TransportInternals;
    const response = await transport.handleRequest(
      createPostRequest(
        createToolCall(2, "one"),
        "text/event-stream",
        "test-session",
      ),
    );
    expect(response.status).toBe(200);
    expect(internals._requestToStreamMapping.size).toBe(1);

    // Cancel, then drop the stream — what a client does on a user abort. The
    // SDK suppresses the response of a cancelled request, so send() never runs
    // for this id and nothing else would ever drop its routing entry.
    const cancelled = await transport.handleRequest(
      createPostRequest(
        {
          jsonrpc: "2.0",
          method: "notifications/cancelled",
          params: { reason: "user aborted", requestId: 2 },
        },
        "application/json, text/event-stream",
        "test-session",
      ),
    );
    expect(cancelled.status).toBe(202);
    await response.body?.cancel("client disconnected");
    await new Promise((resolve) => setTimeout(resolve, 100));

    expect(internals._requestToStreamMapping.size).toBe(0);
    expect(internals._streamMapping.size).toBe(0);
  });

  it("closes a POST stream whose only request was cancelled", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      sessionIdGenerator: () => "test-session",
    });
    await createSlowToolServer(50).connect(transport);
    await readSSEBody(
      await transport.handleRequest(
        createInitializeRequest("application/json, text/event-stream"),
      ),
    );

    const response = await transport.handleRequest(
      createPostRequest(
        createToolCall(2, "one"),
        "text/event-stream",
        "test-session",
      ),
    );
    expect(response.status).toBe(200);

    // The client cancels but keeps reading. No response will ever be written
    // to this stream, so it must end rather than hang until the client
    // gives up.
    await transport.handleRequest(
      createPostRequest(
        {
          jsonrpc: "2.0",
          method: "notifications/cancelled",
          params: { reason: "user aborted", requestId: 2 },
        },
        "application/json, text/event-stream",
        "test-session",
      ),
    );

    const body = await readSSEBody(response);
    expect(body).not.toBeNull();
    expect(body).toBe("");
  });

  it("releases the routing entry even when the event store rejects", async () => {
    // A store that throws must not strand the routing entry: with an event
    // store configured `trackStream` deliberately leaves those entries alone
    // on disconnect, so `send()` is the only thing that ever reclaims them.
    const transport = new WebStreamableHTTPServerTransport({
      eventStore: {
        replayEventsAfter: async () => "unused",
        storeEvent: async () => {
          throw new Error("store is down");
        },
      },
      sessionIdGenerator: () => "test-session",
    });
    await createSlowToolServer(50).connect(transport);
    await readSSEBody(
      await transport.handleRequest(
        createInitializeRequest("application/json, text/event-stream"),
      ),
    );

    const internals = transport as unknown as TransportInternals;
    const response = await transport.handleRequest(
      createPostRequest(
        createToolCall(2, "one"),
        "text/event-stream",
        "test-session",
      ),
    );
    expect(response.status).toBe(200);
    // Only the tool call is outstanding: the initialize response drained on its
    // way through the same rejecting store, rather than leaving its id behind.
    expect(internals._requestToStreamMapping.size).toBe(1);

    await response.body?.cancel("client disconnected");
    // Long enough for the 50 ms tool to answer into the failing store.
    await new Promise((resolve) => setTimeout(resolve, 100));

    expect(internals._requestToStreamMapping.size).toBe(0);
    expect(internals._streamMapping.size).toBe(0);
  });

  it("should wait for a slow handler in JSON response mode", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => "test-session",
    });
    await createSlowToolServer(25).connect(transport);
    await transport.handleRequest(createInitializeRequest("application/json"));

    const response = await transport.handleRequest(
      createPostRequest(
        createToolCall(2, "slow"),
        "application/json",
        "test-session",
      ),
    );

    // Answering on the next tick would serialise an empty result set here.
    const body: JsonResponse = await response.json();
    expect(body.id).toBe(2);
    expect(body.result.content[0].text).toBe("done:slow");
  });

  it("should answer a batch once every request in it resolves", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => "test-session",
    });
    await createSlowToolServer(20).connect(transport);
    await transport.handleRequest(createInitializeRequest("application/json"));

    const response = await transport.handleRequest(
      createPostRequest(
        [createToolCall(2, "one"), createToolCall(3, "two")],
        "application/json",
        "test-session",
      ),
    );

    const body: JsonResponse = await response.json();
    expect(body).toHaveLength(2);
    expect(body[0].result.content[0].text).toBe("done:one");
    expect(body[1].result.content[0].text).toBe("done:two");
  });

  it("should preserve the array envelope for a one-request batch", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => "test-session",
    });
    await createSlowToolServer(0).connect(transport);
    await transport.handleRequest(createInitializeRequest("application/json"));

    const response = await transport.handleRequest(
      createPostRequest(
        [createToolCall(2, "one")],
        "application/json",
        "test-session",
      ),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(Array.isArray(body)).toBe(true);
    expect(body).toHaveLength(1);
    expect(body[0].result.content[0].text).toBe("done:one");
  });

  it("should answer a JSON-mode POST with an error when the session ends first", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => "test-session",
    });
    await createHangingToolServer().connect(transport);
    await transport.handleRequest(createInitializeRequest("application/json"));

    const pending = transport.handleRequest(
      createPostRequest(
        createToolCall(2, "never"),
        "application/json",
        "test-session",
      ),
    );
    await flushMicrotasks();

    const deleted = await transport.handleRequest(createDeleteRequest());
    expect(deleted.status).toBe(204);

    // The tool call can no longer be answered, but the POST still owes the
    // client a JSON-RPC message: an empty body under a 200 with a JSON content
    // type is unparseable, and `response.json()` throws on it.
    const response = await pending;
    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.id).toBe(2);
    expect(body.error.code).toBe(-32000);
  });

  it("should keep the array envelope when a batch loses its session", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => "test-session",
    });
    await createHangingToolServer().connect(transport);
    await transport.handleRequest(createInitializeRequest("application/json"));

    const pending = transport.handleRequest(
      createPostRequest(
        [createToolCall(2, "never")],
        "application/json",
        "test-session",
      ),
    );
    await flushMicrotasks();
    await transport.handleRequest(createDeleteRequest());

    // JSON-RPC forbids answering a batch with an empty array, which is what
    // dropping the unanswered response leaves behind.
    const body: JsonResponse = await (await pending).json();
    expect(Array.isArray(body)).toBe(true);
    expect(body).toHaveLength(1);
    expect(body[0].id).toBe(2);
    expect(body[0].error.code).toBe(-32000);
  });

  it("should release a JSON-mode POST whose request the client cancels", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => "test-session",
    });
    await createHangingToolServer().connect(transport);
    await transport.handleRequest(createInitializeRequest("application/json"));

    const internals = transport as unknown as TransportInternals;
    const pending = transport.handleRequest(
      createPostRequest(
        createToolCall(2, "never"),
        "application/json",
        "test-session",
      ),
    );
    await flushMicrotasks();
    expect(internals._jsonResponseCollectors.size).toBe(1);

    const cancelled = await transport.handleRequest(
      createPostRequest(
        createCancelledNotification(2),
        "application/json",
        "test-session",
      ),
    );
    expect(cancelled.status).toBe(202);

    // A cancelled request is never answered, so this POST carries nothing back
    // — but it must still end, and leave no routing state behind. Without the
    // release it waits on a response that is never coming.
    const response = await Promise.race([
      pending,
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 1000)),
    ]);
    expect(response).not.toBeNull();
    expect(response?.status).toBe(202);
    expect(await response?.text()).toBe("");
    expect(internals._jsonResponseCollectors.size).toBe(0);
    expect(internals._requestToStreamMapping.size).toBe(0);
  });

  it("should answer the rest of a batch when one of its requests is cancelled", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => "test-session",
    });
    const server = new Server(
      { name: "TestServer", version: "1.0.0" },
      { capabilities: { tools: {} } },
    );
    server.setRequestHandler(CallToolRequestSchema, (request, extra) => {
      if (request.params.name === "never") {
        return new Promise<never>((_resolve, reject) => {
          extra.signal.addEventListener("abort", () =>
            reject(extra.signal.reason ?? new Error("aborted")),
          );
        });
      }
      return Promise.resolve({
        content: [{ text: `done:${request.params.name}`, type: "text" }],
      });
    });
    await server.connect(transport);
    await transport.handleRequest(createInitializeRequest("application/json"));

    const pending = transport.handleRequest(
      createPostRequest(
        [createToolCall(2, "never"), createToolCall(3, "one")],
        "application/json",
        "test-session",
      ),
    );
    await flushMicrotasks();

    await transport.handleRequest(
      createPostRequest(
        createCancelledNotification(2),
        "application/json",
        "test-session",
      ),
    );

    // Dropping the cancelled id must not take the batch's other answer with it.
    const response = await Promise.race([
      pending,
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 1000)),
    ]);
    expect(response?.status).toBe(200);
    const body: JsonResponse = await response?.json();
    expect(body).toHaveLength(1);
    expect(body[0].id).toBe(3);
    expect(body[0].result.content[0].text).toBe("done:one");
  });

  it("should reject an empty JSON-RPC batch with one Invalid Request object", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => "test-session",
    });
    await createServer().connect(transport);
    await transport.handleRequest(createInitializeRequest("application/json"));

    const response = await transport.handleRequest(
      createPostRequest([], "application/json", "test-session"),
    );

    // MCP requires an HTTP error status for input the server cannot accept;
    // JSON-RPC only dictates the body shape (a single -32600 object, id null).
    expect(response.status).toBe(400);
    const body: JsonResponse = await response.json();
    expect(Array.isArray(body)).toBe(false);
    expect(body).toMatchObject({
      error: { code: -32600 },
      id: null,
      jsonrpc: "2.0",
    });
  });

  it("should not cross-deliver responses between concurrent POSTs", async () => {
    // Pinning the clock collides any wall-clock derived stream id, which would
    // route both responses onto whichever POST registered last.
    vi.spyOn(Date, "now").mockReturnValue(1700000000000);

    const transport = new WebStreamableHTTPServerTransport({
      sessionIdGenerator: () => "test-session",
    });
    await createSlowToolServer(30).connect(transport);
    const accept = "application/json, text/event-stream";
    await readSSEBody(
      await transport.handleRequest(createInitializeRequest(accept)),
    );

    const [first, second] = await Promise.all([
      transport.handleRequest(
        createPostRequest(createToolCall(2, "one"), accept, "test-session"),
      ),
      transport.handleRequest(
        createPostRequest(createToolCall(3, "two"), accept, "test-session"),
      ),
    ]);

    const [firstBody, secondBody] = await Promise.all([
      readSSEBody(first),
      readSSEBody(second),
    ]);

    expect(firstBody).toContain("done:one");
    expect(firstBody).not.toContain("done:two");
    expect(secondBody).toContain("done:two");
    expect(secondBody).not.toContain("done:one");
  });

  it("should release a pending JSON response when the transport closes", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => "test-session",
    });
    await createSlowToolServer(50).connect(transport);
    await transport.handleRequest(createInitializeRequest("application/json"));

    const pending = transport.handleRequest(
      createPostRequest(
        createToolCall(2, "slow"),
        "application/json",
        "test-session",
      ),
    );

    await new Promise((resolve) => setTimeout(resolve, 5));
    await transport.close();

    const settled = await Promise.race([
      pending.then(() => "settled"),
      new Promise<string>((resolve) => setTimeout(() => resolve("hung"), 1500)),
    ]);
    expect(settled).toBe("settled");
  });
});
