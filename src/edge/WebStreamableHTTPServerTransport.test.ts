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
