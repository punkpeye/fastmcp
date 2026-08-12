import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  LATEST_PROTOCOL_VERSION,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { WebStreamableHTTPServerTransport } from "./WebStreamableHTTPServerTransport.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type JsonResponse = any;

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
