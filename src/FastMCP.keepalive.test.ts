import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { LoggingMessageNotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { getRandomPort } from "get-port-please";
import { setTimeout as delay } from "timers/promises";
import { describe, expect, it } from "vitest";

import { FastMCP } from "./FastMCP.js";

const KEEPALIVE_LOGGER = "fastmcp-keepalive";
const TOOL_DURATION_MS = 100;
const KEEPALIVE_INTERVAL_MS = 15;

type ServerMessage = {
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
};

// Reads the SSE frames of a tools/call POST. Asserting on the bytes of this
// response is the whole point: it is the connection an idle-timeout proxy kills.
const callSlowTool = async (
  port: number,
  sessionId?: string,
): Promise<ServerMessage[]> => {
  const response = await fetch(`http://localhost:${port}/mcp`, {
    body: JSON.stringify({
      id: 1,
      jsonrpc: "2.0",
      method: "tools/call",
      params: { arguments: {}, name: "slow" },
    }),
    headers: {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
      ...(sessionId ? { "mcp-session-id": sessionId } : {}),
    },
    method: "POST",
  });

  expect(response.status).toBe(200);

  return (await response.text())
    .split("\n")
    .filter((line) => line.startsWith("data:"))
    .map((line) => JSON.parse(line.slice("data:".length).trim()));
};

const startServer = async (
  streamKeepalive?: {
    enabled?: boolean;
    intervalMs?: number;
  },
  stateless = true,
) => {
  const port = await getRandomPort();

  const server = new FastMCP({
    name: "Test",
    version: "1.0.0",
    ...(streamKeepalive ? { streamKeepalive } : {}),
  });

  server.addTool({
    description: "Sleeps without writing anything to the response",
    execute: async () => {
      await delay(TOOL_DURATION_MS);

      return "done";
    },
    name: "slow",
  });

  await server.start({
    httpStream: { port, stateless },
    transportType: "httpStream",
  });

  return { port, server };
};

// A stateful server issues a session id and keeps a standalone stream, but a
// tool call still answers on its own POST stream, which is what must stay open.
const initializeSession = async (port: number): Promise<string> => {
  const response = await fetch(`http://localhost:${port}/mcp`, {
    body: JSON.stringify({
      id: 0,
      jsonrpc: "2.0",
      method: "initialize",
      params: {
        capabilities: {},
        clientInfo: { name: "test-client", version: "0.0.0" },
        protocolVersion: "2025-03-26",
      },
    }),
    headers: {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
    },
    method: "POST",
  });

  const sessionId = response.headers.get("mcp-session-id");

  await response.text();

  expect(sessionId).toBeTruthy();

  await fetch(`http://localhost:${port}/mcp`, {
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    }),
    headers: {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
      "mcp-session-id": sessionId as string,
    },
    method: "POST",
  });

  return sessionId as string;
};

// In-memory transports resolve every send, so a timer that outlives its request
// keeps delivering to the client. That makes leaks observable, unlike a stateless
// HTTP call whose stream mapping is torn down with the response.
const connectInMemory = async (server: FastMCP) => {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();

  const client = new Client({ name: "test-client", version: "0.0.0" });

  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);

  const received: { logger?: string }[] = [];

  client.setNotificationHandler(LoggingMessageNotificationSchema, (n) => {
    received.push(n.params as { logger?: string });
  });

  const keepalivesSeen = () =>
    received.filter((p) => p.logger === KEEPALIVE_LOGGER).length;

  return { client, keepalivesSeen };
};

// The exact frame the server must write, so a change to the level, the logger,
// the payload shape, or the interpolated tool name fails the test.
const EXPECTED_KEEPALIVE = {
  jsonrpc: "2.0",
  method: "notifications/message",
  params: {
    data: { message: "keepalive while 'slow' is running" },
    level: "debug",
    logger: KEEPALIVE_LOGGER,
  },
};

const EXPECTED_RESULT = {
  id: 1,
  jsonrpc: "2.0",
  result: { content: [{ text: "done", type: "text" }] },
};

// Collapses repeats so the assertion can state "every frame was exactly this".
const distinct = (frames: ServerMessage[]) => [
  ...new Map(frames.map((frame) => [JSON.stringify(frame), frame])).values(),
];

describe("FastMCP stream keepalive", () => {
  it("keeps a stateless tool call's stream alive while the tool runs", async () => {
    const { port, server } = await startServer({
      enabled: true,
      intervalMs: KEEPALIVE_INTERVAL_MS,
    });

    try {
      const frames = await callSlowTool(port);
      const beforeResult = frames.slice(0, -1);

      // The tool writes nothing for its whole duration, so every frame ahead of
      // the result came from the keepalive - and must be exactly it.
      expect(beforeResult.length).toBeGreaterThanOrEqual(2);
      expect(distinct(beforeResult)).toEqual([EXPECTED_KEEPALIVE]);
      expect(frames.at(-1)).toEqual(EXPECTED_RESULT);
    } finally {
      await server.stop();
    }
  });

  it("keeps a stateful tool call's stream alive too", async () => {
    const { port, server } = await startServer(
      { enabled: true, intervalMs: KEEPALIVE_INTERVAL_MS },
      false,
    );

    try {
      const sessionId = await initializeSession(port);
      const frames = await callSlowTool(port, sessionId);
      const beforeResult = frames.slice(0, -1);

      // `ping` keeps the standalone stream warm, never this one, so a stateful
      // deployment needs the keepalive just as much as a stateless one.
      expect(beforeResult.length).toBeGreaterThanOrEqual(2);
      expect(distinct(beforeResult)).toEqual([EXPECTED_KEEPALIVE]);
      expect(frames.at(-1)).toEqual(EXPECTED_RESULT);
    } finally {
      await server.stop();
    }
  });

  it("writes no keepalives unless they are opted into", async () => {
    const { port, server } = await startServer();

    try {
      const frames = await callSlowTool(port);

      // Not just "no keepalives": nothing at all is added to the stream.
      expect(frames).toEqual([EXPECTED_RESULT]);
    } finally {
      await server.stop();
    }
  });

  it("still runs tools whose execute returns a plain value", async () => {
    // No streamKeepalive configured: this must behave exactly as it did before
    // the option existed.
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    server.addTool({
      description: "Synchronous tool",
      // JS consumers can return a plain value; the handler awaited it before the
      // keepalive existed, so it must keep working.
      execute: (() => "done") as unknown as () => Promise<string>,
      name: "sync",
    });

    const { client } = await connectInMemory(server);

    const result = await client.callTool({ arguments: {}, name: "sync" });

    expect(result).toMatchObject({ content: [{ text: "done", type: "text" }] });
  });

  it("stops keepalives when a tool throws synchronously", async () => {
    const server = new FastMCP({
      name: "Test",
      streamKeepalive: { enabled: true, intervalMs: KEEPALIVE_INTERVAL_MS },
      version: "1.0.0",
    });

    server.addTool({
      description: "Throws before returning a promise",
      execute: () => {
        throw new Error("sync boom");
      },
      name: "boom",
    });

    const { client, keepalivesSeen } = await connectInMemory(server);

    await client.callTool({ arguments: {}, name: "boom" });

    const afterResponse = keepalivesSeen();

    await delay(KEEPALIVE_INTERVAL_MS * 5);

    expect(keepalivesSeen()).toBe(afterResponse);
  });

  it("stops keepalives when a tool call times out", async () => {
    const server = new FastMCP({
      name: "Test",
      streamKeepalive: { enabled: true, intervalMs: KEEPALIVE_INTERVAL_MS },
      version: "1.0.0",
    });

    server.addTool({
      description: "Outlives its own timeout",
      execute: async () => {
        await delay(TOOL_DURATION_MS * 2);

        return "late";
      },
      name: "hangs",
      timeoutMs: KEEPALIVE_INTERVAL_MS * 2,
    });

    const { client, keepalivesSeen } = await connectInMemory(server);

    await client.callTool({ arguments: {}, name: "hangs" });

    const afterResponse = keepalivesSeen();

    await delay(KEEPALIVE_INTERVAL_MS * 6);

    // timeoutMs exists for tools that hang, so the keepalive must not keep
    // writing for the rest of the abandoned tool's lifetime.
    expect(keepalivesSeen()).toBe(afterResponse);
  });

  it("ignores a non-positive interval instead of flooding the stream", async () => {
    const server = new FastMCP({
      name: "Test",
      streamKeepalive: { enabled: true, intervalMs: 0 },
      version: "1.0.0",
    });

    server.addTool({
      description: "Slow enough to be flooded",
      execute: async () => {
        await delay(TOOL_DURATION_MS);

        return "done";
      },
      name: "slow",
    });

    const { client, keepalivesSeen } = await connectInMemory(server);

    await client.callTool({ arguments: {}, name: "slow" });

    // 0 must fall back to the default interval, not fire every tick.
    expect(keepalivesSeen()).toBe(0);
  });
});
