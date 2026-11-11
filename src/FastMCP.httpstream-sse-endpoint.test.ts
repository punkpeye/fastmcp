import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { expect, test } from "vitest";

import { FastMCP } from "./FastMCP.js";
import { getTestPort } from "./getTestPort.js";

const startServer = async (sseEndpoint: `/${string}` | null) => {
  const port = await getTestPort();

  const server = new FastMCP({
    name: "Test",
    version: "1.0.0",
  });

  await server.start({
    httpStream: {
      port,
      sseEndpoint,
    },
    transportType: "httpStream",
  });

  return { port, server };
};

const openEventStream = (port: number, path: string) =>
  fetch(`http://localhost:${port}${path}`, {
    headers: {
      accept: "text/event-stream",
    },
  });

test("sseEndpoint: null disables the legacy SSE endpoints", async () => {
  const { port, server } = await startServer(null);

  try {
    const sse = await openEventStream(port, "/sse");
    expect(sse.status).toBe(404);
    await sse.body?.cancel();

    const messages = await fetch(
      `http://localhost:${port}/messages?sessionId=missing`,
      {
        body: "{}",
        headers: {
          "content-type": "application/json",
        },
        method: "POST",
      },
    );
    expect(messages.status).toBe(404);

    // The Streamable HTTP endpoint is untouched.
    const initialize = await fetch(`http://localhost:${port}/mcp`, {
      body: JSON.stringify({
        id: 1,
        jsonrpc: "2.0",
        method: "initialize",
        params: {
          capabilities: {},
          clientInfo: { name: "test-client", version: "1.0.0" },
          protocolVersion: "2025-06-18",
        },
      }),
      headers: {
        accept: "application/json, text/event-stream",
        "content-type": "application/json",
      },
      method: "POST",
    });
    expect(initialize.status).toBe(200);
    await initialize.body?.cancel();
  } finally {
    await server.stop();
  }
});

test("sseEndpoint moves the legacy SSE endpoint", async () => {
  const { port, server } = await startServer("/events");

  try {
    const moved = await openEventStream(port, "/events");
    expect(moved.status).toBe(200);
    expect(moved.headers.get("content-type")).toContain("text/event-stream");
    await moved.body?.cancel();

    const old = await openEventStream(port, "/sse");
    expect(old.status).toBe(404);
    await old.body?.cancel();

    // A session opened on the moved endpoint still posts to /messages.
    const client = new Client({ name: "test-client", version: "1.0.0" });
    await client.connect(
      new SSEClientTransport(new URL(`http://localhost:${port}/events`)),
    );
    try {
      await client.ping();
    } finally {
      await client.close();
    }
  } finally {
    await server.stop();
  }
});
