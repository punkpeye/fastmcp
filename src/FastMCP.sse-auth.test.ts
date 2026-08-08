import type http from "http";

import { getRandomPort } from "get-port-please";
import { expect, test, vi } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

/**
 * mcp-proxy serves an SSE endpoint at `/sse` by default and — unlike the HTTP
 * Stream endpoint — does not apply `authenticate` to it. FastMCP must therefore
 * reject unauthenticated sessions itself, otherwise `/sse` is an unauthenticated
 * back door into a server whose `/mcp` endpoint returns 401.
 *
 * Reported by @pacocartones.
 */

type Session = { id: number };

const startServer = async (
  authenticate: (
    request: http.IncomingMessage,
  ) => Promise<null | Session | undefined>,
  port: number,
) => {
  const server = new FastMCP<Session>({
    authenticate,
    name: "Test",
    version: "1.0.0",
  });

  server.addTool({
    canAccess: (auth) => auth?.id === 1,
    description: "Returns a secret",
    execute: async () => "TOP_SECRET",
    name: "read_secret",
    parameters: z.object({}),
  });

  await server.start({
    httpStream: { endpoint: "/mcp", port },
    transportType: "httpStream",
  });

  return server;
};

/**
 * Opens an SSE stream and reads the `endpoint` event off it. The stream is left
 * open — cancelling it closes the session server-side — so callers must always
 * invoke the returned `close`.
 */
const openSse = async (port: number, token?: string) => {
  const response = await fetch(`http://localhost:${port}/sse`, {
    headers: {
      accept: "text/event-stream",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
  });

  if (response.status !== 200) {
    await response.text().catch(() => undefined);

    return {
      close: async () => undefined,
      messagesUrl: null,
      status: response.status,
    };
  }

  const reader = response.body!.getReader();
  const close = () => reader.cancel().catch(() => undefined);
  const decoder = new TextDecoder();
  let buffered = "";
  const deadline = Date.now() + 2000;

  while (
    !/event: endpoint\ndata: (.+)/.test(buffered) &&
    Date.now() < deadline
  ) {
    const { done, value } = await reader.read();

    if (done) {
      break;
    }

    buffered += decoder.decode(value, { stream: true });
  }

  const match = buffered.match(/event: endpoint\ndata: (.+)/);

  return {
    close,
    messagesUrl: match ? match[1].trim() : null,
    status: response.status,
  };
};

const initialize = (port: number) =>
  fetch(`http://localhost:${port}/mcp`, {
    body: JSON.stringify({
      id: 1,
      jsonrpc: "2.0",
      method: "initialize",
      params: {
        capabilities: {},
        clientInfo: { name: "anonymous", version: "1.0.0" },
        protocolVersion: "2024-11-05",
      },
    }),
    headers: {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
    },
    method: "POST",
  });

test("rejects unauthenticated SSE connections when authenticate returns undefined", async () => {
  const port = await getRandomPort();
  const authenticate = vi.fn(async () => undefined);
  const server = await startServer(authenticate, port);

  try {
    // Control: the advertised endpoint rejects the same request.
    const stream = await initialize(port);
    await stream.text().catch(() => undefined);

    expect(stream.status).toBe(401);

    // The SSE endpoint must reject it too, rather than handing out a session.
    const sse = await openSse(port);

    expect(sse.status).toBe(401);
    expect(sse.messagesUrl).toBeNull();
    expect(authenticate).toHaveBeenCalled();
  } finally {
    await server.stop();
  }
});

test("rejects unauthenticated SSE connections when authenticate returns null", async () => {
  const port = await getRandomPort();
  const server = await startServer(async () => null, port);

  try {
    const sse = await openSse(port);

    expect(sse.status).toBe(401);
    expect(sse.messagesUrl).toBeNull();
  } finally {
    await server.stop();
  }
});

test("rejects SSE connections for any falsy authenticate result", async () => {
  // `false`/`""`/`0` sit outside the `Authenticate` type, but are reachable
  // from JavaScript consumers. mcp-proxy rejects them on `/mcp`, so `/sse` has
  // to agree — `#createSession` skips `canAccess` filtering for falsy auth,
  // which would otherwise expose every tool.
  for (const result of [false, "", 0, NaN]) {
    const port = await getRandomPort();
    const server = await startServer(
      (async () => result) as unknown as () => Promise<undefined>,
      port,
    );

    try {
      const stream = await initialize(port);
      await stream.text().catch(() => undefined);

      expect(stream.status).toBe(401);

      const sse = await openSse(port);

      expect(sse.status).toBe(401);
      expect(sse.messagesUrl).toBeNull();
    } finally {
      await server.stop();
    }
  }
});

test("still allows authenticated SSE connections", async () => {
  const port = await getRandomPort();
  const server = await startServer(async (request) => {
    if (request.headers.authorization === "Bearer good-token") {
      return { id: 1 };
    }

    return undefined;
  }, port);

  try {
    const sse = await openSse(port, "good-token");

    expect(sse.status).toBe(200);
    expect(sse.messagesUrl).toMatch(/^\/messages\?sessionId=/);

    // The session must be usable, not merely advertised.
    const call = await fetch(`http://localhost:${port}${sse.messagesUrl}`, {
      body: JSON.stringify({
        id: 1,
        jsonrpc: "2.0",
        method: "initialize",
        params: {
          capabilities: {},
          clientInfo: { name: "client", version: "1.0.0" },
          protocolVersion: "2024-11-05",
        },
      }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });
    await call.text().catch(() => undefined);

    expect(call.status).toBe(202);

    await sse.close();
  } finally {
    await server.stop();
  }
});
