import type http from "http";

import { getRandomPort } from "get-port-please";
import { expect, test, vi } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

/**
 * On `httpStream`, FastMCP passes `authenticate` to mcp-proxy (which calls it
 * once per request to gate the 401) AND re-calls it inside its own
 * `createServer` callback to obtain the auth for the session. Both calls
 * receive the identical `IncomingMessage`, so a single HTTP request was
 * authenticated twice — a regression from 3.13 that halves the effective
 * rate-limit budget of any non-idempotent `authenticate`.
 *
 * Reported by @aaronik in #352. A per-request memo keyed on the request object
 * must collapse the two calls into exactly one real invocation while keeping
 * per-request authentication (a new request is a new object).
 */

type Session = { userId: string };

const initialize = (port: number, path = "/mcp") =>
  fetch(`http://localhost:${port}${path}`, {
    body: JSON.stringify({
      id: 1,
      jsonrpc: "2.0",
      method: "initialize",
      params: {
        capabilities: {},
        clientInfo: { name: "repro", version: "1.0.0" },
        protocolVersion: "2024-11-05",
      },
    }),
    headers: {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
    },
    method: "POST",
  });

const startServer = async (
  authenticate: (request: http.IncomingMessage) => Promise<Session>,
  port: number,
  stateless: boolean,
) => {
  const server = new FastMCP<Session>({
    authenticate,
    name: "Test",
    version: "1.0.0",
  });

  server.addTool({
    description: "returns pong",
    execute: async () => "pong",
    name: "ping",
    parameters: z.object({}),
  });

  await server.start({
    httpStream: { port, stateless },
    transportType: "httpStream",
  });

  return server;
};

for (const stateless of [true, false]) {
  test(`authenticate runs exactly once per httpStream request (stateless: ${stateless})`, async () => {
    const port = await getRandomPort();
    const seen: http.IncomingMessage[] = [];
    const authenticate = vi.fn(async (request: http.IncomingMessage) => {
      seen.push(request);

      return { userId: "repro" };
    });
    const server = await startServer(authenticate, port, stateless);

    try {
      const response = await initialize(port);
      await response.text().catch(() => undefined);

      // One HTTP request => one real authenticate invocation.
      expect(authenticate).toHaveBeenCalledTimes(1);

      // Any invocations that did happen were for the very same request object,
      // proving this is one request authenticated once — not two requests.
      for (const request of seen) {
        expect(request).toBe(seen[0]);
      }
    } finally {
      await server.stop();
    }
  });

  test(`authenticate runs once per request across distinct requests (stateless: ${stateless})`, async () => {
    // The memo must be per-request, not per-server: two separate requests are
    // two invocations, so per-request auth (and its rate-limiting side effects)
    // is preserved.
    const port = await getRandomPort();
    const authenticate = vi.fn(async () => ({ userId: "repro" }));
    const server = await startServer(authenticate, port, stateless);

    try {
      for (const response of [await initialize(port), await initialize(port)]) {
        await response.text().catch(() => undefined);
      }

      expect(authenticate).toHaveBeenCalledTimes(2);
    } finally {
      await server.stop();
    }
  });
}
