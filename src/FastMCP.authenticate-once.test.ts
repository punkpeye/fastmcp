import { getRandomPort } from "get-port-please";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

interface TestAuth {
  [key: string]: unknown;
  userId: string;
}

const initialize = (port: number) =>
  fetch(`http://localhost:${port}/mcp`, {
    body: JSON.stringify({
      id: 1,
      jsonrpc: "2.0",
      method: "initialize",
      params: {
        capabilities: {},
        clientInfo: { name: "test", version: "1.0.0" },
        protocolVersion: "2024-11-05",
      },
    }),
    headers: {
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
    },
    method: "POST",
  }).catch(() => undefined);

/**
 * `startHTTPServer` authenticates each request, and the `createServer` callback
 * handed to it needs the same result. Both used to call the consumer's hook, so
 * one request authenticated twice — silent unless `authenticate` has a side
 * effect, and destructive when it has one (a rate limiter charged there spends
 * every caller's budget at twice the intended rate).
 */
describe("authenticate is invoked once per HTTP request", () => {
  for (const stateless of [true, false]) {
    it(`calls authenticate exactly once for one request (stateless: ${stateless})`, async () => {
      const port = await getRandomPort();
      const requests: unknown[] = [];

      const server = new FastMCP<TestAuth>({
        authenticate: async (request) => {
          requests.push(request);

          return { userId: "test-user" };
        },
        name: "authenticate-once",
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

      try {
        await initialize(port);

        expect(requests).toHaveLength(1);
      } finally {
        await server.stop();
      }
    });
  }

  it("authenticates each request separately rather than caching across them", async () => {
    // The memo is keyed on the request object, so this must NOT collapse into a
    // single authentication — that would reintroduce #182, where a stateless
    // server authenticated `initialize` and then trusted everything after it.
    const port = await getRandomPort();
    let calls = 0;

    const server = new FastMCP<TestAuth>({
      authenticate: async () => {
        calls += 1;

        return { userId: "test-user" };
      },
      name: "authenticate-per-request",
      version: "1.0.0",
    });

    server.addTool({
      description: "returns pong",
      execute: async () => "pong",
      name: "ping",
      parameters: z.object({}),
    });

    await server.start({
      httpStream: { port, stateless: true },
      transportType: "httpStream",
    });

    try {
      await initialize(port);
      await initialize(port);
      await initialize(port);

      expect(calls).toBe(3);
    } finally {
      await server.stop();
    }
  });
});
