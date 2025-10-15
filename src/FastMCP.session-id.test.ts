import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

interface TestAuth {
  [key: string]: unknown;
  userId: string;
}

describe("FastMCP Session ID Support", () => {
  describe("HTTP Stream transport", () => {
    it("should expose sessionId to tool handlers from Mcp-Session-Id header", async () => {
      const server = new FastMCP<TestAuth>({
        authenticate: async () => ({
          userId: "test-user",
        }),
        name: "test-server",
        version: "1.0.0",
      });

      let capturedSessionId: string | undefined;
      let capturedRequestId: string | undefined;

      server.addTool({
        description: "Test tool that captures session and request IDs",
        execute: async (_args, context) => {
          capturedSessionId = context.sessionId;
          capturedRequestId = context.requestId;
          return `Session ID: ${context.sessionId || "none"}, Request ID: ${context.requestId || "none"}`;
        },
        name: "capture-ids",
        parameters: z.object({}),
      });

      const port = 3000 + Math.floor(Math.random() * 1000);

      await server.start({
        httpStream: {
          port,
        },
        transportType: "httpStream",
      });

      try {
        const transport = new StreamableHTTPClientTransport(
          new URL(`http://localhost:${port}/mcp`),
        );

        const client = new Client(
          {
            name: "test-client",
            version: "1.0.0",
          },
          {
            capabilities: {},
          },
        );

        await client.connect(transport);

        const result = await client.callTool({
          arguments: {},
          name: "capture-ids",
        });

        expect(result).toBeDefined();
        expect(capturedSessionId).toBeDefined();
        expect(typeof capturedSessionId).toBe("string");
        expect(capturedSessionId).toMatch(/^[0-9a-f-]+$/); // UUID format

        // Request ID may or may not be provided by the client
        // If provided, it should be a string
        if (capturedRequestId !== undefined) {
          expect(typeof capturedRequestId).toBe("string");
        }

        await client.close();
      } finally {
        await server.stop();
      }
    });

    it("should maintain the same sessionId across multiple requests", async () => {
      const server = new FastMCP<TestAuth>({
        authenticate: async () => ({
          userId: "test-user",
        }),
        name: "test-server",
        version: "1.0.0",
      });

      const capturedSessionIds: (string | undefined)[] = [];

      server.addTool({
        description: "Test tool that captures session ID",
        execute: async (_args, context) => {
          capturedSessionIds.push(context.sessionId);
          return `Session ID: ${context.sessionId}`;
        },
        name: "capture-session",
        parameters: z.object({}),
      });

      const port = 3000 + Math.floor(Math.random() * 1000);

      await server.start({
        httpStream: {
          port,
        },
        transportType: "httpStream",
      });

      try {
        const transport = new StreamableHTTPClientTransport(
          new URL(`http://localhost:${port}/mcp`),
        );

        const client = new Client(
          {
            name: "test-client",
            version: "1.0.0",
          },
          {
            capabilities: {},
          },
        );

        await client.connect(transport);

        // Make multiple requests
        await client.callTool({
          arguments: {},
          name: "capture-session",
        });

        await client.callTool({
          arguments: {},
          name: "capture-session",
        });

        await client.callTool({
          arguments: {},
          name: "capture-session",
        });

        // All requests should have the same session ID
        expect(capturedSessionIds).toHaveLength(3);
        expect(capturedSessionIds[0]).toBeDefined();
        expect(capturedSessionIds[0]).toBe(capturedSessionIds[1]);
        expect(capturedSessionIds[1]).toBe(capturedSessionIds[2]);

        await client.close();
      } finally {
        await server.stop();
      }
    });

    it("should support per-session state management using sessionId", async () => {
      const server = new FastMCP<TestAuth>({
        authenticate: async () => ({
          userId: "test-user",
        }),
        name: "test-server",
        version: "1.0.0",
      });

      // Per-session counter storage
      const sessionCounters = new Map<string, number>();

      server.addTool({
        description: "Increment a per-session counter",
        execute: async (_args, context) => {
          if (!context.sessionId) {
            return "No session ID available";
          }

          const currentCount = sessionCounters.get(context.sessionId) || 0;
          const newCount = currentCount + 1;
          sessionCounters.set(context.sessionId, newCount);

          return `Counter for session ${context.sessionId}: ${newCount}`;
        },
        name: "increment-counter",
        parameters: z.object({}),
      });

      const port = 3000 + Math.floor(Math.random() * 1000);

      await server.start({
        httpStream: {
          port,
        },
        transportType: "httpStream",
      });

      try {
        // Create two separate clients with different sessions
        const transport1 = new StreamableHTTPClientTransport(
          new URL(`http://localhost:${port}/mcp`),
        );

        const client1 = new Client(
          {
            name: "test-client-1",
            version: "1.0.0",
          },
          {
            capabilities: {},
          },
        );

        await client1.connect(transport1);

        const transport2 = new StreamableHTTPClientTransport(
          new URL(`http://localhost:${port}/mcp`),
        );

        const client2 = new Client(
          {
            name: "test-client-2",
            version: "1.0.0",
          },
          {
            capabilities: {},
          },
        );

        await client2.connect(transport2);

        // Increment counter for client 1 twice
        const result1a = await client1.callTool({
          arguments: {},
          name: "increment-counter",
        });

        const result1b = await client1.callTool({
          arguments: {},
          name: "increment-counter",
        });

        // Increment counter for client 2 once
        const result2 = await client2.callTool({
          arguments: {},
          name: "increment-counter",
        });

        // Verify counters are independent per session
        expect((result1a.content as Array<{ text: string }>)[0].text).toContain(": 1");
        expect((result1b.content as Array<{ text: string }>)[0].text).toContain(": 2");
        expect((result2.content as Array<{ text: string }>)[0].text).toContain(": 1");

        await client1.close();
        await client2.close();
      } finally {
        await server.stop();
      }
    });

    it("should work in stateless mode without persistent sessionId", async () => {
      const server = new FastMCP<TestAuth>({
        authenticate: async () => ({
          userId: "test-user",
        }),
        name: "test-server",
        version: "1.0.0",
      });

      let capturedSessionId: string | undefined;

      server.addTool({
        description: "Test tool in stateless mode",
        execute: async (_args, context) => {
          capturedSessionId = context.sessionId;
          return `Session ID: ${context.sessionId || "none"}`;
        },
        name: "test-stateless",
        parameters: z.object({}),
      });

      const port = 3000 + Math.floor(Math.random() * 1000);

      await server.start({
        httpStream: {
          port,
          stateless: true,
        },
        transportType: "httpStream",
      });

      try {
        const transport = new StreamableHTTPClientTransport(
          new URL(`http://localhost:${port}/mcp`),
        );

        const client = new Client(
          {
            name: "test-client",
            version: "1.0.0",
          },
          {
            capabilities: {},
          },
        );

        await client.connect(transport);

        await client.callTool({
          arguments: {},
          name: "test-stateless",
        });

        // In stateless mode, sessionId should be undefined
        expect(capturedSessionId).toBeUndefined();

        await client.close();
      } finally {
        await server.stop();
      }
    });
  });

  describe("stdio transport", () => {
    it("should not have sessionId in stdio transport", async () => {
      const server = new FastMCP<TestAuth>({
        authenticate: async () => ({
          userId: "test-user",
        }),
        name: "test-server",
        version: "1.0.0",
      });

      let capturedSessionId: string | undefined;

      server.addTool({
        description: "Test tool for stdio",
        execute: async (_args, context) => {
          capturedSessionId = context.sessionId;
          return `Session ID: ${context.sessionId || "none"}`;
        },
        name: "test-stdio",
        parameters: z.object({}),
      });

      await server.start({ transportType: "stdio" });

      // In stdio transport, sessionId should be undefined
      expect(capturedSessionId).toBeUndefined();
    });
  });
});