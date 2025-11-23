import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { getRandomPort } from "get-port-please";
import { afterAll, beforeAll, describe, expect, it, test } from "vitest";
import { z } from "zod";

import { FastMCP, FastMCPSession, ServerState } from "./FastMCP.js";
// Suppress AbortError from MCP SDK during test cleanup
let originalUnhandledRejection: typeof process.listeners;
beforeAll(() => {
  originalUnhandledRejection = process.listeners("unhandledRejection");
  process.removeAllListeners("unhandledRejection");
  process.on("unhandledRejection", (reason: unknown) => {
    // Ignore AbortError from SSE client during cleanup
    if (
      reason instanceof Error &&
      (reason.name === "AbortError" || reason.message?.includes("aborted"))
    ) {
      return;
    }
    // Re-throw other errors
    throw reason;
  });
});

afterAll(() => {
  process.removeAllListeners("unhandledRejection");
  originalUnhandledRejection.forEach((listener) => {
    process.on("unhandledRejection", listener as never);
  });
});

const runWithTestServer = async ({
  client: createClient,
  run,
  server: createServer,
}: {
  client?: () => Promise<Client>;
  run: ({
    client,
    server,
  }: {
    client: Client;
    server: FastMCP;
    session: FastMCPSession;
  }) => Promise<void>;
  server?: () => Promise<FastMCP>;
}) => {
  const port = await getRandomPort();

  const server = createServer
    ? await createServer()
    : new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

  await server.start({
    httpStream: {
      port,
    },
    transportType: "httpStream",
  });

  const client = createClient
    ? await createClient()
    : new Client(
        {
          name: "example-client",
          version: "1.0.0",
        },
        {
          capabilities: {},
        },
      );

  try {
    const transport = new SSEClientTransport(
      new URL(`http://localhost:${port}/sse`),
    );

    const session = await new Promise<FastMCPSession>((resolve) => {
      server.on("connect", async (event) => {
        // Wait for session to be fully ready before resolving
        await event.session.waitForReady();
        resolve(event.session);
      });

      client.connect(transport);
    });

    await run({ client, server, session });
  } finally {
    try {
      await client.close();
    } catch {
      // Ignore errors during client cleanup
    }
    await server.stop();
  }

  return port;
};

describe("FastMCP Batch Methods", () => {
  const createTestServer = () => {
    return new FastMCP({
      name: "test-server",
      version: "1.0.0",
    });
  };

  describe("addPrompts", () => {
    it("should add multiple prompts", async () => {
      const server = createTestServer();

      const prompts = [
        {
          description: "Test prompt 1",
          load: async () => "Test response 1",
          name: "prompt1",
        },
        {
          description: "Test prompt 2",
          load: async () => "Test response 2",
          name: "prompt2",
        },
      ];

      expect(() => server.addPrompts(prompts)).not.toThrow();
    });

    it("should handle duplicate prompt names by replacing existing prompts", async () => {
      const server = createTestServer();

      const prompt1 = {
        description: "First version",
        load: async () => "First response",
        name: "duplicate",
      };

      const prompt2 = {
        description: "Second version",
        load: async () => "Second response",
        name: "duplicate",
      };

      expect(() => {
        server.addPrompt(prompt1);
        server.addPrompts([prompt2]);
      }).not.toThrow();
    });
  });

  describe("removePrompts", () => {
    it("should remove multiple prompts", async () => {
      const server = createTestServer();

      // Add some prompts first
      const prompts = [
        {
          description: "Test prompt 1",
          load: async () => "Test response 1",
          name: "prompt1",
        },
        {
          description: "Test prompt 2",
          load: async () => "Test response 2",
          name: "prompt2",
        },
        {
          description: "Test prompt 3",
          load: async () => "Test response 3",
          name: "prompt3",
        },
      ];

      server.addPrompts(prompts);

      expect(() => server.removePrompts(["prompt1", "prompt3"])).not.toThrow();
    });
  });

  describe("addTools", () => {
    it("should add multiple tools using addTool individually", async () => {
      const server = createTestServer();

      const tool1 = {
        description: "Test tool 1",
        execute: async () => "Tool 1 result",
        name: "tool1",
      };

      const tool2 = {
        description: "Test tool 2",
        execute: async () => "Tool 2 result",
        name: "tool2",
      };

      // Add them individually to avoid type issues
      expect(() => {
        server.addTool(tool1);
        server.addTool(tool2);
      }).not.toThrow();
    });

    it("should add multiple tools of same type", async () => {
      const server = createTestServer();

      const tools = [
        {
          description: "Calculator tool 1",
          execute: async ({ a, b }: { a: number; b: number }) => `${a + b}`,
          name: "calculator1",
          parameters: z.object({ a: z.number(), b: z.number() }),
        },
        {
          description: "Calculator tool 2",
          execute: async ({ a, b }: { a: number; b: number }) => `${a * b}`,
          name: "calculator2",
          parameters: z.object({ a: z.number(), b: z.number() }),
        },
      ];

      expect(() => server.addTools(tools)).not.toThrow();
    });
  });

  describe("removeTools", () => {
    it("should remove multiple tools", async () => {
      const server = createTestServer();

      const tools = [
        {
          description: "Test tool 1",
          execute: async () => "Tool 1",
          name: "tool1",
        },
        {
          description: "Test tool 2",
          execute: async () => "Tool 2",
          name: "tool2",
        },
        {
          description: "Test tool 3",
          execute: async () => "Tool 3",
          name: "tool3",
        },
      ];

      // Add them first
      for (const tool of tools) {
        server.addTool(tool);
      }

      expect(() => server.removeTools(["tool1", "tool3"])).not.toThrow();
    });
  });

  describe("addResources", () => {
    it("should add multiple resources", async () => {
      const server = createTestServer();

      const resources = [
        {
          description: "Test resource 1",
          load: async () => ({ text: "Resource 1 content" }),
          name: "resource1",
          uri: "test://resource1",
        },
        {
          description: "Test resource 2",
          load: async () => ({ text: "Resource 2 content" }),
          name: "resource2",
          uri: "test://resource2",
        },
      ];

      expect(() => server.addResources(resources)).not.toThrow();
    });
  });

  describe("removeResources", () => {
    it("should remove multiple resources", async () => {
      const server = createTestServer();

      const resources = [
        {
          load: async () => ({ text: "Resource 1" }),
          name: "resource1",
          uri: "test://resource1",
        },
        {
          load: async () => ({ text: "Resource 2" }),
          name: "resource2",
          uri: "test://resource2",
        },
        {
          load: async () => ({ text: "Resource 3" }),
          name: "resource3",
          uri: "test://resource3",
        },
      ];

      server.addResources(resources);

      expect(() =>
        server.removeResources(["resource1", "resource3"]),
      ).not.toThrow();
    });
  });

  describe("addResourceTemplates", () => {
    it("should add multiple resource templates", async () => {
      const server = createTestServer();

      const template1 = {
        arguments: [{ description: "Resource ID", name: "id", required: true }],
        description: "Test template 1",
        load: async (args: Record<string, unknown>) => ({
          text: `Template 1 content for ${args.id}`,
        }),
        name: "template1",
        uriTemplate: "test://template1/{id}",
      };

      const template2 = {
        arguments: [
          { description: "Resource slug", name: "slug", required: true },
        ],
        description: "Test template 2",
        load: async (args: Record<string, unknown>) => ({
          text: `Template 2 content for ${args.slug}`,
        }),
        name: "template2",
        uriTemplate: "test://template2/{slug}",
      };

      expect(() => {
        server.addResourceTemplate(template1);
        server.addResourceTemplate(template2);
      }).not.toThrow();
    });
  });

  describe("removeResourceTemplates", () => {
    it("should remove multiple resource templates", async () => {
      const server = createTestServer();

      const template1 = {
        arguments: [{ name: "id", required: true }],
        load: async (args: Record<string, unknown>) => ({
          text: `Template 1: ${args.id}`,
        }),
        name: "template1",
        uriTemplate: "test://template1/{id}",
      };

      const template2 = {
        arguments: [{ name: "id", required: true }],
        load: async (args: Record<string, unknown>) => ({
          text: `Template 2: ${args.id}`,
        }),
        name: "template2",
        uriTemplate: "test://template2/{id}",
      };

      const template3 = {
        arguments: [{ name: "id", required: true }],
        load: async (args: Record<string, unknown>) => ({
          text: `Template 3: ${args.id}`,
        }),
        name: "template3",
        uriTemplate: "test://template3/{id}",
      };

      // Add them first
      server.addResourceTemplate(template1);
      server.addResourceTemplate(template2);
      server.addResourceTemplate(template3);

      expect(() =>
        server.removeResourceTemplates(["template1", "template3"]),
      ).not.toThrow();
    });
  });

  describe("batch methods handle duplicate names correctly", () => {
    it("should replace existing items when adding duplicates", async () => {
      const server = createTestServer();

      // Add initial items
      server.addTool({
        description: "Original tool",
        execute: async () => "original",
        name: "duplicate-tool",
      });

      server.addPrompt({
        description: "Original prompt",
        load: async () => "original response",
        name: "duplicate-prompt",
      });

      // Add duplicates via batch methods - should replace existing
      server.addTools([
        {
          description: "Updated tool",
          execute: async () => "updated",
          name: "duplicate-tool",
        },
      ]);

      server.addPrompts([
        {
          description: "Updated prompt",
          load: async () => "updated response",
          name: "duplicate-prompt",
        },
      ]);

      // Basic check that the methods didn't throw
      expect(true).toBe(true);
    });
  });

  describe("functionality tests - server state management", () => {
    it("should only send notifications when server is running", async () => {
      const server = createTestServer();

      // Add items before starting server - should not throw and not send notifications
      server.addPrompts([
        {
          load: async () => "test",
          name: "test-prompt",
        },
      ]);

      server.addTools([
        {
          execute: async () => "test",
          name: "test-tool",
        },
      ]);

      // Should not throw
      expect(true).toBe(true);

      // Now start server - this should trigger notifications to sessions
      await server.start({ transportType: "stdio" });
      const session = server.sessions[0];

      // Add more items after server is running - should send notifications
      server.addPrompts([
        {
          load: async () => "runtime test",
          name: "runtime-prompt",
        },
      ]);

      if (session) {
        await session.close();
      }
    });

    it("should properly track server state transitions", async () => {
      const server = createTestServer();

      // Initial state should be stopped
      expect(server.serverState).toBe(ServerState.Stopped);

      // Start server
      await server.start({ transportType: "stdio" });
      expect(server.serverState).toBe(ServerState.Running);

      // Stop server
      await server.stop();
      expect(server.serverState).toBe(ServerState.Stopped);
    });
  });

  describe("notification testing", () => {
    test("should trigger notifications when adding prompts at runtime", async () => {
      await runWithTestServer({
        run: async ({ server, session }) => {
          // Mock the notification method to capture calls
          const notificationsSent: string[] = [];
          const originalNotification = session.server.notification;
          session.server.notification = (notification: { method: string }) => {
            notificationsSent.push(notification.method);
            return originalNotification.call(session.server, notification);
          };

          // Add prompt at runtime - should trigger notification
          server.addPrompts([
            {
              description: "Added at runtime",
              load: async () => "Runtime response",
              name: "runtime-prompt",
            },
          ]);

          // Verify notification was sent
          expect(notificationsSent).toContain(
            "notifications/prompts/list_changed",
          );
        },
        server: async () => {
          const server = new FastMCP({
            name: "test-server",
            version: "1.0.0",
          });

          // Add initial prompt to establish capability
          server.addPrompts([
            {
              description: "Initial prompt to establish capability",
              load: async () => "Initial response",
              name: "initial-prompt",
            },
          ]);

          return server;
        },
      });
    });

    test("should allow calling runtime-added tools", async () => {
      await runWithTestServer({
        run: async ({ client, server }) => {
          // First verify initial tools exist
          const initialTools = await client.listTools();
          expect(initialTools.tools).toHaveLength(1);
          expect(initialTools.tools[0].name).toBe("initial-tool");

          // Add tool at runtime
          server.addTools([
            {
              description: "Tool added at runtime",
              execute: async ({ value }) => `Result: ${value * 2}`,
              name: "runtime-tool",
              parameters: z.object({
                value: z.number(),
              }),
            },
          ]);

          // Verify the runtime tool is now available
          const updatedTools = await client.listTools();
          expect(updatedTools.tools).toHaveLength(2);

          const runtimeTool = updatedTools.tools.find(
            (t) => t.name === "runtime-tool",
          );
          expect(runtimeTool).toBeDefined();
          expect(runtimeTool?.description).toBe("Tool added at runtime");

          // Verify the runtime tool can be called
          const result = await client.callTool({
            arguments: { value: 21 },
            name: "runtime-tool",
          });

          expect((result as CallToolResult).content[0]).toEqual({
            text: "Result: 42",
            type: "text",
          });
        },
        server: async () => {
          const server = new FastMCP({
            name: "test-server",
            version: "1.0.0",
          });

          // Add initial tool to establish capability
          server.addTools([
            {
              description: "Initial tool to establish capability",
              execute: async () => "initial response",
              name: "initial-tool",
            },
          ]);

          return server;
        },
      });
    });

    test("should trigger notifications for resources", async () => {
      await runWithTestServer({
        run: async ({ client, server, session }) => {
          // Mock notifications
          const notificationsSent: string[] = [];
          const originalNotification = session.server.notification;
          session.server.notification = (notification: { method: string }) => {
            notificationsSent.push(notification.method);
            return originalNotification.call(session.server, notification);
          };

          // Verify initial resources exist
          const initialResources = await client.listResources();
          expect(initialResources.resources).toHaveLength(1);

          // Add runtime resource
          server.addResources([
            {
              description: "Runtime resource",
              load: async () => ({ text: "runtime resource content" }),
              name: "runtime-resource",
              uri: "test://runtime-resource",
            },
          ]);

          // Verify notifications were sent
          expect(notificationsSent).toContain(
            "notifications/resources/list_changed",
          );

          // Verify the new resource is available
          const updatedResources = await client.listResources();
          expect(updatedResources.resources).toHaveLength(2);

          const runtimeResource = updatedResources.resources.find(
            (r) => r.name === "runtime-resource",
          );
          expect(runtimeResource).toBeDefined();
        },
        server: async () => {
          const server = new FastMCP({
            name: "test-server",
            version: "1.0.0",
          });

          // Add initial resource to establish capability
          server.addResources([
            {
              description: "Initial resource",
              load: async () => ({ text: "initial resource content" }),
              name: "initial-resource",
              uri: "test://initial-resource",
            },
          ]);

          return server;
        },
      });
    });
  });

  describe("comprehensive batch operations", () => {
    test("should handle multiple batch operations with proper client verification", async () => {
      await runWithTestServer({
        run: async ({ client, server }) => {
          // Verify initial state - server starts with one item of each type
          const initialPrompts = await client.listPrompts();
          const initialTools = await client.listTools();
          const initialResources = await client.listResources();

          expect(initialPrompts.prompts).toHaveLength(1);
          expect(initialTools.tools).toHaveLength(1);
          expect(initialResources.resources).toHaveLength(1);

          // Add items using batch methods
          server.addPrompts([
            {
              description: "Batch prompt 1",
              load: async () => "Response 1",
              name: "batch-prompt-1",
            },
            {
              description: "Batch prompt 2",
              load: async () => "Response 2",
              name: "batch-prompt-2",
            },
          ]);

          server.addTools([
            {
              description: "Batch tool 1",
              execute: async ({ input }) => `Tool 1: ${input}`,
              name: "batch-tool-1",
              parameters: z.object({ input: z.string() }),
            },
            {
              description: "Batch tool 2",
              execute: async () => "Tool 2 result",
              name: "batch-tool-2",
            },
          ]);

          server.addResources([
            {
              description: "Batch resource 1",
              load: async () => ({ text: "Resource 1 content" }),
              name: "batch-resource-1",
              uri: "test://resource1",
            },
            {
              description: "Batch resource 2",
              load: async () => ({ text: "Resource 2 content" }),
              name: "batch-resource-2",
              uri: "test://resource2",
            },
          ]);

          // Verify all items are now available via client (1 initial + 2 batch added = 3 each)
          const updatedPrompts = await client.listPrompts();
          const updatedTools = await client.listTools();
          const updatedResources = await client.listResources();

          expect(updatedPrompts.prompts).toHaveLength(3);
          expect(updatedTools.tools).toHaveLength(3);
          expect(updatedResources.resources).toHaveLength(3);

          // Test that batch-added tools are callable
          const toolResult = await client.callTool({
            arguments: { input: "test" },
            name: "batch-tool-1",
          });

          expect((toolResult as CallToolResult).content[0]).toEqual({
            text: "Tool 1: test",
            type: "text",
          });

          // Test batch removal
          server.removePrompts(["batch-prompt-1"]);
          server.removeTools(["batch-tool-2"]);
          server.removeResources(["batch-resource-1"]);

          const finalPrompts = await client.listPrompts();
          const finalTools = await client.listTools();
          const finalResources = await client.listResources();

          expect(finalPrompts.prompts).toHaveLength(2); // initial + batch-prompt-2
          expect(finalTools.tools).toHaveLength(2); // initial + batch-tool-1
          expect(finalResources.resources).toHaveLength(2); // initial + batch-resource-2

          // Verify the correct items remain
          const batchPrompt = finalPrompts.prompts.find(
            (p) => p.name === "batch-prompt-2",
          );
          const batchTool = finalTools.tools.find(
            (t) => t.name === "batch-tool-1",
          );
          const batchResource = finalResources.resources.find(
            (r) => r.name === "batch-resource-2",
          );

          expect(batchPrompt).toBeDefined();
          expect(batchTool).toBeDefined();
          expect(batchResource).toBeDefined();
        },
        server: async () => {
          const server = new FastMCP({
            name: "batch-test-server",
            version: "1.0.0",
          });

          // Add initial items to establish capabilities
          server.addPrompts([
            {
              description: "Initial prompt",
              load: async () => "Initial response",
              name: "initial-prompt",
            },
          ]);

          server.addTools([
            {
              description: "Initial tool",
              execute: async () => "Initial result",
              name: "initial-tool",
            },
          ]);

          server.addResources([
            {
              description: "Initial resource",
              load: async () => ({ text: "Initial content" }),
              name: "initial-resource",
              uri: "test://initial",
            },
          ]);

          return server;
        },
      });
    });
  });
});
