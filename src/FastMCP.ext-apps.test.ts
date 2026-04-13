/**
 * Tests for MCP ext-apps _meta field support (issue #229)
 *
 * These tests verify that the _meta field is properly passed through
 * in tool listings, enabling MCP ext-apps interactive UI components.
 *
 * @see https://github.com/punkpeye/fastmcp/issues/229
 * @see https://modelcontextprotocol.github.io/ext-apps/
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { getRandomPort } from "get-port-please";
import { expect, test } from "vitest";
import { z } from "zod";

import { FastMCP, FastMCPSession } from "./FastMCP.js";

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

  try {
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

    const transport = new SSEClientTransport(
      new URL(`http://localhost:${port}/sse`),
    );

    const session = await new Promise<FastMCPSession>((resolve) => {
      server.on("connect", async (event) => {
        await event.session.waitForReady();
        resolve(event.session);
      });

      client.connect(transport);
    });

    await run({ client, server, session });
  } finally {
    await server.stop();
  }

  return port;
};

test("includes _meta.ui.resourceUri in tool listing", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      const result = await client.listTools();
      expect(result.tools).toHaveLength(1);
      expect(result.tools[0]).toMatchObject({
        _meta: {
          ui: {
            resourceUri: "ui://greet-user/app.html",
          },
        },
        description: "Greet a user with interactive UI",
        name: "greet-user",
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addTool({
        _meta: {
          ui: {
            resourceUri: "ui://greet-user/app.html",
          },
        },
        description: "Greet a user with interactive UI",
        execute: async (args) => {
          return `Hello, ${args.name}!`;
        },
        name: "greet-user",
        parameters: z.object({
          name: z.string(),
        }),
      });

      return server;
    },
  });
});

test("tool without _meta works correctly", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      const result = await client.listTools();
      expect(result.tools).toHaveLength(1);
      expect(result.tools[0]).toMatchObject({
        description: "Add two numbers",
        name: "add",
      });
      // _meta should not be present
      expect(result.tools[0]).not.toHaveProperty("_meta");
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addTool({
        description: "Add two numbers",
        execute: async (args) => {
          return String(args.a + args.b);
        },
        name: "add",
        parameters: z.object({
          a: z.number(),
          b: z.number(),
        }),
      });

      return server;
    },
  });
});

test("preserves arbitrary _meta fields", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      const result = await client.listTools();
      expect(result.tools).toHaveLength(1);
      expect(result.tools[0]._meta).toEqual({
        customField: "custom-value",
        nested: {
          deep: true,
        },
        ui: {
          resourceUri: "ui://custom-tool/app.html",
        },
        version: 2,
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addTool({
        _meta: {
          customField: "custom-value",
          nested: {
            deep: true,
          },
          ui: {
            resourceUri: "ui://custom-tool/app.html",
          },
          version: 2,
        },
        description: "Tool with custom metadata",
        execute: async () => {
          return "result";
        },
        name: "custom-tool",
      });

      return server;
    },
  });
});

test("multiple tools with and without _meta", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      const result = await client.listTools();
      expect(result.tools).toHaveLength(3);

      // Tool with _meta
      const toolWithMeta = result.tools.find((t) => t.name === "tool-with-ui");
      expect(toolWithMeta?._meta).toEqual({
        ui: { resourceUri: "ui://tool-with-ui/app.html" },
      });

      // Tool without _meta
      const toolWithoutMeta = result.tools.find(
        (t) => t.name === "tool-without-ui",
      );
      expect(toolWithoutMeta).not.toHaveProperty("_meta");

      // Another tool with different _meta
      const anotherTool = result.tools.find(
        (t) => t.name === "another-ui-tool",
      );
      expect(anotherTool?._meta).toEqual({
        category: "dashboard",
        ui: { resourceUri: "ui://another/dashboard.html" },
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addTool({
        _meta: {
          ui: { resourceUri: "ui://tool-with-ui/app.html" },
        },
        description: "Tool with UI",
        execute: async () => "result",
        name: "tool-with-ui",
      });

      server.addTool({
        description: "Tool without UI",
        execute: async () => "result",
        name: "tool-without-ui",
      });

      server.addTool({
        _meta: {
          category: "dashboard",
          ui: { resourceUri: "ui://another/dashboard.html" },
        },
        description: "Another tool with UI",
        execute: async () => "result",
        name: "another-ui-tool",
      });

      return server;
    },
  });
});
