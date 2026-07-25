import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { type } from "arktype";
import { getRandomPort } from "get-port-please";
import { setTimeout as delay } from "timers/promises";
import * as v from "valibot";
import { describe, expect, it } from "vitest";

import { FastMCP, FastMCPSession } from "./FastMCP.js";

// The README documents Zod, ArkType and Valibot as supported parameter
// validators (all wired through the Standard Schema spec), but only Zod is
// exercised by the test suite. These tests cover the ArkType and Valibot
// paths end-to-end — JSON Schema exposure in tools/list plus runtime
// validation on tools/call — so a regression in the non-Zod validators or
// their JSON-Schema conversion can't slip through unnoticed.

const runWithTestServer = async ({
  run,
  server: providedServer,
}: {
  run: ({
    client,
    server,
    session,
  }: {
    client: Client;
    server: FastMCP;
    session: FastMCPSession;
  }) => Promise<void>;
  server?: FastMCP;
}) => {
  const port = await getRandomPort();

  const server =
    providedServer ??
    new FastMCP({
      name: "Test",
      version: "1.0.0",
    });

  await server.start({
    httpStream: {
      host: "127.0.0.1",
      port,
    },
    transportType: "httpStream",
  });

  try {
    const client = new Client(
      {
        name: "example-client",
        version: "1.0.0",
      },
      {
        capabilities: {
          roots: { listChanged: true },
          sampling: {},
        },
      },
    );

    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${port}/mcp`),
    );

    const session = await new Promise<FastMCPSession>((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(new Error("Connection timeout")),
        10000,
      );
      server.on("connect", async (event) => {
        clearTimeout(timeout);
        await event.session.waitForReady();
        resolve(event.session);
      });

      client.connect(transport).catch(reject);
    });

    await delay(100); // Small grace period
    await run({ client, server, session });
  } finally {
    await server.stop();
  }
};

describe("tool parameters via ArkType", () => {
  it("exposes the parameters as JSON Schema in tools/list", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    server.addTool({
      description: "Add two numbers",
      execute: async (args) => String(args.a + args.b),
      name: "add",
      parameters: type({ a: "number", b: "number" }),
    });

    await runWithTestServer({
      run: async ({ client }) => {
        const { tools } = await client.listTools();

        expect(tools).toHaveLength(1);
        expect(tools[0]).toMatchObject({
          inputSchema: {
            properties: {
              a: { type: "number" },
              b: { type: "number" },
            },
            required: ["a", "b"],
            type: "object",
          },
          name: "add",
        });
      },
      server,
    });
  });

  it("validates and forwards valid arguments to execute", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    server.addTool({
      description: "Add two numbers",
      execute: async (args) => String(args.a + args.b),
      name: "add",
      parameters: type({ a: "number", b: "number" }),
    });

    await runWithTestServer({
      run: async ({ client }) => {
        expect(
          await client.callTool({
            arguments: { a: 1, b: 2 },
            name: "add",
          }),
        ).toEqual({
          content: [{ text: "3", type: "text" }],
        });
      },
      server,
    });
  });

  it("rejects invalid arguments before execute runs", async () => {
    let executed = false;
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    server.addTool({
      description: "Add two numbers",
      execute: async (args) => {
        executed = true;
        return String(args.a + args.b);
      },
      name: "add",
      parameters: type({ a: "number", b: "number" }),
    });

    await runWithTestServer({
      run: async ({ client }) => {
        await expect(
          client.callTool({
            arguments: { a: "not-a-number", b: 2 },
            name: "add",
          }),
        ).rejects.toThrow();
        expect(executed).toBe(false);
      },
      server,
    });
  });
});

describe("tool parameters via Valibot", () => {
  it("exposes the parameters as JSON Schema in tools/list", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    server.addTool({
      description: "Add two numbers",
      execute: async (args) => String(args.a + args.b),
      name: "add",
      parameters: v.object({ a: v.number(), b: v.number() }),
    });

    await runWithTestServer({
      run: async ({ client }) => {
        const { tools } = await client.listTools();

        expect(tools).toHaveLength(1);
        expect(tools[0]).toMatchObject({
          inputSchema: {
            properties: {
              a: { type: "number" },
              b: { type: "number" },
            },
            required: ["a", "b"],
            type: "object",
          },
          name: "add",
        });
      },
      server,
    });
  });

  it("validates and forwards valid arguments to execute", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    server.addTool({
      description: "Add two numbers",
      execute: async (args) => String(args.a + args.b),
      name: "add",
      parameters: v.object({ a: v.number(), b: v.number() }),
    });

    await runWithTestServer({
      run: async ({ client }) => {
        expect(
          await client.callTool({
            arguments: { a: 1, b: 2 },
            name: "add",
          }),
        ).toEqual({
          content: [{ text: "3", type: "text" }],
        });
      },
      server,
    });
  });

  it("rejects invalid arguments before execute runs", async () => {
    let executed = false;
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    server.addTool({
      description: "Add two numbers",
      execute: async (args) => {
        executed = true;
        return String(args.a + args.b);
      },
      name: "add",
      parameters: v.object({ a: v.number(), b: v.number() }),
    });

    await runWithTestServer({
      run: async ({ client }) => {
        await expect(
          client.callTool({
            arguments: { a: "not-a-number", b: 2 },
            name: "add",
          }),
        ).rejects.toThrow();
        expect(executed).toBe(false);
      },
      server,
    });
  });

  it("handles optional parameters", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    server.addTool({
      description: "Greet someone",
      execute: async (args) => `Hello, ${args.name ?? "world"}`,
      name: "greet",
      parameters: v.object({ name: v.optional(v.string()) }),
    });

    await runWithTestServer({
      run: async ({ client }) => {
        expect(await client.callTool({ arguments: {}, name: "greet" })).toEqual(
          {
            content: [{ text: "Hello, world", type: "text" }],
          },
        );
        expect(
          await client.callTool({
            arguments: { name: "Ada" },
            name: "greet",
          }),
        ).toEqual({
          content: [{ text: "Hello, Ada", type: "text" }],
        });
      },
      server,
    });
  });
});
