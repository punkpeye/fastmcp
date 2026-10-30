import type { StandardSchemaV1 } from "@standard-schema/spec";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { type } from "arktype";
import { setTimeout as delay } from "timers/promises";
import * as v from "valibot";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { FastMCP, FastMCPSession } from "./FastMCP.js";
import { getTestPort } from "./getTestPort.js";

// The README documents Zod, ArkType and Valibot as supported parameter
// validators (all wired through the Standard Schema spec), but only Zod is
// exercised by the test suite. These tests cover the ArkType and Valibot
// paths end-to-end — JSON Schema exposure in tools/list plus runtime
// validation on tools/call — so a regression in the non-Zod validators or
// their JSON-Schema conversion can't slip through unnoticed.

describe("tool schema registration", () => {
  it("rejects parameters without Standard Schema support before starting a server", () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    expect(() =>
      server.addTool({
        execute: async () => "ok",
        name: "legacy-zod",
        parameters: {} as never,
      }),
    ).toThrow(
      "Tool 'legacy-zod' parameters must implement Standard Schema. If you are using Zod, upgrade to version 3.24 or later.",
    );
  });

  it("rejects output schemas without Standard Schema support before starting a server", () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    expect(() =>
      server.addTool({
        execute: async () => ({ answer: "ok" }),
        name: "legacy-zod-output",
        outputSchema: {} as never,
      }),
    ).toThrow(
      "Tool 'legacy-zod-output' outputSchema must implement Standard Schema. If you are using Zod, upgrade to version 3.24 or later.",
    );
  });
});

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
  const port = await getTestPort();

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

describe("Standard Schema issue paths", () => {
  const schemaWithIssue = (issue: StandardSchemaV1.Issue) => {
    const schema = z.object({});
    Object.assign(schema["~standard"], {
      validate: () => ({ issues: [issue] }),
    });
    return schema;
  };

  const invalidArgumentDiagnostic = async (
    server: FastMCP,
    args: Record<string, unknown>,
  ) => {
    const client = new Client({ name: "test-client", version: "1.0.0" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();

    try {
      await Promise.all([
        server.connect(serverTransport),
        client.connect(clientTransport),
      ]);
      await client.listTools();

      return await client.callTool({ arguments: args, name: "check" }).then(
        (response) => {
          const result = CallToolResultSchema.parse(response);
          expect(result.isError).toBe(true);
          return result.content
            .filter((content) => content.type === "text")
            .map((content) => content.text)
            .join("\n");
        },
        (error: unknown) =>
          error instanceof Error ? error.message : String(error),
      );
    } finally {
      await client.close();
      await serverTransport.close();
      await server.stop();
    }
  };

  const cases: {
    args: Record<string, unknown>;
    expected: string;
    name: string;
    parameters: StandardSchemaV1;
  }[] = [
    {
      args: { user: { age: "x" } },
      expected: 'user.age: Invalid type: Expected number but received "x"',
      name: "Valibot nested fields",
      parameters: v.object({ user: v.object({ age: v.number() }) }),
    },
    {
      args: { ages: ["x"] },
      expected: 'ages.0: Invalid type: Expected number but received "x"',
      name: "Valibot array indices",
      parameters: v.object({ ages: v.array(v.number()) }),
    },
    {
      args: { user: { age: "x" } },
      expected: "user.age: Invalid input: expected number, received string",
      name: "Zod nested fields",
      parameters: z.object({ user: z.object({ age: z.number() }) }),
    },
    {
      args: { user: { age: "x" } },
      expected: "user.age: user.age must be a number (was a string)",
      name: "ArkType nested fields",
      parameters: type({ user: { age: "number" } }),
    },
    {
      args: {},
      expected: "Symbol(field): Invalid value",
      name: "symbol keys",
      parameters: schemaWithIssue({
        message: "Invalid value",
        path: [Symbol("field")],
      }),
    },
    {
      args: {},
      expected: "users.0.Symbol(field): Invalid value",
      name: "mixed primitive and object keys",
      parameters: schemaWithIssue({
        message: "Invalid value",
        path: ["users", 0, { key: Symbol("field") }],
      }),
    },
    {
      args: {},
      expected: "root: Invalid value",
      name: "missing paths",
      parameters: schemaWithIssue({ message: "Invalid value" }),
    },
    {
      args: {},
      expected: "root: Invalid value",
      name: "empty paths",
      parameters: schemaWithIssue({ message: "Invalid value", path: [] }),
    },
  ];

  it.each(cases)("formats $name", async ({ args, expected, parameters }) => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    const execute = vi.fn(async () => "ok");
    server.addTool({ execute, name: "check", parameters });

    const diagnostic = await invalidArgumentDiagnostic(server, args);

    expect(diagnostic).toContain(expected);
    expect(diagnostic).not.toContain("[object Object]");
    expect(execute).not.toHaveBeenCalled();
  });

  it("passes original Valibot issues to the custom formatter", async () => {
    const formatInvalidParamsErrorMessage = vi.fn<
      (issues: readonly StandardSchemaV1.Issue[]) => string
    >(() => "custom validation message");
    const server = new FastMCP({
      name: "Test",
      utils: { formatInvalidParamsErrorMessage },
      version: "1.0.0",
    });
    server.addTool({
      execute: async () => "ok",
      name: "check",
      parameters: v.object({ user: v.object({ age: v.number() }) }),
    });

    expect(
      await invalidArgumentDiagnostic(server, { user: { age: "x" } }),
    ).toContain("custom validation message");
    expect(formatInvalidParamsErrorMessage).toHaveBeenCalledOnce();
    expect(
      formatInvalidParamsErrorMessage.mock.calls[0][0][0].path,
    ).toMatchObject([{ key: "user" }, { key: "age" }]);
  });
});
