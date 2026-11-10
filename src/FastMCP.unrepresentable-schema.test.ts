import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import * as v from "valibot";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { FastMCP, type Logger } from "./FastMCP.js";

const createLogger = () =>
  ({
    debug: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    log: vi.fn(),
    warn: vi.fn(),
  }) satisfies Logger;

const connect = async (server: FastMCP) => {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "1.0.0" });

  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);

  return client;
};

const createServer = (logger: Logger) => {
  const server = new FastMCP({ logger, name: "Test", version: "1.0.0" });

  server.addTool({
    description: "Add two numbers",
    execute: async ({ a, b }) => String(a + b),
    name: "add",
    parameters: z.object({ a: z.number(), b: z.number() }),
  });

  return server;
};

describe("tools/list with a schema that has no JSON Schema form", () => {
  it.each([
    ["z.date()", z.object({ at: z.date() })],
    ["z.coerce.date()", z.object({ at: z.coerce.date() })],
    ["z.bigint()", z.object({ at: z.bigint() })],
    ["valibot v.date()", v.object({ at: v.date() })],
    [
      "valibot v.transform()",
      v.object({
        at: v.pipe(
          v.string(),
          v.transform((value) => value.length),
        ),
      }),
    ],
  ])(
    "lists every tool when one tool's parameters use %s",
    async (_, parameters) => {
      const logger = createLogger();
      const server = createServer(logger);

      server.addTool({
        description: "Schedule something",
        execute: async () => "scheduled",
        name: "schedule",
        parameters,
      });

      const client = await connect(server);

      try {
        const { tools } = await client.listTools();

        expect(tools.map((tool) => tool.name)).toEqual(["add", "schedule"]);
        expect(tools[0].inputSchema).toMatchObject({
          properties: { a: { type: "number" }, b: { type: "number" } },
          required: ["a", "b"],
        });
        expect(tools[1].inputSchema).toEqual({ type: "object" });
        expect(logger.warn).toHaveBeenCalledWith(
          expect.stringContaining(
            "Tool 'schedule' parameters cannot be converted to JSON Schema",
          ),
          expect.any(Error),
        );
      } finally {
        await client.close();
      }
    },
  );

  it("lists the tool without an outputSchema when the outputSchema has no JSON Schema form", async () => {
    const logger = createLogger();
    const server = createServer(logger);

    server.addTool({
      description: "Get the current time",
      execute: async () => ({ now: new Date(0) }),
      name: "now",
      outputSchema: z.object({ now: z.date() }),
    });

    const client = await connect(server);

    try {
      const { tools } = await client.listTools();

      expect(tools.map((tool) => tool.name)).toEqual(["add", "now"]);
      expect(tools[1]).not.toHaveProperty("outputSchema");
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining(
          "Tool 'now' outputSchema cannot be converted to JSON Schema",
        ),
        expect.any(Error),
      );
    } finally {
      await client.close();
    }
  });

  it("still validates and calls the tool with its own schema", async () => {
    const server = createServer(createLogger());

    server.addTool({
      description: "Echo a date",
      execute: async ({ at }) => at.toISOString(),
      name: "echoDate",
      parameters: z.object({ at: z.coerce.date() }),
    });

    const client = await connect(server);

    try {
      await client.listTools();

      expect(
        await client.callTool({
          arguments: { at: "2026-01-02T03:04:05.000Z" },
          name: "echoDate",
        }),
      ).toEqual({
        content: [{ text: "2026-01-02T03:04:05.000Z", type: "text" }],
      });

      const invalid = await client.callTool({
        arguments: { at: "not a date" },
        name: "echoDate",
      });

      expect(invalid.isError).toBe(true);
      expect(invalid.content).toEqual([
        {
          text: expect.stringContaining(
            "Tool 'echoDate' parameter validation failed",
          ),
          type: "text",
        },
      ]);
    } finally {
      await client.close();
    }
  });
});
