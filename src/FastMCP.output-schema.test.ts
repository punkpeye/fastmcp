import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { expect, test } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

const callDiscoveredTool = async (outputSchema: z.ZodType, output: unknown) => {
  const server = new FastMCP({ name: "Inventory", version: "1.0.0" });
  server.addTool({
    execute: async () => output,
    name: "getInventory",
    outputSchema,
  });

  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "inventory-client", version: "1.0.0" });

  try {
    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);
    // Discovery caches the advertised output schema for client-side validation.
    const { tools } = await client.listTools();
    const result = await client.callTool({ name: "getInventory" });
    return { result, schema: tools[0].outputSchema };
  } finally {
    await client.close();
    await server.stop();
  }
};

test.each([
  {
    name: "a record",
    output: { warehouse_a: 12, warehouse_b: 8 },
    schema: z.record(z.string(), z.number()),
  },
  {
    name: "a nested record",
    output: { stock: { warehouse_a: 12, warehouse_b: 8 } },
    schema: z.object({ stock: z.record(z.string(), z.number()) }),
  },
  {
    name: "a loose object",
    output: { product: "sprocket", warehouse_a: 12 },
    schema: z.looseObject({ product: z.string() }),
  },
  {
    name: "an object with a typed catchall",
    output: { product: "sprocket", warehouse_a: 12 },
    schema: z.object({ product: z.string() }).catchall(z.number()),
  },
])("accepts $name output after tools/list", async ({ output, schema }) => {
  const { result } = await callDiscoveredTool(schema, output);

  expect(result.isError).toBeFalsy();
  expect(result.structuredContent).toEqual(output);
});

test("keeps strict output objects closed after tools/list", async () => {
  const { result, schema } = await callDiscoveredTool(
    z.strictObject({ warehouse_a: z.number() }),
    { warehouse_a: 12 },
  );

  expect(schema?.additionalProperties).toBe(false);
  expect(result.isError).toBeFalsy();
  expect(result.structuredContent).toEqual({ warehouse_a: 12 });
});

test.each([
  {
    name: "an invalid record value",
    output: { warehouse_a: "twelve" },
    schema: z.record(z.string(), z.number()),
  },
  {
    name: "an extra property in a strict object",
    output: { warehouse_a: 12, warehouse_b: 8 },
    schema: z.strictObject({ warehouse_a: z.number() }),
  },
])("rejects $name after tools/list", async ({ output, schema }) => {
  const { result } = await callDiscoveredTool(schema, output);

  expect(result.isError).toBe(true);
  expect(result.content).toEqual([
    {
      text: expect.stringContaining("structured output validation failed"),
      type: "text",
    },
  ]);
});

test.each([
  { name: "a string", output: "12 in stock" },
  { name: "undefined", output: undefined },
  {
    name: "content without structuredContent",
    output: { content: [{ text: "12 in stock", type: "text" }] },
  },
])("returns a tool error for $name after tools/list", async ({ output }) => {
  const { result } = await callDiscoveredTool(
    z.object({ warehouse_a: z.number() }),
    output,
  );

  expect(result).toEqual({
    content: [
      {
        text: "Tool 'getInventory' returned no structured content. Please return a value that matches the tool's outputSchema.",
        type: "text",
      },
    ],
    isError: true,
  });
});

test("keeps a tool's own error result after tools/list", async () => {
  const output = {
    content: [{ text: "warehouse offline", type: "text" }],
    isError: true,
  };
  const { result } = await callDiscoveredTool(
    z.object({ warehouse_a: z.number() }),
    output,
  );

  expect(result).toEqual(output);
});
