import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Ajv } from "ajv";
import { expect, test } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

const listInputSchema = async (parameters: z.ZodType) => {
  const server = new FastMCP({ name: "Labels", version: "1.0.0" });
  server.addTool({
    execute: async (args) => JSON.stringify(args),
    name: "setLabels",
    parameters,
  });

  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "labels-client", version: "1.0.0" });

  try {
    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);
    const { tools } = await client.listTools();
    return tools[0].inputSchema;
  } finally {
    await client.close();
    await server.stop();
  }
};

const acceptsArguments = (schema: object, args: unknown) =>
  new Ajv({ strict: false }).validate(schema, args);

test.each([
  {
    args: { labels: { environment: "staging", team: "infra" } },
    name: "a record",
    parameters: z.object({ labels: z.record(z.string(), z.string()) }),
  },
  {
    args: { labels: { environment: "staging", team: "infra" } },
    name: "an empty object with a typed catchall",
    parameters: z.object({ labels: z.object({}).catchall(z.string()) }),
  },
])(
  "advertises $name argument that accepts the keys execute receives",
  async ({ args, parameters }) => {
    const schema = await listInputSchema(parameters);

    expect(acceptsArguments(schema, args)).toBe(true);
    expect(acceptsArguments(schema, { labels: { team: 42 } })).toBe(false);
    expect(acceptsArguments(schema, { ...args, extra: true })).toBe(false);
  },
);

test("keeps objects with declared properties closed", async () => {
  const schema = await listInputSchema(
    z.object({
      owner: z.looseObject({ name: z.string() }),
      target: z.object({ id: z.string() }).catchall(z.string()),
    }),
  );

  expect(schema.additionalProperties).toBe(false);
  expect(schema.properties?.owner).toMatchObject({
    additionalProperties: false,
  });
  expect(schema.properties?.target).toMatchObject({
    additionalProperties: false,
  });
});
