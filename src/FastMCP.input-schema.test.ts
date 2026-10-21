import type { StandardSchemaV1 } from "@standard-schema/spec";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Ajv } from "ajv";
import { type } from "arktype";
import { expect, test } from "vitest";
import { z } from "zod";

import { FastMCP, jsonSchemaAdapter } from "./FastMCP.js";

const listInputSchema = async (parameters: StandardSchemaV1) => {
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

test.each(
  [
    {
      args: (value: unknown) => ({ value: [value] }),
      name: "arrays",
      parameters: (value: z.ZodType) => z.object({ value: z.array(value) }),
    },
    {
      args: (value: unknown) => ({ value }),
      name: "unions",
      parameters: (value: z.ZodType) =>
        z.object({ value: z.union([value, z.string()]) }),
    },
    {
      args: (value: unknown) => ({ value: { entry: value } }),
      name: "record values",
      parameters: (value: z.ZodType) =>
        z.object({ value: z.record(z.string(), value) }),
    },
  ].flatMap(({ args, name, parameters }) =>
    [
      {
        acceptsExtra: false,
        acceptsNumberExtra: false,
        kind: "ordinary objects",
        object: z.object({ name: z.string() }),
      },
      {
        acceptsExtra: true,
        acceptsNumberExtra: true,
        kind: "explicitly loose objects",
        object: z.looseObject({ name: z.string() }),
      },
      {
        acceptsExtra: true,
        acceptsNumberExtra: false,
        kind: "objects with typed catchalls",
        object: z.object({ name: z.string() }).catchall(z.string()),
      },
    ].map(({ object, ...control }) => ({
      ...control,
      args,
      name,
      parameters: parameters(object),
    })),
  ),
)(
  "preserves $kind inside $name in input schemas",
  async ({ acceptsExtra, acceptsNumberExtra, args, parameters }) => {
    const schema = await listInputSchema(parameters);

    expect(acceptsArguments(schema, args({ name: "a" }))).toBe(true);
    expect(acceptsArguments(schema, args({ name: 42 }))).toBe(false);
    expect(
      acceptsArguments(schema, args({ extra: "allowed", name: "a" })),
    ).toBe(acceptsExtra);
    expect(acceptsArguments(schema, args({ extra: 42, name: "a" }))).toBe(
      acceptsNumberExtra,
    );
  },
);

test.each([
  {
    args: { n: "abcd" },
    expected: { n: 4 },
    fieldSchema: { type: "string" },
    name: "a transform",
    parameters: z.object({ n: z.string().transform((value) => value.length) }),
    required: ["n"],
  },
  {
    args: {},
    expected: { n: 5 },
    fieldSchema: { default: 5, type: "number" },
    name: "a default",
    parameters: z.object({ n: z.number().default(5) }),
    required: undefined,
  },
])(
  "lists and calls a tool with $name alongside a plain tool",
  async ({ args, expected, fieldSchema, parameters, required }) => {
    const server = new FastMCP({ name: "Inputs", version: "1.0.0" });
    server.addTool({
      execute: async (value) => JSON.stringify(value),
      name: "converted",
      parameters,
    });
    server.addTool({
      execute: async ({ message }) => message,
      name: "plain",
      parameters: z.object({ message: z.string() }),
    });

    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "inputs-client", version: "1.0.0" });

    try {
      await Promise.all([
        server.connect(serverTransport),
        client.connect(clientTransport),
      ]);
      const { tools } = await client.listTools();
      expect(tools.map((tool) => tool.name)).toEqual(["converted", "plain"]);
      const schema = tools[0].inputSchema;
      expect(schema.$schema).toBe("http://json-schema.org/draft-07/schema#");
      expect(schema.properties?.n).toMatchObject(fieldSchema);
      expect(schema.required).toEqual(required);
      expect(schema.additionalProperties).toBe(false);
      expect(acceptsArguments(schema, args)).toBe(true);

      const result = await client.callTool({
        arguments: args,
        name: "converted",
      });
      expect(result.isError).toBeFalsy();
      expect(result.content).toEqual([
        { text: JSON.stringify(expected), type: "text" },
      ]);
      const plainResult = await client.callTool({
        arguments: { message: "ok" },
        name: "plain",
      });
      expect(plainResult.isError).toBeFalsy();
      expect(plainResult.content).toEqual([{ text: "ok", type: "text" }]);
    } finally {
      await client.close();
      await server.stop();
    }
  },
);

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

test.each([
  { metadata: { type: "object" }, name: "a bare object" },
  {
    metadata: { additionalProperties: true, type: "object" },
    name: "an object with additionalProperties: true",
  },
])(
  "advertises a free-form argument written as $name that accepts any keys",
  async ({ metadata }) => {
    const schema = await listInputSchema(
      jsonSchemaAdapter({
        properties: { metadata, name: { type: "string" } },
        required: ["name"],
        type: "object",
      }),
    );

    expect(
      acceptsArguments(schema, { metadata: { team: "infra" }, name: "a" }),
    ).toBe(true);
    expect(acceptsArguments(schema, { extra: true, name: "a" })).toBe(false);
  },
);

test("keeps an object that declares no keys closed", async () => {
  const schema = await listInputSchema(
    jsonSchemaAdapter({
      properties: { options: { properties: {}, type: "object" } },
      type: "object",
    }),
  );

  expect(acceptsArguments(schema, { options: {} })).toBe(true);
  expect(acceptsArguments(schema, { options: { team: "infra" } })).toBe(false);
});

test.each([
  { name: "ArkType's", parameters: type({}) },
  {
    name: "a plain JSON Schema",
    parameters: jsonSchemaAdapter({ type: "object" }),
  },
])(
  "keeps $name bare top-level object closed, as a tool without arguments",
  async ({ parameters }) => {
    const schema = await listInputSchema(parameters);

    expect(schema.additionalProperties).toBe(false);
  },
);
