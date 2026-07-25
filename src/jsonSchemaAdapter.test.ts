import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { getRandomPort } from "get-port-please";
import { expect, test, vi } from "vitest";
import { toJsonSchema } from "xsschema";

import { FastMCP } from "./FastMCP.js";
import { jsonSchemaAdapter } from "./jsonSchemaAdapter.js";

const personSchema = {
  properties: {
    age: { type: "number" },
    name: { type: "string" },
  },
  required: ["name"],
  type: "object",
};

test("accepts input matching the schema", async () => {
  const schema = jsonSchemaAdapter({ ...personSchema });

  const result = await schema["~standard"].validate({ age: 30, name: "Alice" });

  expect(result.issues).toBeUndefined();
  expect(result.issues === undefined && result.value).toEqual({
    age: 30,
    name: "Alice",
  });
});

test("reports issues for input that does not match", async () => {
  const schema = jsonSchemaAdapter({ ...personSchema });

  const result = await schema["~standard"].validate({ age: "not a number" });

  expect(result.issues?.length).toBeGreaterThan(0);
});

test("points a missing-property issue at the missing field", async () => {
  const schema = jsonSchemaAdapter({ ...personSchema });

  const result = await schema["~standard"].validate({ age: 30 });

  // AJV reports `required` against the parent object, so without fixing up the
  // path the issue would point at the root and say nothing about which field.
  expect(result.issues?.map((issue) => issue.path)).toContainEqual(["name"]);
});

test("reports paths into nested objects and arrays", async () => {
  const schema = jsonSchemaAdapter({
    properties: {
      contacts: {
        items: {
          properties: { email: { type: "string" } },
          required: ["email"],
          type: "object",
        },
        type: "array",
      },
    },
    required: ["contacts"],
    type: "object",
  });

  const result = await schema["~standard"].validate({
    contacts: [{ email: "a@example.com" }, { email: 42 }],
  });

  // Array indices come back as numbers, not as the strings AJV puts in its
  // JSON Pointer.
  expect(result.issues?.map((issue) => issue.path)).toContainEqual([
    "contacts",
    1,
    "email",
  ]);
});

test("validates nested objects", async () => {
  const schema = jsonSchemaAdapter({
    properties: {
      address: {
        properties: {
          street: { type: "string" },
          zip: { type: "string" },
        },
        required: ["street"],
        type: "object",
      },
    },
    required: ["address"],
    type: "object",
  });

  const valid = await schema["~standard"].validate({
    address: { street: "123 Main St", zip: "12345" },
  });
  expect(valid.issues).toBeUndefined();

  const invalid = await schema["~standard"].validate({
    address: { zip: "12345" },
  });
  expect(invalid.issues?.length).toBeGreaterThan(0);
});

test("enforces format keywords when ajv-formats is installed", async () => {
  const schema = jsonSchemaAdapter({
    properties: { email: { format: "email", type: "string" } },
    required: ["email"],
    type: "object",
  });

  const valid = await schema["~standard"].validate({
    email: "user@example.com",
  });
  expect(valid.issues).toBeUndefined();

  const invalid = await schema["~standard"].validate({ email: "not-an-email" });
  expect(invalid.issues?.length).toBeGreaterThan(0);
});

test("compiles the schema once across many validations", async () => {
  let compileCount = 0;

  const counted = new Proxy({ ...personSchema } as Record<string, unknown>, {
    ownKeys(target) {
      // AJV reads the schema's keys while compiling, so this counts
      // compilations without reaching into AJV internals.
      compileCount++;
      return Reflect.ownKeys(target);
    },
  });

  const schema = jsonSchemaAdapter(
    counted as unknown as { type: string } & Record<string, unknown>,
  );

  await Promise.all(
    Array.from({ length: 5 }, () =>
      schema["~standard"].validate({ name: "Alice" }),
    ),
  );
  await schema["~standard"].validate({ name: "Bob" });

  const afterFirstBatch = compileCount;

  await schema["~standard"].validate({ name: "Carol" });

  // Whatever AJV reads during compilation, it must not read it again.
  expect(compileCount).toBe(afterFirstBatch);
  expect(compileCount).toBeGreaterThan(0);
});

test("converts to JSON Schema without a vendor-specific converter", async () => {
  const schema = jsonSchemaAdapter({ ...personSchema });

  // xsschema has no "json-schema" vendor; it has to take the schema straight
  // off `~standard.jsonSchema` instead. This is what lets the adapter work for
  // both parameters and outputSchema with no special-casing in FastMCP.
  await expect(toJsonSchema(schema)).resolves.toEqual(personSchema);
});

/** Starts a server exposing one JSON Schema tool and connects a client to it. */
const withGreetServer = async (
  run: (client: Client) => Promise<void>,
): Promise<void> => {
  const port = await getRandomPort();
  const server = new FastMCP({ name: "Test server", version: "1.0.0" });

  server.addTool({
    description: "Greet a user",
    execute: async (args) => `Hello, ${(args as { name: string }).name}!`,
    name: "greet",
    outputSchema: jsonSchemaAdapter({
      properties: { greeting: { type: "string" } },
      required: ["greeting"],
      type: "object",
    }),
    parameters: jsonSchemaAdapter({ ...personSchema }),
  });

  await server.start({ httpStream: { port }, transportType: "httpStream" });

  const client = new Client({ name: "Test client", version: "1.0.0" });

  try {
    await client.connect(
      new StreamableHTTPClientTransport(
        new URL(`http://localhost:${port}/mcp`),
      ),
    );
    await run(client);
    await client.close();
  } finally {
    await server.stop();
  }
};

test("advertises the schema through tools/list, made strict like any other", async () => {
  await withGreetServer(async (client) => {
    const { tools } = await client.listTools();
    const greet = tools.find((tool) => tool.name === "greet");

    // The adapter's schema goes through the same strictJsonSchema pass every
    // Zod or Valibot tool does, rather than being advertised raw — note the
    // additionalProperties the input schema never specified.
    expect(greet?.inputSchema).toEqual({
      additionalProperties: false,
      properties: {
        age: { type: "number" },
        name: { type: "string" },
      },
      required: ["name"],
      type: "object",
    });

    // outputSchema is converted by the same path, which is why it works at all
    // — xsschema would otherwise reject the "json-schema" vendor and fail the
    // whole listing.
    expect(greet?.outputSchema).toMatchObject({
      additionalProperties: false,
      required: ["greeting"],
    });
  });
});

test("rejects a tool call whose arguments do not match", async () => {
  await withGreetServer(async (client) => {
    // The issue path fix is what puts "name:" in front of the message; without
    // it the client is told a property is missing but not which one.
    await expect(
      client.callTool({ arguments: { age: 30 }, name: "greet" }),
    ).rejects.toThrow(/name: must have required property 'name'/);

    const accepted = await client.callTool({
      arguments: { name: "Alice" },
      name: "greet",
    });
    expect(accepted.content).toMatchObject([
      { text: "Hello, Alice!", type: "text" },
    ]);
  });
});

test("explains what to install when ajv is missing", async () => {
  vi.doMock("ajv", () => {
    throw new Error("Cannot find module 'ajv'");
  });
  vi.resetModules();

  const { jsonSchemaAdapter: freshAdapter } =
    await import("./jsonSchemaAdapter.js");
  const schema = freshAdapter({ ...personSchema });

  await expect(schema["~standard"].validate({ name: "Alice" })).rejects.toThrow(
    /npm install ajv/,
  );

  // The failure is not cached, so installing ajv and retrying works without
  // rebuilding the schema.
  await expect(schema["~standard"].validate({ name: "Alice" })).rejects.toThrow(
    /npm install ajv/,
  );

  vi.doUnmock("ajv");
  vi.resetModules();
});
