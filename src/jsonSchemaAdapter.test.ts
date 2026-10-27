import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { expect, test, vi } from "vitest";
import { toJsonSchema } from "xsschema";

import { FastMCP } from "./FastMCP.js";
import { getTestPort } from "./getTestPort.js";
import {
  jsonSchemaAdapter,
  type JsonSchemaObject,
} from "./jsonSchemaAdapter.js";

const personSchema = {
  properties: {
    age: { type: "number" },
    name: { type: "string" },
  },
  required: ["name"],
  type: "object",
};

test("validates schema-valued additional properties without type assertions", async () => {
  const dictionary: JsonSchemaObject = {
    additionalProperties: { type: "string" },
    type: "object",
  };
  const schema = jsonSchemaAdapter(dictionary);

  expect(
    (await schema["~standard"].validate({ team: "infra" })).issues,
  ).toBeUndefined();
  expect((await schema["~standard"].validate({ team: 42 })).issues).toEqual([
    expect.objectContaining({ path: ["team"] }),
  ]);
  await expect(toJsonSchema(schema)).resolves.toEqual(dictionary);
});

test.each([true, false, undefined])(
  "preserves additionalProperties: %s validation",
  async (additionalProperties) => {
    const schema = jsonSchemaAdapter({ additionalProperties, type: "object" });
    const result = await schema["~standard"].validate({ team: "infra" });

    if (additionalProperties === false) {
      expect(result.issues?.length).toBeGreaterThan(0);
    } else {
      expect(result.issues).toBeUndefined();
    }
  },
);

test("preserves dictionary schemas through tool discovery and calls", async () => {
  const dictionary = {
    additionalProperties: { type: "string" },
    type: "object",
  };
  const server = new FastMCP({ name: "Dictionary server", version: "1.0.0" });
  const execute = vi.fn(async () => ({ team: "infra" }));
  server.addTool({
    execute,
    name: "dictionary",
    outputSchema: jsonSchemaAdapter(dictionary),
    parameters: jsonSchemaAdapter(dictionary),
  });
  const port = await getTestPort();
  const client = new Client({ name: "Dictionary client", version: "1.0.0" });
  await server.start({ httpStream: { port }, transportType: "httpStream" });

  try {
    await client.connect(
      new StreamableHTTPClientTransport(
        new URL(`http://localhost:${port}/mcp`),
      ),
    );
    const { tools } = await client.listTools();
    expect(tools[0]?.inputSchema).toEqual(dictionary);
    expect(tools[0]?.outputSchema).toEqual(dictionary);
    const result = await client.callTool({
      arguments: { team: "infra" },
      name: "dictionary",
    });
    expect(result.structuredContent).toEqual({ team: "infra" });
    await expect(
      client.callTool({ arguments: { team: 42 }, name: "dictionary" }),
    ).rejects.toThrow(/team: must be string/);
    expect(execute).toHaveBeenCalledTimes(1);
  } finally {
    await client.close();
    await server.stop();
  }
});

test("accepts input matching the schema", async () => {
  const schema = jsonSchemaAdapter({ ...personSchema });

  const result = await schema["~standard"].validate({ age: 30, name: "Alice" });

  expect(result.issues).toBeUndefined();
  expect(result.issues === undefined && result.value).toEqual({
    age: 30,
    name: "Alice",
  });
});

test.each([
  "http://json-schema.org/draft/2020-12/schema",
  "http://json-schema.org/draft/2020-12/schema#",
  "https://json-schema.org/draft/2020-12/schema",
  "https://json-schema.org/draft/2020-12/schema#",
])("validates draft 2020-12 schemas (%s)", async ($schema) => {
  const schema = jsonSchemaAdapter({
    $schema,
    properties: {
      pair: {
        items: false,
        prefixItems: [{ type: "string" }, { type: "number" }],
        type: "array",
      },
    },
    required: ["pair"],
    type: "object",
    unevaluatedProperties: false,
  });

  const valid = await schema["~standard"].validate({ pair: ["answer", 42] });
  expect(valid.issues).toBeUndefined();
  await expect(toJsonSchema(schema)).resolves.toMatchObject({ $schema });

  for (const input of [
    { pair: [42, "answer"] },
    { pair: ["answer", 42, true] },
    { extra: true, pair: ["answer", 42] },
  ]) {
    const invalid = await schema["~standard"].validate(input);
    expect(invalid.issues?.length).toBeGreaterThan(0);
  }
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

test("preserves non-canonical numeric object keys in issue paths", async () => {
  const numericObjectKeys = ["01", "-1", "1.0", "9007199254740993"];
  const schema = jsonSchemaAdapter({
    properties: Object.fromEntries(
      numericObjectKeys.map((key) => [key, { type: "number" }]),
    ),
    required: numericObjectKeys,
    type: "object",
  });

  const result = await schema["~standard"].validate(
    Object.fromEntries(numericObjectKeys.map((key) => [key, "not a number"])),
  );

  expect(result.issues?.map((issue) => issue.path)).toEqual(
    numericObjectKeys.map((key) => [key]),
  );
});

test.each([
  { input: null, name: "the document root", path: [] },
  { input: { "": 42 }, name: "an empty property name", path: [""] },
  {
    input: { "": [{ "a/b": "not a number" }] },
    name: "an array item under an empty property name",
    path: ["", 0, "a/b"],
  },
  {
    input: { "": [{}] },
    name: "a missing property under an empty property name",
    path: ["", 0, "a/b"],
  },
])("preserves issue paths for $name", async ({ input, path }) => {
  const schema = jsonSchemaAdapter({
    properties: {
      "": {
        items: {
          properties: { "a/b": { type: "number" } },
          required: ["a/b"],
          type: "object",
        },
        type: "array",
      },
    },
    type: "object",
  });

  const result = await schema["~standard"].validate(input);

  expect(result.issues?.map((issue) => issue.path)).toEqual([path]);
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
  const port = await getTestPort();
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

test("advertises strict inputs and preserves the declared output schema", async () => {
  await withGreetServer(async (client) => {
    const { tools } = await client.listTools();
    const greet = tools.find((tool) => tool.name === "greet");

    // Input schemas still go through strictJsonSchema, including adapters.
    expect(greet?.inputSchema).toEqual({
      additionalProperties: false,
      properties: {
        age: { type: "number" },
        name: { type: "string" },
      },
      required: ["name"],
      type: "object",
    });

    // Omitting additionalProperties allows extra output fields; keep that
    // contract consistent with the adapter's runtime validation.
    expect(greet?.outputSchema).toEqual({
      properties: { greeting: { type: "string" } },
      required: ["greeting"],
      type: "object",
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
