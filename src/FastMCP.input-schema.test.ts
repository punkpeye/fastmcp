import type { StandardSchemaV1 } from "@standard-schema/spec";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Ajv } from "ajv";
import { type } from "arktype";
import { expect, test } from "vitest";
import { toJsonSchema } from "xsschema";
import { z } from "zod";
import { z as z3 } from "zod/v3";

import { FastMCP, jsonSchemaAdapter } from "./FastMCP.js";
import { objectRootSchema } from "./strictInputSchema.js";

const objectBranches = [
  z.object({ kind: z.literal("a"), n: z.number() }),
  z.object({ kind: z.literal("b"), s: z.string() }),
] as const;

const objectValues = [
  { kind: "a", n: 1 },
  { kind: "b", s: "ok" },
];
const repeatedBranch = z3.object({ kind: z3.literal("a"), n: z3.number() });

// The adapter's descriptor type requires a type, but union roots omit it.
const unionAdapter = (
  schema: Omit<Parameters<typeof jsonSchemaAdapter>[0], "type">,
) => jsonSchemaAdapter(schema as Parameters<typeof jsonSchemaAdapter>[0]);

test.each(
  [
    {
      acceptsExtra: false,
      name: "a discriminated union",
      schema: z.discriminatedUnion("kind", objectBranches),
    },
    {
      acceptsExtra: false,
      name: "an object union",
      schema: z.union(objectBranches),
    },
    {
      acceptsExtra: false,
      name: "a oneOf object union",
      schema: jsonSchemaAdapter({
        oneOf: objectBranches.map((branch) => z.toJSONSchema(branch)),
        type: "object",
      }),
    },
    {
      acceptsExtra: true,
      name: "a loose object union",
      schema: z.union([objectBranches[0].loose(), objectBranches[1].loose()]),
    },
    {
      acceptsExtra: false,
      name: "a nested Zod 4 object union",
      schema: z.union([
        objectBranches[0],
        z.union([
          objectBranches[1],
          z.object({ flag: z.boolean(), kind: z.literal("c") }),
        ]),
      ]),
      values: [...objectValues, { flag: true, kind: "c" }],
    },
    {
      acceptsExtra: false,
      name: "a nested Zod 3 object union",
      schema: z3.union([
        repeatedBranch,
        z3.union([
          z3.object({ kind: z3.literal("b"), s: z3.string() }),
          z3.object({ flag: z3.boolean(), kind: z3.literal("c") }),
        ]),
      ]),
      values: [...objectValues, { flag: true, kind: "c" }],
    },
    {
      acceptsExtra: false,
      name: "a Zod 3 local $ref branch union",
      schema: z3.union([repeatedBranch, repeatedBranch]),
      values: [objectValues[0]],
    },
    {
      acceptsExtra: false,
      name: "a oneOf object union without a root type",
      schema: unionAdapter({
        oneOf: objectBranches.map((branch) => z.toJSONSchema(branch)),
      }),
    },
    {
      acceptsExtra: false,
      name: "an object-only oneOf beside a mixed anyOf",
      schema: unionAdapter({
        anyOf: [
          ...objectBranches.map((branch) => z.toJSONSchema(branch)),
          { type: "string" },
        ],
        oneOf: objectBranches.map((branch) => z.toJSONSchema(branch)),
      }),
    },
    {
      acceptsExtra: false,
      name: "a percent-encoded local $ref branch union",
      schema: unionAdapter({
        anyOf: [
          { $ref: "#%2Fdefinitions%2Fa" },
          { $ref: "#%2Fdefinitions%2Fb" },
        ],
        definitions: {
          a: z.toJSONSchema(objectBranches[0]),
          b: z.toJSONSchema(objectBranches[1]),
        },
      }),
    },
    {
      acceptsExtra: false,
      name: "an object union with both combinators",
      schema: unionAdapter({
        anyOf: objectBranches.map((branch) => z.toJSONSchema(branch)),
        oneOf: [
          { oneOf: objectBranches.map((branch) => z.toJSONSchema(branch)) },
        ],
      }),
    },
  ].flatMap((entry) =>
    (["parameters", "outputSchema"] as const).map((field) => ({
      ...entry,
      field,
      values: entry.values ?? objectValues,
    })),
  ),
)(
  "lists and calls $name as $field",
  async ({ acceptsExtra, field, schema, values }) => {
    const server = new FastMCP({ name: "Unions", version: "1.0.0" });
    let output: Record<string, unknown> = { kind: "a", n: 1 };
    server.addTool({
      execute: async (args) =>
        field === "parameters" ? JSON.stringify(args) : output,
      [field]: schema,
      name: "union",
    });
    server.addTool({
      execute: async () => "ok",
      name: "plain",
      parameters: z.object({ message: z.string() }),
    });

    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "unions-client", version: "1.0.0" });

    try {
      await Promise.all([
        server.connect(serverTransport),
        client.connect(clientTransport),
      ]);
      const { tools } = await client.listTools();
      expect(tools.map((tool) => tool.name)).toEqual(["union", "plain"]);
      expect(tools[1].inputSchema).toEqual({
        $schema: "http://json-schema.org/draft-07/schema#",
        additionalProperties: false,
        properties: { message: { type: "string" } },
        required: ["message"],
        type: "object",
      });
      const advertised =
        tools[0][field === "parameters" ? "inputSchema" : field];
      expect(advertised?.type).toBe("object");
      expect(advertised?.properties).toBeUndefined();
      expect(advertised?.additionalProperties).toBeUndefined();
      expect(advertised).toMatchObject(await toJsonSchema(schema));
      // Both branch shapes must remain usable after discovery.
      for (const value of values) {
        expect(acceptsArguments(advertised!, value)).toBe(true);
        expect(acceptsArguments(advertised!, { ...value, extra: true })).toBe(
          acceptsExtra,
        );
        output = value;
        const result = await client.callTool({
          arguments: value,
          name: "union",
        });
        expect(result.isError).toBeFalsy();
        if (field === "parameters") {
          expect(result.content).toEqual([
            { text: JSON.stringify(value), type: "text" },
          ]);
        } else {
          // listTools installs the SDK's output validator before this call.
          expect(result.structuredContent).toEqual(value);
        }
      }
      expect(acceptsArguments(advertised!, { kind: "a", n: "wrong" })).toBe(
        false,
      );
    } finally {
      await client.close();
      await server.stop();
    }
  },
);

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

test.each([
  {
    args: { cursor: "c1", limit: 10 },
    name: "a Zod 4 intersection",
    parameters: z.intersection(
      z.object({ cursor: z.string() }),
      z.object({ limit: z.number() }),
    ),
  },
  {
    args: { cursor: "c1", limit: 10 },
    name: "a Zod 4 intersection with a union operand",
    parameters: z
      .union([
        z.object({ cursor: z.string() }),
        z.object({ offset: z.number() }),
      ])
      .and(z.object({ limit: z.number() })),
  },
])("lists and calls $name parameters", async ({ args, parameters }) => {
  const server = new FastMCP({ name: "Intersections", version: "1.0.0" });
  server.addTool({
    execute: async (value) => JSON.stringify(value),
    name: "pagination",
    parameters,
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "intersections-client", version: "1.0.0" });

  try {
    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);
    const schema = (await client.listTools()).tools[0].inputSchema;
    expect(parameters.safeParse(args).success).toBe(true);
    expect(acceptsArguments(schema, args)).toBe(true);
    expect(acceptsArguments(schema, { ...args, limit: "wrong" })).toBe(false);
    expect(
      await client.callTool({ arguments: args, name: "pagination" }),
    ).toEqual({ content: [{ text: JSON.stringify(args), type: "text" }] });
  } finally {
    await client.close();
    await server.stop();
  }
});

test.each(["before", "after"])(
  "keeps nested and reused objects closed %s an intersection occurrence",
  async (order) => {
    const shared = z.object({ details: z.object({ name: z.string() }) });
    const ordinary = z.array(shared);
    const intersection = shared.and(z.object({ count: z.number() }));
    const entries = [
      ["ordinary", ordinary],
      ["intersection", intersection],
    ] as const;
    const schema = await listInputSchema(
      z.object(
        Object.fromEntries(
          order === "before" ? entries : [...entries].reverse(),
        ),
      ),
    );
    const args = {
      intersection: { count: 1, details: { name: "Alice" } },
      ordinary: [{ details: { name: "Alice" } }],
    };

    expect(acceptsArguments(schema, args)).toBe(true);
    expect(
      acceptsArguments(schema, {
        ...args,
        intersection: { count: 1, details: { extra: true, name: "Alice" } },
      }),
    ).toBe(false);
    expect(
      acceptsArguments(schema, {
        ...args,
        ordinary: [{ details: { name: "Alice" }, extra: true }],
      }),
    ).toBe(false);
  },
);

test("keeps a deliberately strict intersection operand closed", async () => {
  const parameters = z
    .object({ name: z.string() })
    .strict()
    .and(z.object({ count: z.number().optional() }));
  const schema = await listInputSchema(parameters);

  expect(schema.allOf).toMatchObject([{ additionalProperties: false }, {}]);
  expect(acceptsArguments(schema, { name: "Alice" })).toBe(true);
  const extra = { count: 1, name: "Alice" };
  expect(parameters.safeParse(extra).success).toBe(false);
  expect(acceptsArguments(schema, extra)).toBe(false);
});

test("keeps a referenced operand's ordinary occurrences closed", async () => {
  type Shared = {
    children?: Shared[];
    combinedChildren?: ({ count: number } & Shared)[];
    details: { name: string };
  };
  const shared: z.ZodType<Shared> = z.object({
    get children() {
      return z.array(shared).optional();
    },
    get combinedChildren() {
      return z.array(shared.and(z.object({ count: z.number() }))).optional();
    },
    details: z.object({ name: z.string() }),
  });
  const schema = await listInputSchema(
    z.object({
      combined: shared.and(z.object({ count: z.number() })),
      ordinary: z.array(shared),
    }),
  );
  const value = { details: { name: "Alice" } };
  const args = {
    combined: {
      ...value,
      combinedChildren: [
        { ...value, combinedChildren: [{ ...value, count: 3 }], count: 2 },
      ],
      count: 1,
    },
    ordinary: [value],
  };

  expect(acceptsArguments(schema, args)).toBe(true);
  expect(
    acceptsArguments(schema, {
      ...args,
      ordinary: [{ ...value, extra: true }],
    }),
  ).toBe(false);
  expect(
    acceptsArguments(schema, {
      ...args,
      combined: { ...args.combined, children: [{ ...value, extra: true }] },
    }),
  ).toBe(false);
});

test.each([
  {
    name: "a description",
    wrap: (schema: z.ZodType) => schema.describe("Recursive input"),
  },
  {
    name: "a default",
    wrap: (schema: z.ZodType) => schema.default({ name: "Alice" }),
  },
])("keeps a recursive object closed with $name", async ({ wrap }) => {
  const shared = z.object({
    get children() {
      return z.array(shared).optional();
    },
    name: z.string(),
  });
  const schema = await listInputSchema(z.object({ value: wrap(shared) }));

  expect(acceptsArguments(schema, { value: { name: "Alice" } })).toBe(true);
  expect(
    acceptsArguments(schema, { value: { extra: true, name: "Alice" } }),
  ).toBe(false);
});

test.each([
  {
    acceptsExtra: true,
    name: "allOf",
    schema: {
      allOf: [
        { properties: { name: { type: "string" } }, required: ["name"] },
        {
          properties: { age: { minimum: 0, type: "integer" } },
          required: ["age"],
        },
      ],
      type: "object",
    },
  },
  {
    acceptsExtra: false,
    name: "a root $ref",
    schema: {
      $defs: {
        person: {
          additionalProperties: false,
          properties: {
            age: { minimum: 0, type: "integer" },
            name: { type: "string" },
          },
          required: ["name", "age"],
          type: "object",
        },
      },
      $ref: "#/$defs/person",
      type: "object",
    },
  },
  ...(["allOf", "anyOf", "oneOf"] as const).map((keyword) => ({
    acceptsExtra: true,
    name: `${keyword} with root properties`,
    schema: {
      [keyword]: [
        {
          properties: { age: { minimum: 0, type: "integer" } },
          required: ["age"],
        },
      ],
      properties: { name: { type: "string" } },
      required: ["name"],
      type: "object",
    },
  })),
  {
    acceptsExtra: true,
    name: "a root $ref with root properties",
    schema: {
      $defs: {
        extension: {
          properties: { age: { minimum: 0, type: "integer" } },
          required: ["age"],
          type: "object",
        },
      },
      $ref: "#/$defs/extension",
      properties: { name: { type: "string" } },
      required: ["name"],
      type: "object",
    },
  },
])("advertises usable $name parameters", async ({ acceptsExtra, schema }) => {
  const server = new FastMCP({ name: "Composed inputs", version: "1.0.0" });
  server.addTool({
    execute: async (args) => JSON.stringify(args),
    name: "person",
    parameters: jsonSchemaAdapter(schema),
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({
    name: "composed-inputs-client",
    version: "1.0.0",
  });

  try {
    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);
    const advertised = (await client.listTools()).tools[0].inputSchema;
    const args = { age: 20, name: "Alice" };
    expect(acceptsArguments(advertised, args)).toBe(true);
    expect(acceptsArguments(advertised, { ...args, extra: true })).toBe(
      acceptsExtra,
    );
    for (const invalid of [
      { name: "Alice" },
      { age: -1, name: "Alice" },
      { age: 20, name: 42 },
    ]) {
      expect(acceptsArguments(advertised, invalid)).toBe(false);
      expect(
        await client.callTool({ arguments: invalid, name: "person" }),
      ).toMatchObject({ isError: true });
    }
    expect(await client.callTool({ arguments: args, name: "person" })).toEqual({
      content: [{ text: JSON.stringify(args), type: "text" }],
    });
    expect(advertised).toEqual(schema);
  } finally {
    await client.close();
    await server.stop();
  }
});

test.each([
  {
    name: "a union that also admits a string",
    parameters: z.union([...objectBranches, z.string()]),
  },
  {
    name: "a nullable union",
    parameters: z.union(objectBranches).nullable(),
  },
])("lists $name with an object root", async ({ parameters }) => {
  const schema = await listInputSchema(parameters);
  expect(schema.type).toBe("object");
  for (const value of objectValues) {
    expect(acceptsArguments(schema, value)).toBe(true);
  }
});

test("keeps a root type the schema states", () => {
  expect(objectRootSchema({ type: "array" })).toEqual({ type: "array" });
});

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
