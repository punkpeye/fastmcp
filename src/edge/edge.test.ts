import {
  CallToolResultSchema,
  LATEST_PROTOCOL_VERSION,
  ListToolsResultSchema,
  SUPPORTED_PROTOCOL_VERSIONS,
} from "@modelcontextprotocol/sdk/types.js";
import { Ajv } from "ajv";
import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { z as z3 } from "zod/v3";

import { EdgeFastMCP } from "./index.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type JsonResponse = any;

const postResult = async (
  server: EdgeFastMCP,
  method: string,
  params?: Record<string, unknown>,
): Promise<JsonResponse> => {
  const response = await server.fetch(
    new Request("http://localhost/mcp", {
      body: JSON.stringify({ id: 1, jsonrpc: "2.0", method, params }),
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      method: "POST",
    }),
  );
  expect(response.status).toBe(200);
  const body: JsonResponse = await response.json();
  return body.result;
};

const unionValues = [
  { kind: "a", n: 1 },
  { kind: "b", s: "ok" },
];
const repeatedUnionBranch = z3.object({
  kind: z3.literal("a"),
  n: z3.number(),
});

describe("EdgeFastMCP", () => {
  it.each(
    [
      {
        name: "a discriminated union",
        parameters: z.discriminatedUnion("kind", [
          z.object({ kind: z.literal("a"), n: z.number() }),
          z.object({ kind: z.literal("b"), s: z.string() }),
        ]),
      },
      {
        name: "an object union",
        parameters: z.union([
          z.object({ kind: z.literal("a"), n: z.number() }),
          z.object({ kind: z.literal("b"), s: z.string() }),
        ]),
      },
      {
        name: "a Zod 3 object union",
        parameters: z3.union([
          z3.object({ kind: z3.literal("a"), n: z3.number() }),
          z3.object({ kind: z3.literal("b"), s: z3.string() }),
        ]),
      },
      {
        expectedBranches: [
          { type: "object" },
          { anyOf: [{ type: "object" }, { type: "object" }] },
        ],
        name: "a nested Zod 4 object union",
        parameters: z.union([
          z.object({ kind: z.literal("a"), n: z.number() }),
          z.union([
            z.object({ kind: z.literal("b"), s: z.string() }),
            z.object({ flag: z.boolean(), kind: z.literal("c") }),
          ]),
        ]),
        values: [...unionValues, { flag: true, kind: "c" }],
      },
      {
        expectedBranches: [
          { type: "object" },
          { anyOf: [{ type: "object" }, { type: "object" }] },
        ],
        name: "a nested Zod 3 object union",
        parameters: z3.union([
          repeatedUnionBranch,
          z3.union([
            z3.object({ kind: z3.literal("b"), s: z3.string() }),
            z3.object({ flag: z3.boolean(), kind: z3.literal("c") }),
          ]),
        ]),
        values: [...unionValues, { flag: true, kind: "c" }],
      },
      {
        expectedBranches: [{ type: "object" }, { $ref: "#/anyOf/0" }],
        name: "a Zod 3 local $ref branch union",
        parameters: z3.union([repeatedUnionBranch, repeatedUnionBranch]),
        values: [unionValues[0]],
      },
    ].map((entry) => ({ ...entry, values: entry.values ?? unionValues })),
  )(
    "lists and calls $name parameters",
    async ({ expectedBranches, parameters, values }) => {
      const server = new EdgeFastMCP({ name: "Unions", version: "1.0.0" });
      server.addTool({
        description: "Accept either branch",
        execute: async (args) => JSON.stringify(args),
        name: "union",
        parameters,
      });
      const { tools } = ListToolsResultSchema.parse(
        await postResult(server, "tools/list"),
      );
      const schema = tools[0].inputSchema;
      expect(schema.type).toBe("object");
      expect(schema.properties).toBeUndefined();
      expect(schema.additionalProperties).toBeUndefined();
      if (expectedBranches) {
        expect(schema.anyOf).toMatchObject(expectedBranches);
      }
      const validator =
        schema.$schema === "http://json-schema.org/draft-07/schema#"
          ? new Ajv({ strict: false })
          : new Ajv2020({ strict: false });
      const validate = validator.compile(schema);
      for (const value of values) {
        expect(validate(value)).toBe(true);
        expect(validate({ ...value, extra: true })).toBe(false);
        const result = CallToolResultSchema.parse(
          await postResult(server, "tools/call", {
            arguments: value,
            name: "union",
          }),
        );
        expect(result.isError).toBeFalsy();
        expect(result.content).toEqual([
          { text: JSON.stringify(value), type: "text" },
        ]);
      }
      expect(validate({ kind: "a", n: "wrong" })).toBe(false);
    },
  );

  it.each([
    {
      name: "a nested mixed union",
      parameters: z.union([
        z.object({ kind: z.literal("a") }),
        z.union([z.object({ kind: z.literal("b") }), z.string()]),
      ]),
    },
    {
      name: "a nullable object union",
      parameters: z
        .union([
          z.object({ kind: z.literal("a") }),
          z.object({ kind: z.literal("b") }),
        ])
        .nullable(),
    },
  ])("leaves $name unnormalized", async ({ parameters }) => {
    const server = new EdgeFastMCP({ name: "Mixed", version: "1.0.0" });
    server.addTool({
      description: "Keep mixed and nullable roots excluded",
      execute: async () => "ok",
      name: "mixed",
      parameters,
    });
    const result = await postResult(server, "tools/list");
    expect(result.tools[0].inputSchema.type).toBeUndefined();
    expect(() => ListToolsResultSchema.parse(result)).toThrow();
  });

  it.each(
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
      const server = new EdgeFastMCP({ name: "Inputs", version: "1.0.0" });
      server.addTool({
        description: "Check nested objects",
        execute: async () => "ok",
        name: "nested",
        parameters,
      });

      const response = await server.fetch(
        new Request("http://localhost/mcp", {
          body: JSON.stringify({ id: 1, jsonrpc: "2.0", method: "tools/list" }),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          method: "POST",
        }),
      );
      expect(response.status).toBe(200);
      const body: JsonResponse = await response.json();
      const schema = body.result.tools[0].inputSchema;
      const validate = new Ajv2020({ strict: false }).compile(schema);

      expect(validate(args({ name: "a" }))).toBe(true);
      expect(validate(args({ name: 42 }))).toBe(false);
      expect(validate(args({ extra: "allowed", name: "a" }))).toBe(
        acceptsExtra,
      );
      expect(validate(args({ extra: 42, name: "a" }))).toBe(acceptsNumberExtra);
    },
  );

  it("should handle initialize request", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 1,
          jsonrpc: "2.0",
          method: "initialize",
          params: {
            capabilities: {},
            clientInfo: { name: "test-client", version: "1.0.0" },
            protocolVersion: LATEST_PROTOCOL_VERSION,
          },
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.jsonrpc).toBe("2.0");
    expect(body.id).toBe(1);
    expect(body.result.serverInfo.name).toBe("TestServer");
    expect(body.result.serverInfo.version).toBe("1.0.0");
  });

  it("answers initialize with the protocol version the client asked for", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    const initialize = async (protocolVersion: string) => {
      const response = await server.fetch(
        new Request("http://localhost/mcp", {
          body: JSON.stringify({
            id: 1,
            jsonrpc: "2.0",
            method: "initialize",
            params: {
              capabilities: {},
              clientInfo: { name: "test-client", version: "1.0.0" },
              protocolVersion,
            },
          }),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          method: "POST",
        }),
      );
      const body: JsonResponse = await response.json();
      return body.result.protocolVersion;
    };

    // An older client only accepts a version it knows, so it must get its own back.
    for (const version of SUPPORTED_PROTOCOL_VERSIONS) {
      expect(await initialize(version)).toBe(version);
    }

    // A version the server does not support is answered with the latest one.
    expect(await initialize("1999-01-01")).toBe(LATEST_PROTOCOL_VERSION);
  });

  it.each([
    {
      parameters: z3.object({ name: z3.string() }),
      required: ["name"],
      version: "3",
    },
    {
      parameters: z.object({ name: z.string() }),
      required: ["name"],
      version: "4",
    },
    {
      parameters: z.object({ name: z.string().default("World") }),
      required: undefined,
      version: "4 with a default",
    },
  ])(
    "should list tools with Zod $version parameters",
    async ({ parameters, required }) => {
      const server = new EdgeFastMCP({
        name: "TestServer",
        version: "1.0.0",
      });

      server.addTool({
        description: "Greet someone",
        execute: async ({ name }) => `Hello, ${name}!`,
        name: "greet",
        parameters,
      });

      const response = await server.fetch(
        new Request("http://localhost/mcp", {
          body: JSON.stringify({
            id: 2,
            jsonrpc: "2.0",
            method: "tools/list",
          }),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          method: "POST",
        }),
      );

      expect(response.status).toBe(200);
      const body: JsonResponse = await response.json();
      expect(body.result.tools).toHaveLength(1);
      expect(body.result.tools[0].name).toBe("greet");
      expect(body.result.tools[0].description).toBe("Greet someone");
      expect(body.result.tools[0].inputSchema.properties.name).toMatchObject({
        type: "string",
      });
      expect(body.result.tools[0].inputSchema.required).toEqual(required);
    },
  );

  it.each([
    {
      args: { n: "abcd" },
      expected: { n: 4 },
      fieldSchema: { type: "string" },
      name: "a transform",
      parameters: z.object({
        n: z.string().transform((value) => value.length),
      }),
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
      const server = new EdgeFastMCP({ name: "Inputs", version: "1.0.0" });
      server.addTool({
        description: "Convert input",
        execute: async (value) => JSON.stringify(value),
        name: "converted",
        parameters,
      });
      server.addTool({
        description: "Echo input",
        execute: async ({ message }) => message,
        name: "plain",
        parameters: z.object({ message: z.string() }),
      });

      const request = async (method: string, params?: unknown) => {
        const response = await server.fetch(
          new Request("http://localhost/mcp", {
            body: JSON.stringify({ id: 1, jsonrpc: "2.0", method, params }),
            headers: {
              Accept: "application/json",
              "Content-Type": "application/json",
            },
            method: "POST",
          }),
        );
        expect(response.status).toBe(200);
        const body: JsonResponse = await response.json();
        expect(body.error).toBeUndefined();
        return body.result;
      };

      const { tools } = await request("tools/list");
      expect(tools.map((tool: { name: string }) => tool.name)).toEqual([
        "converted",
        "plain",
      ]);
      const schema = tools[0].inputSchema;
      expect(schema.properties?.n).toMatchObject(fieldSchema);
      expect(schema.required).toEqual(required);
      expect(schema.additionalProperties).toBe(false);

      const result = await request("tools/call", {
        arguments: args,
        name: "converted",
      });
      expect(result.isError).toBeFalsy();
      expect(result.content).toEqual([
        { text: JSON.stringify(expected), type: "text" },
      ]);
      const plainResult = await request("tools/call", {
        arguments: { message: "ok" },
        name: "plain",
      });
      expect(plainResult.isError).toBeFalsy();
      expect(plainResult.content).toEqual([{ text: "ok", type: "text" }]);
    },
  );

  it("keeps the generic Standard Schema fallback in tools/list", async () => {
    const server = new EdgeFastMCP({ name: "TestServer", version: "1.0.0" });
    server.addTool({
      description: "Accept anything",
      execute: async () => "ok",
      name: "generic",
      parameters: {
        "~standard": {
          validate: (value) => ({ value }),
          vendor: "custom",
          version: 1,
        },
      },
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({ id: 2, jsonrpc: "2.0", method: "tools/list" }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    const body: JsonResponse = await response.json();
    expect(body.result.tools[0].inputSchema).toEqual({ type: "object" });
  });

  it("keeps a record argument's value schema in tools/list, as FastMCP does", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    server.addTool({
      description: "Set labels",
      execute: async () => "ok",
      name: "setLabels",
      parameters: z.object({ labels: z.record(z.string(), z.string()) }),
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 2,
          jsonrpc: "2.0",
          method: "tools/list",
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    const body: JsonResponse = await response.json();
    const { inputSchema } = body.result.tools[0];
    expect(inputSchema.additionalProperties).toBe(false);
    expect(inputSchema.properties.labels.additionalProperties).toEqual({
      type: "string",
    });
  });

  it("should call a tool", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    server.addTool({
      description: "Greet someone",
      execute: async ({ name }) => `Hello, ${name}!`,
      name: "greet",
      parameters: z.object({ name: z.string() }),
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 3,
          jsonrpc: "2.0",
          method: "tools/call",
          params: {
            arguments: { name: "World" },
            name: "greet",
          },
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.result.content).toEqual([
      { text: "Hello, World!", type: "text" },
    ]);
  });

  it("should reject invalid tool arguments before execute", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });
    const execute = vi.fn(
      async ({ count }: { count: number }) => `Count: ${count}`,
    );

    server.addTool({
      description: "Count something",
      execute,
      name: "count",
      parameters: z.object({ count: z.number() }),
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 9,
          jsonrpc: "2.0",
          method: "tools/call",
          params: {
            arguments: { count: "not-a-number" },
            name: "count",
          },
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect.soft(body.error?.code).toBe(-32602);
    expect(execute).not.toHaveBeenCalled();
  });

  it("should return a JSON-RPC error when tool validation throws", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });
    const execute = vi.fn(async () => "unexpected");

    server.addTool({
      description: "Throw during validation",
      execute,
      name: "explode",
      parameters: z.object({ value: z.string() }).transform(() => {
        throw new Error("validator exploded");
      }),
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 11,
          jsonrpc: "2.0",
          method: "tools/call",
          params: {
            arguments: { value: "boom" },
            name: "explode",
          },
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body).toMatchObject({
      error: { code: -32603 },
      id: 11,
      jsonrpc: "2.0",
    });
    expect(execute).not.toHaveBeenCalled();
  });

  it("reports a tool that throws as a tool execution error", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    server.addTool({
      description: "Fail while running",
      execute: async () => {
        throw new Error("upstream API returned 503");
      },
      name: "flaky",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 12,
          jsonrpc: "2.0",
          method: "tools/call",
          params: { arguments: {}, name: "flaky" },
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body).toEqual({
      id: 12,
      jsonrpc: "2.0",
      result: {
        content: [
          {
            text: "Tool execution failed: upstream API returned 503",
            type: "text",
          },
        ],
        isError: true,
      },
    });
  });

  it.each([
    {
      content: [{ text: "upstream API returned 503", type: "text" }],
      isError: true,
    },
    {
      content: [{ text: "Account loaded", type: "text" }],
      isError: false,
    },
    {
      content: [{ text: "Account loaded", type: "text" }],
      structuredContent: { accountId: "123" },
    },
    {
      _meta: { retryAfter: 30 },
      content: [{ text: "upstream API returned 503", type: "text" }],
      isError: true,
      structuredContent: { status: 503 },
    },
  ])("preserves explicit tool result fields: %j", async (result) => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });
    server.addTool({
      description: "Fetch account",
      execute: async () => result,
      name: "fetchAccount",
    });
    expect(CallToolResultSchema.safeParse(result).success).toBe(true);

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 13,
          jsonrpc: "2.0",
          method: "tools/call",
          params: { name: "fetchAccount" },
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      id: 13,
      jsonrpc: "2.0",
      result,
    });
  });

  it.each([undefined, null])(
    "reports a tool that returns %s as a tool execution error",
    async (result) => {
      const server = new EdgeFastMCP({
        name: "TestServer",
        version: "1.0.0",
      });
      server.addTool({
        description: "Return nothing",
        // A JavaScript tool is not held to the declared return type.
        execute: async () => result as never,
        name: "returnNothing",
      });

      const response = await server.fetch(
        new Request("http://localhost/mcp", {
          body: JSON.stringify({
            id: 14,
            jsonrpc: "2.0",
            method: "tools/call",
            params: { name: "returnNothing" },
          }),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          method: "POST",
        }),
      );

      expect(response.status).toBe(200);
      const body: JsonResponse = await response.json();
      expect(body.id).toBe(14);
      expect(body.result.isError).toBe(true);
    },
  );

  it("should pass transformed tool arguments to execute", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });
    const execute = vi.fn(
      async ({ normalized }: { normalized: string }) => normalized,
    );

    server.addTool({
      description: "Normalize a value",
      execute,
      name: "normalize",
      parameters: z
        .object({ value: z.string() })
        .transform(({ value }) => ({ normalized: value.trim().toUpperCase() })),
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 10,
          jsonrpc: "2.0",
          method: "tools/call",
          params: {
            arguments: { value: "  transformed  " },
            name: "normalize",
          },
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.result.content).toEqual([
      { text: "TRANSFORMED", type: "text" },
    ]);
    expect(execute).toHaveBeenCalledWith({ normalized: "TRANSFORMED" });
  });

  it("should list resources", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    server.addResource({
      description: "A test resource",
      load: async () => "Test content",
      mimeType: "text/plain",
      name: "Test Resource",
      uri: "test://resource",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 4,
          jsonrpc: "2.0",
          method: "resources/list",
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.result.resources).toHaveLength(1);
    expect(body.result.resources[0].uri).toBe("test://resource");
  });

  it("lists no resource templates when it advertises static resources", async () => {
    const server = new EdgeFastMCP({ name: "TestServer", version: "1.0.0" });
    server.addResource({
      load: async () => "Test content",
      name: "Test Resource",
      uri: "test://resource",
    });

    const post = async (message: Record<string, unknown>) => {
      const response = await server.fetch(
        new Request("http://localhost/mcp", {
          body: JSON.stringify(message),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          method: "POST",
        }),
      );
      expect(response.status).toBe(200);
      return (await response.json()) as JsonResponse;
    };

    const initialized = await post({
      id: 1,
      jsonrpc: "2.0",
      method: "initialize",
      params: {
        capabilities: {},
        clientInfo: { name: "test-client", version: "1.0.0" },
        protocolVersion: LATEST_PROTOCOL_VERSION,
      },
    });
    expect(initialized.result.capabilities.resources).toEqual({});

    expect(
      await post({
        id: 2,
        jsonrpc: "2.0",
        method: "resources/templates/list",
      }),
    ).toEqual({
      id: 2,
      jsonrpc: "2.0",
      result: { resourceTemplates: [] },
    });
  });

  it("should read a resource", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    server.addResource({
      load: async () => "Test content",
      name: "Test Resource",
      uri: "test://resource",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 5,
          jsonrpc: "2.0",
          method: "resources/read",
          params: { uri: "test://resource" },
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.result.contents[0].text).toBe("Test content");
  });

  it.each([
    {
      content: { text: '{"ok":true}' },
      expectedMimeType: "application/json",
      mimeType: "application/json",
    },
    {
      content: { blob: "aGVsbG8=" },
      expectedMimeType: "application/octet-stream",
      mimeType: "application/octet-stream",
    },
    {
      content: { mimeType: "text/markdown", text: "# Hello" },
      expectedMimeType: "text/markdown",
      mimeType: "text/plain",
    },
  ])(
    "preserves $expectedMimeType when a resource load returns an object",
    async ({ content, expectedMimeType, mimeType }) => {
      const server = new EdgeFastMCP({ name: "TestServer", version: "1.0.0" });
      server.addResource({
        load: async () => content,
        mimeType,
        name: "Test Resource",
        uri: "test://resource",
      });

      const response = await server.fetch(
        new Request("http://localhost/mcp", {
          body: JSON.stringify({
            id: 5,
            jsonrpc: "2.0",
            method: "resources/read",
            params: { uri: "test://resource" },
          }),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          method: "POST",
        }),
      );

      expect(response.status).toBe(200);
      const body: JsonResponse = await response.json();
      expect(body.result.contents).toEqual([
        { ...content, mimeType: expectedMimeType, uri: "test://resource" },
      ]);
    },
  );

  it("should list prompts", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    server.addPrompt({
      arguments: [
        { description: "First argument", name: "arg1", required: true },
      ],
      description: "A test prompt",
      load: async (args) => `Prompt with ${args.arg1}`,
      name: "test_prompt",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 6,
          jsonrpc: "2.0",
          method: "prompts/list",
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.result.prompts).toHaveLength(1);
    expect(body.result.prompts[0].name).toBe("test_prompt");
  });

  it("should get a prompt", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    server.addPrompt({
      description: "A test prompt",
      load: async (args) => `Prompt with ${args.value ?? "default"}`,
      name: "test_prompt",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 7,
          jsonrpc: "2.0",
          method: "prompts/get",
          params: { arguments: { value: "test" }, name: "test_prompt" },
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.result.messages[0].content.text).toBe("Prompt with test");
  });

  it("answers -32602 when prompts/get omits a required argument", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });
    const load = vi.fn(async (args: Record<string, string>) => {
      return `Commit: ${args.changes}`;
    });

    server.addPrompt({
      arguments: [
        { description: "Changes to commit", name: "changes", required: true },
      ],
      load,
      name: "git-commit",
    });
    server.addPrompt({
      arguments: [{ name: "constructor", required: true }],
      load,
      name: "build",
    });

    const getPrompt = async (name: string, args?: Record<string, string>) => {
      const response = await server.fetch(
        new Request("http://localhost/mcp", {
          body: JSON.stringify({
            id: 8,
            jsonrpc: "2.0",
            method: "prompts/get",
            params: { arguments: args, name },
          }),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          method: "POST",
        }),
      );

      return (await response.json()) as JsonResponse;
    };

    expect((await getPrompt("git-commit")).error).toMatchObject({
      code: -32602,
      message:
        "Prompt 'git-commit' requires argument 'changes': Changes to commit",
    });
    // `in` would find Object.prototype.constructor and let it through.
    expect((await getPrompt("build", {})).error).toMatchObject({
      code: -32602,
      message: expect.stringContaining("requires argument 'constructor'"),
    });
    expect(load).not.toHaveBeenCalled();

    const body = await getPrompt("git-commit", { changes: "add tests" });
    expect(body.result.messages[0].content.text).toBe("Commit: add tests");
  });

  it("replaces a tool added again with the same name", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    for (const version of ["v1", "v2"]) {
      server.addTool({
        description: version,
        execute: async () => version,
        name: "greet",
      });
    }

    expect((await postResult(server, "tools/list")).tools).toEqual([
      { description: "v2", inputSchema: { type: "object" }, name: "greet" },
    ]);
    expect(
      (await postResult(server, "tools/call", { name: "greet" })).content,
    ).toEqual([{ text: "v2", type: "text" }]);
  });

  it("replaces a prompt added again with the same name", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    for (const version of ["v1", "v2"]) {
      server.addPrompt({
        description: version,
        load: async () => version,
        name: "greet",
      });
    }

    expect((await postResult(server, "prompts/list")).prompts).toEqual([
      { description: "v2", name: "greet" },
    ]);
    expect(
      (await postResult(server, "prompts/get", { name: "greet" })).messages,
    ).toEqual([{ content: { text: "v2", type: "text" }, role: "user" }]);
  });

  it("replaces a resource added again with the same URI", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    for (const version of ["v1", "v2"]) {
      server.addResource({
        load: async () => version,
        name: version,
        uri: "test://greeting",
      });
    }

    expect((await postResult(server, "resources/list")).resources).toEqual([
      { name: "v2", uri: "test://greeting" },
    ]);
    expect(
      (await postResult(server, "resources/read", { uri: "test://greeting" }))
        .contents,
    ).toEqual([{ mimeType: "text/plain", text: "v2", uri: "test://greeting" }]);
  });

  it("should handle health check", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    const response = await server.fetch(new Request("http://localhost/health"));

    expect(response.status).toBe(200);
    const body = await response.text();
    expect(body).toContain("Ok");
  });

  it("should handle ping", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 8,
          jsonrpc: "2.0",
          method: "ping",
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.result).toEqual({});
  });

  it("should preserve the array envelope for a one-request JSON-RPC batch", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify([
          {
            id: 12,
            jsonrpc: "2.0",
            method: "ping",
          },
        ]),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body).toEqual([{ id: 12, jsonrpc: "2.0", result: {} }]);
  });

  it("should reject an empty JSON-RPC batch with one Invalid Request object", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify([]),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    // MCP requires an HTTP error status for input the server cannot accept;
    // JSON-RPC only dictates the body shape (a single -32600 object, id null).
    expect(response.status).toBe(400);
    const body: JsonResponse = await response.json();
    expect(body).toMatchObject({
      error: { code: -32600 },
      id: null,
      jsonrpc: "2.0",
    });
    expect(Array.isArray(body)).toBe(false);
  });

  it("should return error for invalid JSON", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: "not json",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(400);
    const body: JsonResponse = await response.json();
    expect(body.error.code).toBe(-32700);
  });

  it("should return 406 for wrong Accept header", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({}),
        headers: {
          Accept: "text/html",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(406);
  });

  it("should return 400 for an unsupported MCP-Protocol-Version header", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    const post = (headers: Record<string, string>) =>
      server.fetch(
        new Request("http://localhost/mcp", {
          body: JSON.stringify({ id: 1, jsonrpc: "2.0", method: "ping" }),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            ...headers,
          },
          method: "POST",
        }),
      );

    const unsupported = await post({ "MCP-Protocol-Version": "1999-01-01" });

    expect(unsupported.status).toBe(400);
    const body: JsonResponse = await unsupported.json();
    expect(body.error.code).toBe(-32000);
    expect(body.error.message).toContain(
      "Unsupported protocol version: 1999-01-01",
    );

    // A supported version, or none at all, is still served.
    expect(
      (await post({ "MCP-Protocol-Version": LATEST_PROTOCOL_VERSION })).status,
    ).toBe(200);
    expect((await post({})).status).toBe(200);

    // initialize negotiates the version in its body, so the header is not
    // checked there, as in the SDK's transport.
    const initialize = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 2,
          jsonrpc: "2.0",
          method: "initialize",
          params: {
            capabilities: {},
            clientInfo: { name: "test-client", version: "1.0.0" },
            protocolVersion: "1999-01-01",
          },
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "MCP-Protocol-Version": "1999-01-01",
        },
        method: "POST",
      }),
    );

    expect(initialize.status).toBe(200);

    const get = await server.fetch(
      new Request("http://localhost/mcp", {
        headers: {
          Accept: "text/event-stream",
          "MCP-Protocol-Version": "1999-01-01",
        },
      }),
    );
    expect(get.status).toBe(400);

    const deleted = await server.fetch(
      new Request("http://localhost/mcp", {
        headers: { "MCP-Protocol-Version": "1999-01-01" },
        method: "DELETE",
      }),
    );
    expect(deleted.status).toBe(400);
  });

  it("should allow custom MCP path", async () => {
    const server = new EdgeFastMCP({
      mcpPath: "/api/mcp",
      name: "TestServer",
      version: "1.0.0",
    });

    const response = await server.fetch(
      new Request("http://localhost/api/mcp", {
        body: JSON.stringify({
          id: 1,
          jsonrpc: "2.0",
          method: "ping",
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
  });
});
