import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { fileURLToPath } from "node:url";
import { expect, test, vi } from "vitest";

import { FastMCP } from "../FastMCP.js";
import { fromOpenAPI } from "./fromOpenAPI.js";

const WIDGETS_SPEC = {
  info: { title: "Widgets API", version: "1.0.0" },
  openapi: "3.0.3",
  paths: {
    "/widgets": {
      post: {
        operationId: "createWidget",
        requestBody: {
          content: {
            "application/json": {
              schema: {
                properties: { name: { type: "string" } },
                required: ["name"],
                type: "object",
              },
            },
          },
        },
        responses: { 200: { description: "OK" } },
      },
    },
  },
  servers: [{ url: "https://api.example.com" }],
};

const WIDGETS_TYPED_SPEC = {
  info: { title: "Widgets API", version: "1.0.0" },
  openapi: "3.0.3",
  paths: {
    "/widgets/typed": {
      get: {
        operationId: "listTypedWidgets",
        responses: {
          200: {
            content: {
              "application/json": {
                schema: { items: { type: "string" }, type: "array" },
              },
            },
            description: "OK",
          },
        },
      },
      post: {
        operationId: "createTypedWidget",
        requestBody: {
          content: {
            "application/json": {
              schema: {
                properties: { name: { type: "string" } },
                required: ["name"],
                type: "object",
              },
            },
          },
        },
        responses: {
          200: {
            content: {
              "application/json": {
                schema: {
                  properties: {
                    id: { type: "string" },
                    name: { type: "string" },
                  },
                  required: ["id", "name"],
                  type: "object",
                },
              },
            },
            description: "OK",
          },
        },
      },
    },
  },
  servers: [{ url: "https://api.example.com" }],
};

const WIDGETS_READ_SPEC = {
  info: { title: "Widgets API", version: "1.0.0" },
  openapi: "3.0.3",
  paths: {
    "/widgets": {
      get: {
        operationId: "listWidgets",
        responses: { 200: { description: "OK" } },
      },
    },
    "/widgets/{widgetId}": {
      get: {
        operationId: "getWidget",
        parameters: [
          {
            in: "path",
            name: "widgetId",
            required: true,
            schema: { type: "string" },
          },
        ],
        responses: { 200: { description: "OK" } },
      },
    },
  },
  servers: [{ url: "https://api.example.com" }],
};

const PATH_SERVERS = [
  { url: "https://path.example.com/v2" },
  { url: "https://unused.example.com" },
];
const OPERATION_SERVERS = [
  {
    url: "https://{region}.example.com/v3",
    variables: { region: { default: "operation" } },
  },
  { url: "https://unused.example.com" },
];

async function connect(server: FastMCP) {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });

  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);

  return client;
}

test.each([
  { expected: ["id,name"], explode: false, style: undefined },
  { expected: ["id,name"], explode: false, style: "form" },
  { expected: ["id", "name"], explode: true, style: undefined },
  { expected: ["id", "name"], explode: true, style: "form" },
  { expected: ["id", "name"], explode: undefined, style: undefined },
  { expected: ["id", "name"], explode: undefined, style: "form" },
])(
  "a referenced query array respects style=$style, explode=$explode",
  async ({ expected, explode, style }) => {
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response("{}"));
    const server = await fromOpenAPI({
      fetch: fetchImpl,
      spec: {
        components: {
          parameters: {
            Fields: {
              explode,
              in: "query",
              name: "fields",
              schema: { items: { type: "string" }, type: "array" },
              style,
            },
          },
        },
        info: { title: "Files API", version: "1.0.0" },
        openapi: "3.0.3",
        paths: {
          "/files/{file_id}": {
            get: {
              operationId: "getFile",
              parameters: [
                {
                  in: "path",
                  name: "file_id",
                  required: true,
                  schema: { type: "string" },
                },
                { $ref: "#/components/parameters/Fields" },
              ],
              responses: { 200: { description: "OK" } },
            },
          },
        },
        servers: [{ url: "https://api.example.com" }],
      },
    });
    const client = await connect(server);

    try {
      const result = await client.callTool({
        arguments: { fields: ["id", "name"], file_id: "123" },
        name: "getFile",
      });
      expect(result.isError).toBeFalsy();
      expect(fetchImpl).toHaveBeenCalledOnce();
      const [calledUrl] = fetchImpl.mock.calls[0]!;
      const url = new URL(calledUrl);
      expect(url.pathname).toBe("/files/123");
      expect(url.searchParams.getAll("fields")).toEqual(expected);
    } finally {
      await server.sessions[0]?.close();
      await client.close();
      await server.stop();
    }
  },
);

test.each([
  { emptyProperties: false, required: false },
  { emptyProperties: false, required: true },
  { emptyProperties: true, required: false },
  { emptyProperties: true, required: true },
])(
  "a JSON dictionary body remains callable with emptyProperties=$emptyProperties, required=$required",
  async ({ emptyProperties, required }) => {
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response("{}"));
    const server = await fromOpenAPI({
      fetch: fetchImpl,
      spec: {
        info: { title: "Labels API", version: "1.0.0" },
        openapi: "3.0.3",
        paths: {
          "/labels": {
            post: {
              operationId: "setLabels",
              parameters: [
                { in: "query", name: "body", schema: { type: "string" } },
              ],
              requestBody: {
                content: {
                  "application/json": {
                    // zod-to-json-schema's openApi3 target emits these shapes
                    // for z.record(z.string()) and z.object({}).catchall(z.string()).
                    schema: {
                      additionalProperties: { type: "string" },
                      ...(emptyProperties ? { properties: {} } : {}),
                      type: "object",
                    },
                  },
                },
                required,
              },
              responses: { 200: { description: "OK" } },
            },
          },
        },
        servers: [{ url: "https://api.example.com" }],
      },
    });
    const client = await connect(server);

    try {
      const { tools } = await client.listTools();
      const labels = { environment: "staging", team: "infra" };
      const result = await client.callTool({
        arguments: { body: labels, body__query: "preview" },
        name: "setLabels",
      });
      expect(result.isError).toBeFalsy();
      expect(fetchImpl).toHaveBeenCalledExactlyOnceWith(
        "https://api.example.com/labels?body=preview",
        expect.objectContaining({
          body: JSON.stringify(labels),
          method: "POST",
        }),
      );
      expect(fetchImpl.mock.calls[0][1]?.headers).toBeInstanceOf(Headers);
      expect(
        (fetchImpl.mock.calls[0][1]?.headers as Headers).get("content-type"),
      ).toBe("application/json");
      expect(Object.keys(tools[0].inputSchema.properties!).sort()).toEqual([
        "body",
        "body__query",
      ]);
      expect(tools[0].inputSchema.properties!.body).toMatchObject({
        additionalProperties: { type: "string" },
      });
      expect(tools[0].inputSchema.required).toEqual(
        required ? ["body"] : undefined,
      );

      fetchImpl.mockClear();
      await expect(
        client.callTool({
          arguments: { body: { team: 42 } },
          name: "setLabels",
        }),
      ).rejects.toThrow(/must be string/);
      expect(fetchImpl).not.toHaveBeenCalled();

      const empty = await client.callTool({
        arguments: { body: {} },
        name: "setLabels",
      });
      expect(empty.isError).toBeFalsy();
      expect(fetchImpl).toHaveBeenCalledExactlyOnceWith(
        "https://api.example.com/labels",
        expect.objectContaining({ body: "{}" }),
      );

      fetchImpl.mockClear();
      if (required) {
        await expect(
          client.callTool({ arguments: {}, name: "setLabels" }),
        ).rejects.toThrow(/body.*[Rr]equired|required.*body/);
        expect(fetchImpl).not.toHaveBeenCalled();
      } else {
        const omitted = await client.callTool({
          arguments: {},
          name: "setLabels",
        });
        expect(omitted.isError).toBeFalsy();
        expect(fetchImpl).toHaveBeenCalledExactlyOnceWith(
          "https://api.example.com/labels",
          expect.objectContaining({ body: undefined }),
        );
      }
    } finally {
      await server.sessions[0]?.close();
      await client.close();
      await server.stop();
    }
  },
);

test.each([
  { expected: "https://api.example.com", label: "root fallback" },
  {
    expected: "https://path.example.com/v2",
    label: "path overrides root",
    pathServers: PATH_SERVERS,
  },
  {
    expected: "https://operation.example.com/v3",
    label: "operation overrides root",
    operationServers: OPERATION_SERVERS,
  },
  {
    expected: "https://operation.example.com/v3",
    label: "operation overrides path and root",
    operationServers: OPERATION_SERVERS,
    pathServers: PATH_SERVERS,
  },
  {
    expected: "https://path.example.com/v2",
    label: "path without root servers",
    pathServers: PATH_SERVERS,
    withoutRootServers: true,
  },
  {
    expected: "https://operation.example.com/v3",
    label: "operation without root servers",
    operationServers: OPERATION_SERVERS,
    withoutRootServers: true,
  },
  {
    expected: "https://path.example.com/v2",
    label: "empty operation servers inherit path servers",
    operationServers: [],
    pathServers: PATH_SERVERS,
  },
  {
    expected: "https://api.example.com",
    label: "empty path servers inherit root servers",
    pathServers: [],
  },
  {
    expected: "https://api.example.com",
    label: "empty operation and path servers inherit root servers",
    operationServers: [],
    pathServers: [],
  },
  {
    baseUrl: "https://proxy.example.com/api/",
    expected: "https://proxy.example.com/api",
    label: "baseUrl overrides every server level",
    operationServers: OPERATION_SERVERS,
    pathServers: PATH_SERVERS,
  },
])(
  "tool server selection: $label",
  async ({
    baseUrl,
    expected,
    operationServers,
    pathServers,
    withoutRootServers,
  }) => {
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response("{}"));
    const server = await fromOpenAPI({
      baseUrl,
      fetch: fetchImpl,
      spec: {
        ...WIDGETS_SPEC,
        paths: {
          "/widgets": {
            post: {
              ...WIDGETS_SPEC.paths["/widgets"].post,
              servers: operationServers,
            },
            servers: pathServers,
          },
        },
        servers: withoutRootServers ? undefined : WIDGETS_SPEC.servers,
      },
    });
    const client = await connect(server);

    try {
      const result = await client.callTool({
        arguments: { name: "sprocket" },
        name: "createWidget",
      });
      expect(result.isError).toBeFalsy();
      expect(fetchImpl).toHaveBeenCalledExactlyOnceWith(
        `${expected}/widgets`,
        expect.objectContaining({
          body: JSON.stringify({ name: "sprocket" }),
          method: "POST",
        }),
      );
    } finally {
      await server.sessions[0]?.close();
      await client.close();
      await server.stop();
    }
  },
);

test.each([undefined, "https://proxy.example.com/api"])(
  "resources keep each route's servers, including referenced path items (baseUrl: %s)",
  async (baseUrl) => {
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response("{}"));
    const server = await fromOpenAPI({
      baseUrl,
      fetch: fetchImpl,
      resources: true,
      spec: {
        components: {
          pathItems: {
            Widget: {
              get: {
                parameters:
                  WIDGETS_READ_SPEC.paths["/widgets/{widgetId}"].get.parameters,
                responses: { 200: { description: "OK" } },
              },
            },
          },
        },
        info: WIDGETS_READ_SPEC.info,
        openapi: "3.1.0",
        paths: {
          "/archived-widgets/{widgetId}": {
            $ref: "#/components/pathItems/Widget",
            servers: [{ url: "https://archive.example.com" }],
          },
          "/health": {
            get: {
              operationId: "health",
              responses: { 200: { description: "OK" } },
            },
          },
          "/widgets": {
            get: {
              ...WIDGETS_READ_SPEC.paths["/widgets"].get,
              servers: OPERATION_SERVERS,
            },
            servers: PATH_SERVERS,
          },
          "/widgets/{widgetId}": {
            $ref: "#/components/pathItems/Widget",
            servers: PATH_SERVERS,
          },
        },
        servers: WIDGETS_READ_SPEC.servers,
      },
    });
    const client = await connect(server);

    try {
      for (const [name, path, expectedBase] of [
        ["get_widgets_widgetId", "/widgets/w1", "https://path.example.com/v2"],
        [
          "get_archived_widgets_widgetId",
          "/archived-widgets/w1",
          "https://archive.example.com",
        ],
        ["listWidgets", "/widgets", "https://operation.example.com/v3"],
        ["health", "/health", "https://api.example.com"],
      ]) {
        const result = await client.readResource({
          uri: `openapi://${name}${path}`,
        });
        expect(result.contents).toEqual([
          expect.objectContaining({ text: "{}" }),
        ]);
        expect(fetchImpl).toHaveBeenLastCalledWith(
          `${baseUrl ?? expectedBase}${path}`,
          expect.objectContaining({ method: "GET" }),
        );
      }
      expect(fetchImpl).toHaveBeenCalledTimes(4);
    } finally {
      await server.sessions[0]?.close();
      await client.close();
      await server.stop();
    }
  },
);

test.each(["path", "operation"])(
  "relative %s servers resolve against the spec URL with variable defaults",
  async (level) => {
    const servers = [
      { url: "../{version}", variables: { version: { default: "v2" } } },
    ];
    const specFetch = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () =>
        Response.json({
          ...WIDGETS_SPEC,
          paths: {
            "/widgets": {
              post: {
                ...WIDGETS_SPEC.paths["/widgets"].post,
                ...(level === "operation" ? { servers } : {}),
              },
              servers: level === "path" ? servers : PATH_SERVERS,
            },
          },
        }),
      );

    try {
      const fetchImpl = vi.fn<typeof fetch>(async () => new Response("{}"));
      const server = await fromOpenAPI({
        fetch: fetchImpl,
        spec: "https://specs.example.com/specs/openapi.json",
      });
      const client = await connect(server);

      try {
        const result = await client.callTool({
          arguments: { name: "sprocket" },
          name: "createWidget",
        });
        expect(result.isError).toBeFalsy();
        expect(fetchImpl).toHaveBeenCalledExactlyOnceWith(
          "https://specs.example.com/v2/widgets",
          expect.objectContaining({ method: "POST" }),
        );
      } finally {
        await server.sessions[0]?.close();
        await client.close();
        await server.stop();
      }
    } finally {
      specFetch.mockRestore();
    }
  },
);

test.each([false, true])(
  "shared external path items stay callable at each path (resources: %s)",
  async (resources) => {
    const fetchImpl = vi.fn<typeof fetch>(
      async () => new Response(JSON.stringify({ id: 42 })),
    );
    const server = await fromOpenAPI({
      fetch: fetchImpl,
      resources,
      spec: fileURLToPath(
        new URL("./__fixtures__/shared-path-items/root.yaml", import.meta.url),
      ),
    });
    const client = await connect(server);

    try {
      if (resources) {
        const { resourceTemplates } = await client.listResourceTemplates();
        expect(
          resourceTemplates.map((template) => template.uriTemplate).sort(),
        ).toEqual([
          "openapi://get_archived_pets_petId/archived-pets/{petId}",
          "openapi://get_pets_petId/pets/{petId}",
        ]);

        for (const template of resourceTemplates) {
          const result = await client.readResource({
            uri: template.uriTemplate.replace("{petId}", "42"),
          });
          expect(result.contents).toEqual([
            expect.objectContaining({ text: JSON.stringify({ id: 42 }) }),
          ]);
        }
      } else {
        const { tools } = await client.listTools();
        expect(tools.map((tool) => tool.name).sort()).toEqual([
          "get_archived_pets_petId",
          "get_pets_petId",
        ]);

        for (const tool of tools) {
          const result = await client.callTool({
            arguments: { petId: 42 },
            name: tool.name,
          });
          expect(result.isError).toBeFalsy();
          expect(result.content).toEqual([
            { text: JSON.stringify({ id: 42 }), type: "text" },
          ]);
        }
      }

      expect(fetchImpl.mock.calls.map(([url]) => url).sort()).toEqual([
        "https://api.example.com/archived-pets/42",
        "https://api.example.com/pets/42",
      ]);
    } finally {
      await client.close();
      await server.stop();
    }
  },
);

test.each(["3.0.3", "3.1.0"])(
  "internal path item references preserve sibling parameters in OpenAPI %s",
  async (openapi) => {
    const prefix =
      openapi === "3.0.3" ? "#/x-path-items" : "#/components/pathItems";
    const pathItems = {
      Alias: { $ref: `${prefix}/Pet` },
      Pet: {
        get: {
          operationId: "getPet",
          responses: { 200: { description: "OK" } },
        },
      },
    };
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response("pet"));
    const server = await fromOpenAPI({
      fetch: fetchImpl,
      spec: {
        ...(openapi === "3.0.3"
          ? { "x-path-items": pathItems }
          : { components: { pathItems } }),
        info: { title: "Internal path items", version: "1.0.0" },
        openapi,
        paths: {
          "/pets/{petId}": {
            $ref: `${prefix}/Alias`,
            parameters: [
              {
                in: "path",
                name: "petId",
                required: true,
                schema: { type: "integer" },
              },
            ],
          },
        },
        servers: [{ url: "https://api.example.com" }],
      },
    });
    const client = await connect(server);

    try {
      const { tools } = await client.listTools();
      expect(tools.map((tool) => tool.name)).toEqual(["getPet"]);
      const result = await client.callTool({
        arguments: { petId: 42 },
        name: "getPet",
      });
      expect(result.content).toEqual([{ text: "pet", type: "text" }]);
      expect(result.isError).toBeFalsy();
      expect(fetchImpl).toHaveBeenCalledWith(
        "https://api.example.com/pets/42",
        expect.objectContaining({ method: "GET" }),
      );
    } finally {
      await client.close();
      await server.stop();
    }
  },
);

test("path item reference chains keep sibling fields from intermediate items", async () => {
  const fetchImpl = vi.fn<typeof fetch>(async () => new Response("pet"));
  const server = await fromOpenAPI({
    fetch: fetchImpl,
    spec: {
      components: {
        pathItems: {
          Pet: {
            get: {
              operationId: "getPet",
              responses: { 200: { description: "OK" } },
            },
          },
          PetById: {
            $ref: "#/components/pathItems/Pet",
            parameters: [
              {
                in: "path",
                name: "petId",
                required: true,
                schema: { type: "integer" },
              },
            ],
          },
        },
      },
      info: { title: "Path item chains", version: "1.0.0" },
      openapi: "3.1.0",
      paths: {
        "/pets/{petId}": { $ref: "#/components/pathItems/PetById" },
      },
      servers: [{ url: "https://api.example.com" }],
    },
  });
  const client = await connect(server);

  try {
    const { tools } = await client.listTools();
    expect(tools.map((tool) => tool.name)).toEqual(["getPet"]);
    const result = await client.callTool({
      arguments: { petId: 42 },
      name: "getPet",
    });
    expect(result.content).toEqual([{ text: "pet", type: "text" }]);
    expect(result.isError).toBeFalsy();
    expect(fetchImpl).toHaveBeenCalledWith(
      "https://api.example.com/pets/42",
      expect.objectContaining({ method: "GET" }),
    );
  } finally {
    await client.close();
    await server.stop();
  }
});

test("paths sharing an external path item keep only their own sibling parameters", async () => {
  const server = await fromOpenAPI({
    fetch: vi.fn(async () => new Response("{}")),
    spec: fileURLToPath(
      new URL(
        "./__fixtures__/shared-path-items/sibling-parameters.yaml",
        import.meta.url,
      ),
    ),
  });
  const client = await connect(server);

  try {
    const { tools } = await client.listTools();
    expect(
      Object.fromEntries(
        tools.map((tool) => [
          tool.name,
          Object.keys(tool.inputSchema.properties ?? {}),
        ]),
      ),
    ).toEqual({
      get_archived_pets_archivedId: ["archivedId"],
      get_pets_petId: ["petId"],
    });
  } finally {
    await client.close();
    await server.stop();
  }
});

test("defaults the server name to the spec's info.title, and the version to 1.0.0", async () => {
  const server = await fromOpenAPI({
    fetch: vi.fn(async () => new Response("{}")),
    spec: WIDGETS_SPEC,
  });

  const client = await connect(server);
  expect(client.getServerVersion()).toMatchObject({
    name: "Widgets API",
    version: "1.0.0",
  });
});

test("an explicit fetch is used to execute a tool call, and the request is built correctly", async () => {
  const fetchImpl = vi.fn<typeof fetch>(
    async () => new Response(JSON.stringify({ id: "w1" })),
  );

  const server = await fromOpenAPI({ fetch: fetchImpl, spec: WIDGETS_SPEC });
  const client = await connect(server);

  const result = await client.callTool({
    arguments: { name: "sprocket" },
    name: "createWidget",
  });

  expect(fetchImpl).toHaveBeenCalledWith(
    "https://api.example.com/widgets",
    expect.objectContaining({ method: "POST" }),
  );
  expect((result.content as { text: string }[])[0].text).toContain("w1");
});

test("registers onto an existing server (`server` option) instead of always creating a new one", async () => {
  const existing = new FastMCP({ name: "My Server", version: "2.0.0" });
  existing.addTool({
    execute: async () => "pong",
    name: "ping",
  });

  const returned = await fromOpenAPI({
    fetch: vi.fn(async () => new Response("{}")),
    server: existing,
    spec: WIDGETS_SPEC,
  });

  expect(returned).toBe(existing);

  const client = await connect(returned);
  const { tools } = await client.listTools();
  expect(tools.map((tool) => tool.name).sort()).toEqual([
    "createWidget",
    "ping",
  ]);
});

test("resources: true — a parameterless GET becomes a static resource, readable end-to-end", async () => {
  const fetchImpl = vi.fn<typeof fetch>(
    async () => new Response(JSON.stringify({ widgets: [] })),
  );

  const server = await fromOpenAPI({
    fetch: fetchImpl,
    resources: true,
    spec: WIDGETS_READ_SPEC,
  });
  const client = await connect(server);

  const { resources } = await client.listResources();
  expect(resources.map((r) => r.uri)).toContain(
    "openapi://listWidgets/widgets",
  );
  // The spec has exactly one operation, and it became a resource — no tools
  // capability is declared at all (not just an empty tools/list).
  expect(client.getServerCapabilities()?.tools).toBeUndefined();

  const result = await client.readResource({
    uri: "openapi://listWidgets/widgets",
  });
  expect(fetchImpl).toHaveBeenCalledWith(
    "https://api.example.com/widgets",
    expect.objectContaining({ method: "GET" }),
  );
  expect(result.contents[0].mimeType).toBe("application/json");
  expect((result.contents[0] as { text: string }).text).toContain("widgets");
});

test("resources: true — a GET with a path parameter becomes a resource template, readable end-to-end", async () => {
  const fetchImpl = vi.fn<typeof fetch>(
    async () => new Response(JSON.stringify({ id: "w1", name: "sprocket" })),
  );

  const server = await fromOpenAPI({
    fetch: fetchImpl,
    resources: true,
    spec: WIDGETS_READ_SPEC,
  });
  const client = await connect(server);

  const { resourceTemplates } = await client.listResourceTemplates();
  const template = resourceTemplates.find((t) => t.name === "getWidget");
  expect(template?.uriTemplate).toBe("openapi://getWidget/widgets/{widgetId}");

  const result = await client.readResource({
    uri: "openapi://getWidget/widgets/w1",
  });
  expect(fetchImpl).toHaveBeenCalledWith(
    "https://api.example.com/widgets/w1",
    expect.objectContaining({ method: "GET" }),
  );
  expect(JSON.parse((result.contents[0] as { text: string }).text)).toEqual({
    id: "w1",
    name: "sprocket",
  });
});

test("a FastAPI-style form body (`$ref` to a component schema) becomes a tool with flattened parameters that posts form-encoded", async () => {
  const fetchImpl = vi.fn<typeof fetch>(
    async () => new Response(JSON.stringify({ access_token: "t" })),
  );

  const server = await fromOpenAPI({
    fetch: fetchImpl,
    spec: {
      components: {
        schemas: {
          Body_login: {
            properties: {
              password: { type: "string" },
              username: { type: "string" },
            },
            required: ["username", "password"],
            type: "object",
          },
        },
      },
      info: { title: "Auth API", version: "1.0.0" },
      openapi: "3.1.0",
      paths: {
        "/token": {
          post: {
            operationId: "login",
            requestBody: {
              content: {
                "application/x-www-form-urlencoded": {
                  schema: { $ref: "#/components/schemas/Body_login" },
                },
              },
              required: true,
            },
            responses: { 200: { description: "OK" } },
          },
        },
      },
      servers: [{ url: "https://api.example.com" }],
    },
  });
  const client = await connect(server);

  const { tools } = await client.listTools();
  expect(tools.map((tool) => tool.name)).toEqual(["login"]);
  expect(Object.keys(tools[0].inputSchema.properties ?? {}).sort()).toEqual([
    "password",
    "username",
  ]);

  await client.callTool({
    arguments: { password: "pw", username: "ann" },
    name: "login",
  });

  const [url, init] = fetchImpl.mock.calls[0]!;
  expect(url).toBe("https://api.example.com/token");
  expect((init!.headers as Headers).get("content-type")).toBe(
    "application/x-www-form-urlencoded",
  );
  expect(new URLSearchParams(init!.body as string).get("username")).toBe("ann");
});

test.each([false, true])(
  "an explicit non-nullable input keeps its type validation (explicit=$0)",
  async (explicit) => {
    const spec = structuredClone(WIDGETS_SPEC);
    if (explicit) {
      Object.assign(
        spec.paths["/widgets"].post.requestBody.content["application/json"]
          .schema.properties.name,
        { nullable: false },
      );
    }
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response("{}"));
    const server = await fromOpenAPI({ fetch: fetchImpl, spec });
    const client = await connect(server);

    try {
      for (const name of [42, null]) {
        await expect(
          client.callTool({ arguments: { name }, name: "createWidget" }),
        ).rejects.toThrow(/must be string/);
      }
      expect(fetchImpl).not.toHaveBeenCalled();

      const { tools } = await client.listTools();
      expect(tools[0].inputSchema.properties?.name).toEqual({ type: "string" });

      const result = await client.callTool({
        arguments: { name: "sprocket" },
        name: "createWidget",
      });
      expect(result.isError).toBeFalsy();
      expect(fetchImpl).toHaveBeenCalledExactlyOnceWith(
        "https://api.example.com/widgets",
        expect.objectContaining({ body: '{"name":"sprocket"}' }),
      );
    } finally {
      await Promise.all(server.sessions.map((session) => session.close()));
      await client.close();
      await server.stop();
    }
  },
);

test.each([false, true])(
  "an explicit non-nullable response keeps structured output (referenced=$0)",
  async (referenced) => {
    const spec = structuredClone(WIDGETS_TYPED_SPEC);
    const response =
      spec.paths["/widgets/typed"].post.responses[200].content[
        "application/json"
      ];
    const schema = { ...response.schema, nullable: false };
    Object.assign(response, {
      schema: referenced ? { $ref: "#/components/schemas/Widget" } : schema,
    });
    Object.assign(spec, { components: { schemas: { Widget: schema } } });
    const payload = { id: "w1", name: "sprocket" };
    const fetchImpl = vi.fn<typeof fetch>(async () => Response.json(payload));
    const server = await fromOpenAPI({ fetch: fetchImpl, spec });
    const client = await connect(server);

    try {
      const { tools } = await client.listTools();
      expect(
        tools.find((tool) => tool.name === "createTypedWidget")?.outputSchema,
      ).toMatchObject({ properties: schema.properties, type: "object" });

      const result = await client.callTool({
        arguments: { name: "sprocket" },
        name: "createTypedWidget",
      });
      expect(result.isError).toBeFalsy();
      expect(result.structuredContent).toEqual(payload);
    } finally {
      await Promise.all(server.sessions.map((session) => session.close()));
      await client.close();
      await server.stop();
    }
  },
);

test("OpenAPI 3.0's boolean exclusive bounds validate input and keep tools/list and structured output working", async () => {
  const spec = structuredClone(WIDGETS_TYPED_SPEC);
  const operation = spec.paths["/widgets/typed"].post;
  Object.assign(
    operation.requestBody.content["application/json"].schema.properties,
    { price: { exclusiveMinimum: true, minimum: 0, type: "number" } },
  );
  Object.assign(
    operation.responses[200].content["application/json"].schema.properties,
    { price: { exclusiveMaximum: true, maximum: 100, type: "number" } },
  );
  const payload = { id: "w1", name: "sprocket", price: 5 };
  const fetchImpl = vi.fn<typeof fetch>(async () => Response.json(payload));
  const server = await fromOpenAPI({ fetch: fetchImpl, spec });
  const client = await connect(server);

  try {
    // The SDK client compiles every advertised output schema here, so a
    // boolean bound in any one of them used to make this call throw.
    const { tools } = await client.listTools();
    const tool = tools.find(({ name }) => name === "createTypedWidget");
    expect(tool?.inputSchema.properties?.price).toEqual({
      exclusiveMinimum: 0,
      type: "number",
    });
    expect(tool?.outputSchema?.properties?.price).toEqual({
      exclusiveMaximum: 100,
      type: "number",
    });

    await expect(
      client.callTool({
        arguments: { name: "sprocket", price: 0 },
        name: "createTypedWidget",
      }),
    ).rejects.toThrow(/must be > 0/);
    expect(fetchImpl).not.toHaveBeenCalled();

    const result = await client.callTool({
      arguments: { name: "sprocket", price: 5 },
      name: "createTypedWidget",
    });
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent).toEqual(payload);
  } finally {
    await Promise.all(server.sessions.map((session) => session.close()));
    await client.close();
    await server.stop();
  }
});

test("outputSchema: a schema-matching JSON response returns structuredContent", async () => {
  const fetchImpl = vi.fn<typeof fetch>(
    async () =>
      new Response(JSON.stringify({ id: "w1", name: "sprocket" }), {
        headers: { "content-type": "application/json" },
      }),
  );

  const server = await fromOpenAPI({
    fetch: fetchImpl,
    spec: WIDGETS_TYPED_SPEC,
  });
  const client = await connect(server);

  const { tools } = await client.listTools();
  expect(
    tools.find((tool) => tool.name === "createTypedWidget")?.outputSchema,
  ).toBeDefined();

  const result = await client.callTool({
    arguments: { name: "sprocket" },
    name: "createTypedWidget",
  });

  expect(result.isError).toBeFalsy();
  expect(result.structuredContent).toEqual({ id: "w1", name: "sprocket" });
});

test("outputSchema: a real response that doesn't match the wired schema falls back to plain text, not an error", async () => {
  const fetchImpl = vi.fn<typeof fetch>(
    async () =>
      new Response(JSON.stringify({ unexpected: true }), {
        headers: { "content-type": "application/json" },
      }),
  );

  const server = await fromOpenAPI({
    fetch: fetchImpl,
    spec: WIDGETS_TYPED_SPEC,
  });
  const client = await connect(server);

  const result = await client.callTool({
    arguments: { name: "sprocket" },
    name: "createTypedWidget",
  });

  expect(result.isError).toBeFalsy();
  expect(result.structuredContent).toBeUndefined();
  expect((result.content as { text: string }[])[0].text).toContain(
    "unexpected",
  );
});

test("outputSchema: an array-shaped response schema is never wired, and a real array response stays plain text", async () => {
  const fetchImpl = vi.fn<typeof fetch>(
    async () =>
      new Response(JSON.stringify(["a", "b"]), {
        headers: { "content-type": "application/json" },
      }),
  );

  const server = await fromOpenAPI({
    fetch: fetchImpl,
    spec: WIDGETS_TYPED_SPEC,
  });
  const client = await connect(server);

  const { tools } = await client.listTools();
  expect(
    tools.find((tool) => tool.name === "listTypedWidgets")?.outputSchema,
  ).toBeUndefined();

  const result = await client.callTool({
    arguments: {},
    name: "listTypedWidgets",
  });

  expect(result.isError).toBeFalsy();
  expect(result.structuredContent).toBeUndefined();
  expect((result.content as { text: string }[])[0].text).toContain("a");
});
