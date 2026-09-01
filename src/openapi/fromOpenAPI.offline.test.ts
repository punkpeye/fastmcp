import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
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
