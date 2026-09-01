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
