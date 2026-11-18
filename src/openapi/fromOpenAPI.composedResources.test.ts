import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { once } from "node:events";
import { createServer } from "node:http";
import { expect, test } from "vitest";

import { fromOpenAPI } from "./fromOpenAPI.js";

test.each(["anyOf", "oneOf", "allOf"] as const)(
  "%s object parameters preserve their HTTP representation with resources enabled",
  async (composition) => {
    const expected =
      "/items?filter%5Bowner%5D=alice+%26+bob&filter%5Bstatus%5D=active";
    const requests: string[] = [];
    const upstream = createServer((request, response) => {
      requests.push(request.url ?? "");
      response.statusCode = request.url === expected ? 200 : 400;
      response.end(response.statusCode === 200 ? "matched" : "invalid filter");
    });
    upstream.listen(0, "127.0.0.1");
    await once(upstream, "listening");
    const address = upstream.address();
    if (!address || typeof address === "string") {
      throw new Error("Expected a TCP listener");
    }

    try {
      for (const resources of [false, true]) {
        const filter = {
          properties: {
            owner: { type: "string" },
            status: { type: "string" },
          },
          required: ["owner", "status"],
          type: "object",
        };
        const schema = {
          [composition]:
            composition === "allOf" ? [filter] : [filter, { type: "null" }],
        };
        const server = await fromOpenAPI({
          baseUrl: `http://127.0.0.1:${address.port}`,
          resources,
          spec: {
            info: { title: "Composed parameters", version: "1.0.0" },
            openapi: "3.1.0",
            paths: {
              "/items": {
                get: {
                  operationId: "listItems",
                  parameters: [
                    {
                      explode: true,
                      in: "query",
                      name: "filter",
                      required: true,
                      schema,
                      style: "deepObject",
                    },
                  ],
                  responses: { 200: { description: "OK" } },
                },
              },
            },
          },
        });
        const client = new Client({ name: "test-client", version: "1.0.0" });
        const [clientTransport, serverTransport] =
          InMemoryTransport.createLinkedPair();
        try {
          await Promise.all([
            server.connect(serverTransport),
            client.connect(clientTransport),
          ]);
          const { tools } = client.getServerCapabilities()?.tools
            ? await client.listTools()
            : { tools: [] };
          expect(tools.map((tool) => tool.name)).toEqual(["listItems"]);
          const result = await client.callTool({
            arguments: { filter: { owner: "alice & bob", status: "active" } },
            name: "listItems",
          });
          expect(result.isError).toBeFalsy();
          expect(result.content).toEqual([{ text: "matched", type: "text" }]);
          expect(requests.at(-1), `resources=${resources}`).toBe(expected);
        } finally {
          await client.close();
          await server.stop();
        }
      }
      expect(requests).toEqual([expected, expected]);
    } finally {
      upstream.closeAllConnections();
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
    }
  },
);
