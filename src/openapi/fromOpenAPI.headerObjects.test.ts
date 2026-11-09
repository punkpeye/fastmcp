import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { once } from "node:events";
import { createServer } from "node:http";
import { expect, test } from "vitest";

import type { FastMCP } from "../FastMCP.js";

import { fromOpenAPI } from "./fromOpenAPI.js";

test.each([
  [undefined, undefined, false],
  ["simple", false, false],
  ["simple", true, false],
  [undefined, undefined, true],
  ["simple", false, true],
  ["simple", true, true],
] as const)(
  "object headers reach HTTP intact: style=%s explode=%s referenced=%s",
  async (style, explode, referenced) => {
    const expected = explode
      ? "active=false,count=0,name=caf%C3%A9%2Ctea%3Dgreen"
      : "active,false,count,0,name,caf%C3%A9%2Ctea%3Dgreen";
    const requests: { header?: string | string[]; url?: string }[] = [];
    const upstream = createServer((request, response) => {
      requests.push({ header: request.headers["x-filter"], url: request.url });
      response.statusCode =
        request.headers["x-filter"] === expected ? 200 : 400;
      response.end(response.statusCode === 200 ? "matched" : "invalid filter");
    });
    const client = new Client({ name: "test-client", version: "1.0.0" });
    let server: FastMCP | undefined;

    try {
      upstream.listen(0, "127.0.0.1");
      await once(upstream, "listening");
      const address = upstream.address();
      if (!address || typeof address === "string") {
        throw new Error("Expected a TCP listener");
      }
      const parameter = {
        ...(explode === undefined ? {} : { explode }),
        in: "header",
        name: "X-Filter",
        required: true,
        schema: {
          properties: {
            active: { type: "boolean" },
            count: { type: "integer" },
            name: { type: "string" },
          },
          required: ["active", "count", "name"],
          type: "object",
        },
        ...(style === undefined ? {} : { style }),
      };
      server = await fromOpenAPI({
        baseUrl: `http://127.0.0.1:${address.port}`,
        resources: true,
        spec: {
          components: { parameters: { Filter: parameter } },
          info: { title: "Header API", version: "1.0.0" },
          openapi: "3.0.4",
          paths: {
            "/items": {
              get: {
                operationId: "listItems",
                parameters: [
                  referenced
                    ? { $ref: "#/components/parameters/Filter" }
                    : parameter,
                  { in: "query", name: "X-Filter", schema: { type: "string" } },
                ],
                responses: { 200: { description: "OK" } },
              },
            },
          },
        },
      });
      const [clientTransport, serverTransport] =
        InMemoryTransport.createLinkedPair();
      await Promise.all([
        server.connect(serverTransport),
        client.connect(clientTransport),
      ]);
      const { tools } = await client.listTools();
      expect(tools.map((tool) => tool.name)).toEqual(["listItems"]);

      const result = await client.callTool({
        arguments: {
          "X-Filter__header": {
            active: false,
            count: 0,
            name: "café,tea=green",
          },
          "X-Filter__query": "query value",
        },
        name: "listItems",
      });

      expect(requests).toEqual([
        { header: expected, url: "/items?X-Filter=query+value" },
      ]);
      expect(result.isError).not.toBe(true);
      expect(result.content).toEqual([{ text: "matched", type: "text" }]);
    } finally {
      await client.close();
      await server?.stop();
      upstream.closeAllConnections();
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
    }
  },
);
