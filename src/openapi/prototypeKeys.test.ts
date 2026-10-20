import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { once } from "node:events";
import http from "node:http";
import { expect, test } from "vitest";

import { fromOpenAPI } from "./fromOpenAPI.js";

for (const location of ["path", "body"] as const) {
  test.each([false, true])(
    `preserves a ${location} __proto__ field through MCP and HTTP (collision=%s)`,
    async (collision) => {
      const received: { body?: unknown; url?: string }[] = [];
      const httpServer = http.createServer(async (request, response) => {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const body = Buffer.concat(chunks).toString();
        received.push({
          body: body ? JSON.parse(body) : undefined,
          url: request.url,
        });
        response.setHeader("content-type", "application/json");
        response.end("{}");
      });
      httpServer.listen(0, "127.0.0.1");
      await once(httpServer, "listening");
      const address = httpServer.address();
      if (!address || typeof address === "string")
        throw new Error("Expected TCP address");
      const baseAlias = `__proto____${location}`;
      const alias = collision ? `${baseAlias}_2` : baseAlias;
      const args = JSON.parse(
        `{"${alias}":"wire-value"${collision ? `,"${baseAlias}":"other-value"` : ""}}`,
      );
      const properties = JSON.parse(
        `{"__proto__":{"type":"string"}${collision ? `,"${baseAlias}":{"type":"string"}` : ""}}`,
      );
      const operation = {
        operationId: "send_item",
        ...(location === "path"
          ? {
              parameters: [
                {
                  in: "path",
                  name: "__proto__",
                  required: true,
                  schema: { type: "string" },
                },
                ...(collision
                  ? [
                      {
                        in: "query",
                        name: baseAlias,
                        schema: { type: "string" },
                      },
                    ]
                  : []),
              ],
            }
          : {
              requestBody: {
                content: {
                  "application/json": {
                    schema: {
                      properties,
                      required: ["__proto__"],
                      type: "object",
                    },
                  },
                },
                required: true,
              },
            }),
        responses: { "200": { description: "OK" } },
      };
      let server: Awaited<ReturnType<typeof fromOpenAPI>> | undefined;
      let client: Client | undefined;
      try {
        server = await fromOpenAPI({
          spec: {
            info: { title: "Prototype field fixture", version: "1" },
            openapi: "3.0.3",
            paths: {
              [location === "path" ? "/items/{__proto__}" : "/items"]: {
                post: operation,
              },
            },
            servers: [{ url: `http://127.0.0.1:${address.port}` }],
          },
        });
        const [clientTransport, serverTransport] =
          InMemoryTransport.createLinkedPair();
        client = new Client({ name: "test-client", version: "1" });
        await Promise.all([
          server.connect(serverTransport),
          client.connect(clientTransport),
        ]);
        const result = await client.callTool({
          arguments: args,
          name: "send_item",
        });
        expect(result.isError).not.toBe(true);
        expect(received).toHaveLength(1);
        if (location === "path") {
          expect(received[0].url).toBe(
            `/items/wire-value${collision ? `?${baseAlias}=other-value` : ""}`,
          );
        } else {
          expect(received[0].body).toEqual(
            JSON.parse(
              `{"__proto__":"wire-value"${collision ? `,"${baseAlias}":"other-value"` : ""}}`,
            ),
          );
          expect(Object.hasOwn(received[0].body as object, "__proto__")).toBe(
            true,
          );
        }
        const tools = await client.listTools();
        expect(
          Object.hasOwn(tools.tools[0].inputSchema.properties!, alias),
        ).toBe(true);
      } finally {
        await client?.close();
        await server?.stop();
        httpServer.closeAllConnections();
        await new Promise<void>((resolve) => httpServer.close(() => resolve()));
      }
    },
  );
}
