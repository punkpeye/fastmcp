import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { once } from "node:events";
import { createServer } from "node:http";
import { expect, test } from "vitest";

import type { FastMCP } from "../FastMCP.js";

import { jsonSchemaAdapter } from "../jsonSchemaAdapter.js";
import { fromOpenAPI } from "./fromOpenAPI.js";
import { buildFlatSchema } from "./schemas.js";

test.each([
  ["application/json", undefined, false],
  ["application/json", false, false],
  ["application/json", true, false],
  ["application/json", false, true],
  ["application/x-www-form-urlencoded", undefined, false],
  ["application/x-www-form-urlencoded", false, false],
  ["application/x-www-form-urlencoded", true, false],
  ["application/x-www-form-urlencoded", false, true],
] as const)(
  "%s body required=%s referenced=%s preserves omission and property requirements",
  async (contentType, required, referenced) => {
    const bodySchema = {
      properties: {
        enabled: { type: "boolean" },
        mode: { type: "string" },
        name: { type: "string" },
      },
      required: ["name", "mode"],
      type: "object",
    };
    const requests: { body: string; contentType?: string; url?: string }[] = [];
    const upstream = createServer(async (request, response) => {
      let body = "";
      for await (const chunk of request) {
        body += chunk;
      }
      requests.push({
        body,
        contentType: request.headers["content-type"],
        url: request.url,
      });
      response.end(body || "saved options");
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

      server = await fromOpenAPI({
        baseUrl: `http://127.0.0.1:${address.port}`,
        spec: {
          components: {
            schemas: { Options: bodySchema },
          },
          info: { title: "Job API", version: "1.0.0" },
          openapi: "3.0.3",
          paths: {
            "/jobs/{id}": {
              post: {
                operationId: "runJob",
                parameters: [
                  {
                    in: "path",
                    name: "id",
                    required: true,
                    schema: { type: "string" },
                  },
                  {
                    in: "query",
                    name: "name",
                    required: true,
                    schema: { type: "string" },
                  },
                ],
                requestBody: {
                  content: {
                    [contentType]: {
                      schema: referenced
                        ? { $ref: "#/components/schemas/Options" }
                        : bodySchema,
                    },
                  },
                  ...(required === undefined ? {} : { required }),
                },
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
      const advertised = jsonSchemaAdapter(tools[0].inputSchema)["~standard"];
      const wholeBody = referenced && contentType === "application/json";
      const parameters = {
        id: "job-1",
        [wholeBody ? "name" : "name__query"]: "query name",
      };

      const omitted = await client.callTool({
        arguments: parameters,
        name: "runJob",
      });
      if (required) {
        expect(omitted.isError).toBe(true);
        expect((await advertised.validate(parameters)).issues).toBeDefined();
        expect(requests).toHaveLength(0);
      } else {
        expect(omitted.isError).not.toBe(true);
        expect((await advertised.validate(parameters)).issues).toBeUndefined();
        expect(requests).toEqual([
          {
            body: "",
            contentType: undefined,
            url: "/jobs/job-1?name=query+name",
          },
        ]);
      }

      const bodyArgs = (body: Record<string, unknown>) =>
        wholeBody ? { body } : body;
      const requestCount = requests.length;
      for (const args of [
        { ...parameters, ...bodyArgs({ enabled: false }) },
        { ...parameters, ...bodyArgs({ name: "body name" }) },
        { ...parameters, ...bodyArgs({ mode: "fast", name: 42 }) },
        {
          ...parameters,
          ...bodyArgs({ mode: "fast", name: "body name" }),
          id: undefined,
        },
        {
          ...parameters,
          ...bodyArgs({ mode: "fast", name: "body name" }),
          [wholeBody ? "name" : "name__query"]: undefined,
        },
      ]) {
        expect((await advertised.validate(args)).issues).toBeDefined();
        expect(
          (await client.callTool({ arguments: args, name: "runJob" })).isError,
        ).toBe(true);
        expect(requests).toHaveLength(requestCount);
      }

      const complete = {
        ...parameters,
        ...bodyArgs({ enabled: false, mode: "fast", name: "body name" }),
      };
      expect((await advertised.validate(complete)).issues).toBeUndefined();
      expect(
        (await client.callTool({ arguments: complete, name: "runJob" }))
          .isError,
      ).not.toBe(true);
      expect(requests.at(-1)).toEqual({
        body:
          contentType === "application/json"
            ? '{"enabled":false,"mode":"fast","name":"body name"}'
            : "enabled=false&mode=fast&name=body+name",
        contentType,
        url: "/jobs/job-1?name=query+name",
      });
    } finally {
      await client.close();
      await server?.stop();
      upstream.closeAllConnections();
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
    }
  },
);

test("optional body requirements follow aliased property names", async () => {
  const { flatSchema } = buildFlatSchema(
    {
      deprecated: false,
      method: "post",
      parameters: [
        { in: "query", name: "__proto____body", schema: { type: "string" } },
      ],
      path: "/options",
      requestBody: {
        content: {
          "application/json": {
            schema: {
              properties: {
                ["__proto__"]: { type: "string" },
                enabled: { type: "boolean" },
              },
              required: ["__proto__"],
              type: "object",
            },
          },
        },
      },
      tags: [],
    },
    undefined,
  );
  const schema = jsonSchemaAdapter(flatSchema)["~standard"];
  expect(
    (await schema.validate({ __proto____body: "query" })).issues,
  ).toBeUndefined();
  expect(
    (await schema.validate({ __proto____body: "query", enabled: false }))
      .issues,
  ).toBeDefined();
  expect(
    (await schema.validate({ __proto____body_2: "body", enabled: false }))
      .issues,
  ).toBeUndefined();
});
