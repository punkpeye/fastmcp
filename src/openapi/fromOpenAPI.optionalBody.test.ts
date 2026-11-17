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

test.each(
  (["get", "head"] as const).flatMap((method) =>
    [
      "application/json",
      "application/x-www-form-urlencoded",
      "multipart/form-data",
    ].flatMap((contentType) =>
      [false, true].flatMap((required) =>
        [false, true].map((typedResponse) => ({
          contentType,
          method,
          required,
          typedResponse,
        })),
      ),
    ),
  ),
)(
  "$method ignores a $contentType request body (required=$required, typedResponse=$typedResponse)",
  async ({ contentType, method, required, typedResponse }) => {
    const requests: {
      body: string;
      contentType?: string;
      method?: string;
      url?: string;
    }[] = [];
    const upstream = createServer(async (request, response) => {
      let body = "";
      for await (const chunk of request) {
        body += chunk;
      }
      requests.push({
        body,
        contentType: request.headers["content-type"],
        method: request.method,
        url: request.url,
      });
      if (typedResponse) {
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({ exists: true }));
      } else {
        response.end();
      }
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
          info: { title: "Jobs API", version: "1.0.0" },
          openapi: "3.1.0",
          paths: {
            "/jobs/{id}": {
              [method]: {
                operationId: "probeJob",
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
                      schema: {
                        properties: { payload: { type: "string" } },
                        type: "object",
                      },
                    },
                  },
                  required,
                },
                responses: {
                  200: {
                    description: "OK",
                    ...(typedResponse
                      ? {
                          content: {
                            "application/json": {
                              schema: {
                                properties: { exists: { type: "boolean" } },
                                required: ["exists"],
                                type: "object",
                              },
                            },
                          },
                        }
                      : {}),
                  },
                },
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
      const result = await client.callTool({
        arguments: { id: "job-1", name: "nightly" },
        name: "probeJob",
      });
      expect(result.isError).not.toBe(true);
      expect(requests).toEqual([
        {
          body: "",
          contentType: undefined,
          method: method.toUpperCase(),
          url: "/jobs/job-1?name=nightly",
        },
      ]);
      const { tools } = await client.listTools();
      expect(Object.keys(tools[0].inputSchema.properties ?? {})).toEqual([
        "id",
        "name",
      ]);
      if (method === "head") {
        expect(result.content).toEqual([{ text: "", type: "text" }]);
        expect(tools[0].outputSchema).toBeUndefined();
        expect(result.structuredContent).toBeUndefined();
      } else if (typedResponse) {
        expect(result.structuredContent).toEqual({ exists: true });
      }
    } finally {
      await server?.sessions[0]?.close();
      await client.close();
      await server?.stop();
      upstream.closeAllConnections();
      await new Promise<void>((resolve, reject) => {
        upstream.close((error) => (error ? reject(error) : resolve()));
      });
    }
  },
);
