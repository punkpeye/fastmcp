import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { once } from "node:events";
import { createServer } from "node:http";
import { expect, test } from "vitest";

import { fromOpenAPI } from "./fromOpenAPI.js";

test.each([false, true])(
  "binary resource reads preserve HTTP response bytes (template: %s)",
  async (template) => {
    const bytes = Buffer.from([0, 0x7f, 0x80, 0xff, 0xc3, 0x28]);
    const requests: string[] = [];
    const upstream = createServer((request, response) => {
      requests.push(request.url ?? "");
      response.setHeader("Content-Type", "application/octet-stream");
      response.end(bytes);
    });
    upstream.listen(0, "127.0.0.1");
    await once(upstream, "listening");
    const address = upstream.address();
    if (!address || typeof address === "string") {
      throw new Error("Expected a TCP listener");
    }

    const path = template ? "/files/{id}" : "/files";
    const server = await fromOpenAPI({
      resources: true,
      spec: {
        info: { title: "Downloads", version: "1.0.0" },
        openapi: "3.0.3",
        paths: {
          [path]: {
            get: {
              operationId: "download",
              parameters: template
                ? [
                    {
                      in: "path",
                      name: "id",
                      required: true,
                      schema: { type: "string" },
                    },
                  ]
                : [],
              responses: {
                200: {
                  content: {
                    "application/octet-stream": {
                      schema: { format: "binary", type: "string" },
                    },
                  },
                  description: "File bytes",
                },
              },
            },
          },
        },
        servers: [{ url: `http://127.0.0.1:${address.port}` }],
      },
    });
    const client = new Client({ name: "binary-test", version: "1.0.0" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();

    try {
      await Promise.all([
        server.connect(serverTransport),
        client.connect(clientTransport),
      ]);
      const uri = template
        ? "openapi://download/files/sample"
        : "openapi://download/files";
      const result = await client.readResource({ uri });
      expect(result.contents).toEqual([
        { blob: "AH+A/8Mo", mimeType: "application/octet-stream", uri },
      ]);
      expect(requests).toEqual([template ? "/files/sample" : "/files"]);
      expect(await server.embedded(uri)).toEqual({
        blob: "AH+A/8Mo",
        mimeType: "application/octet-stream",
        uri,
      });
    } finally {
      await Promise.all(server.sessions.map((session) => session.close()));
      await client.close();
      await server.stop();
      upstream.closeAllConnections();
      await new Promise<void>((resolve, reject) => {
        upstream.close((error) => (error ? reject(error) : resolve()));
      });
    }
  },
);

test.each([
  ["image/png", "image/png"],
  ["application/pdf", "application/pdf"],
  ["application/vnd.example.download", "application/vnd.example.download"],
  ["Application/Octet-Stream; filename=sample.bin", "application/octet-stream"],
])(
  "binary resources use the HTTP media type %s",
  async (contentType, mimeType) => {
    const content = await readResource(
      new Response(new Uint8Array([0, 0x7f, 0x80, 0xff, 0xc3, 0x28]), {
        headers: { "content-type": contentType },
      }),
    );
    expect(content).toEqual({
      blob: "AH+A/8Mo",
      mimeType,
      uri: "openapi://download/files",
    });
  },
);

test("an empty binary response is still a blob", async () => {
  expect(
    await readResource(
      new Response(null, { headers: { "content-type": "image/png" } }),
    ),
  ).toEqual({
    blob: "",
    mimeType: "image/png",
    uri: "openapi://download/files",
  });
});

test.each([
  ["text/plain; charset=utf-8", "Hello 世界", "text/plain", "Hello 世界"],
  ["text/csv", "id,name\n1,example", "text/plain", "id,name\n1,example"],
  ["application/json", '{"ok":true}', "application/json", '{\n  "ok": true\n}'],
  [
    "application/problem+json",
    '{"status":200}',
    "application/json",
    '{\n  "status": 200\n}',
  ],
  ["application/xml", "<ok/>", "text/plain", "<ok/>"],
  ["image/svg+xml", "<svg/>", "text/plain", "<svg/>"],
  ["application/javascript", "console.log(1)", "text/plain", "console.log(1)"],
  ["application/x-www-form-urlencoded", "a=1&b=2", "text/plain", "a=1&b=2"],
  ["application/json", "invalid JSON", "text/plain", "invalid JSON"],
  [
    "application/x-json",
    '{"ok":true}',
    "application/json",
    '{\n  "ok": true\n}',
  ],
  ["application/x-json", "invalid JSON", "text/plain", "invalid JSON"],
  [
    "application/x-ndjson",
    '{"ok":true}',
    "application/json",
    '{\n  "ok": true\n}',
  ],
  [
    "application/x-ndjson",
    '{"ok":true}\n{"ok":false}',
    "text/plain",
    '{"ok":true}\n{"ok":false}',
  ],
  [
    "application/x-javascript",
    "console.log(1)",
    "text/plain",
    "console.log(1)",
  ],
  ["application/ecmascript", "console.log(1)", "text/plain", "console.log(1)"],
  [
    "application/x-ecmascript",
    "console.log(1)",
    "text/plain",
    "console.log(1)",
  ],
  ["application/x-xml", "<ok/>", "text/plain", "<ok/>"],
  [undefined, '{"ok":true}', "application/json", '{"ok":true}'],
  [undefined, "Hello 世界", "text/plain", "Hello 世界"],
  [undefined, "", "text/plain", ""],
])(
  "text resource behavior is preserved for %s (%s)",
  async (contentType, body, mimeType, text) => {
    const content = await readResource(
      new Response(new TextEncoder().encode(body), {
        headers: contentType ? { "content-type": contentType } : {},
      }),
    );
    expect(content).toEqual({
      mimeType,
      text,
      uri: "openapi://download/files",
    });
  },
);

test("a binary response's HTTP error is reported before returning its contents", async () => {
  await expect(
    readResource(
      new Response("download unavailable", {
        headers: { "content-type": "application/octet-stream" },
        status: 404,
      }),
    ),
  ).rejects.toThrow("GET /files failed with 404: download unavailable");
});

async function readResource(response: Response) {
  const server = await fromOpenAPI({
    fetch: async () => response,
    resources: true,
    spec: {
      info: { title: "Downloads", version: "1.0.0" },
      openapi: "3.1.0",
      paths: {
        "/files": {
          get: {
            operationId: "download",
            responses: { 200: { description: "Download" } },
          },
        },
      },
      servers: [{ url: "https://api.example.com" }],
    },
  });
  const client = new Client({ name: "binary-test", version: "1.0.0" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);
    const result = await client.readResource({
      uri: "openapi://download/files",
    });
    return result.contents[0];
  } finally {
    await Promise.all(server.sessions.map((session) => session.close()));
    await client.close();
    await server.stop();
  }
}
