import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { once } from "node:events";
import { createServer } from "node:http";
import { expect, test, vi } from "vitest";

import { fromOpenAPI } from "./fromOpenAPI.js";

test.each([
  ["cancel", "headers"],
  ["cancel", "body"],
  ["close", "headers"],
  ["close", "body"],
])("%s stops an OpenAPI request waiting for %s", async (ending, stage) => {
  const requestStarted = Promise.withResolvers<void>();
  const responseStarted = Promise.withResolvers<void>();
  let responseClosed = false;
  const upstream = createServer((request, response) => {
    if (request.url === "/ready") {
      response.end("ready");
      return;
    }
    response.once("close", () => {
      responseClosed = true;
    });
    if (stage === "body") {
      response.writeHead(200, { "content-type": "text/plain" });
      response.write("partial");
    }
    requestStarted.resolve();
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  const address = upstream.address();
  if (!address || typeof address === "string") {
    throw new Error("Expected a TCP listener");
  }

  const server = await fromOpenAPI({
    baseUrl: `http://127.0.0.1:${address.port}`,
    fetch: async (input, init) => {
      const response = await fetch(input, init);
      responseStarted.resolve();
      return response;
    },
    spec: {
      info: { title: "Cancellation test", version: "1.0.0" },
      openapi: "3.0.3",
      paths: {
        "/ready": {
          get: {
            operationId: "ready",
            responses: { 200: { description: "Ready" } },
          },
        },
        "/slow": {
          get: {
            operationId: "slow",
            responses: { 200: { description: "Slow response" } },
          },
        },
      },
    },
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "1.0.0" });

  try {
    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);
    const cancel = new AbortController();
    const call = client
      .callTool({ name: "slow" }, undefined, { signal: cancel.signal })
      .catch(() => "stopped");

    await requestStarted.promise;
    if (stage === "body") {
      await responseStarted.promise;
    }
    expect(responseClosed).toBe(false);
    if (ending === "cancel") {
      cancel.abort();
    } else {
      await client.close();
    }
    await expect(call).resolves.toBe("stopped");
    await vi.waitFor(() => expect(responseClosed).toBe(true), {
      timeout: 2000,
    });

    if (ending === "cancel") {
      await expect(client.callTool({ name: "ready" })).resolves.toEqual({
        content: [{ text: "ready", type: "text" }],
      });
    }
  } finally {
    await client.close();
    await server.stop();
    upstream.closeAllConnections();
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  }
});
