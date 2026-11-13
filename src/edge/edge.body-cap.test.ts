import { describe, expect, it } from "vitest";

import { EdgeFastMCP } from "./index.js";

const MiB = 1024 * 1024;

const oversizedRequest = (chunked: boolean): Request => {
  // 8 MiB of padding inside a valid JSON-RPC request, twice the 4 MiB cap the
  // edge transport enforces.
  const body = JSON.stringify({
    id: 1,
    jsonrpc: "2.0",
    method: "tools/list",
    params: { padding: "A".repeat(8 * MiB) },
  });

  return new Request("http://localhost/mcp", {
    body: chunked
      ? new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode(body));
            controller.close();
          },
        })
      : body,
    duplex: "half",
    headers: {
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
    },
    method: "POST",
  } as RequestInit);
};

describe("EdgeFastMCP POST body size cap", () => {
  it("rejects an oversized body that declares its Content-Length", async () => {
    const server = new EdgeFastMCP({ name: "test", version: "1.0.0" });

    const response = await server.fetch(oversizedRequest(false));

    expect(response.status).toBe(413);
    expect(await response.json()).toMatchObject({
      error: { code: -32000 },
      jsonrpc: "2.0",
    });
  });

  it("rejects an oversized body that arrives without a Content-Length header", async () => {
    const server = new EdgeFastMCP({ name: "test", version: "1.0.0" });
    const request = oversizedRequest(true);
    expect(request.headers.get("content-length")).toBeNull();

    const response = await server.fetch(request);

    expect(response.status).toBe(413);
  });
});
