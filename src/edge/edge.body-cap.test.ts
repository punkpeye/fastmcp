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

  const bytes = new TextEncoder().encode(body);

  return new Request("http://localhost/mcp", {
    body: chunked
      ? new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(bytes);
            controller.close();
          },
        })
      : bytes,
    duplex: "half",
    headers: {
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
      // A Request sets no Content-Length of its own, even for a fixed body.
      ...(!chunked && { "Content-Length": String(bytes.byteLength) }),
    },
    method: "POST",
  } as RequestInit);
};

describe("EdgeFastMCP POST body size cap", () => {
  it("rejects an oversized body that declares its Content-Length", async () => {
    const server = new EdgeFastMCP({ name: "test", version: "1.0.0" });
    const request = oversizedRequest(false);

    const response = await server.fetch(request);

    expect(response.status).toBe(413);
    expect(await response.json()).toMatchObject({
      error: { code: -32000 },
      jsonrpc: "2.0",
    });
    // Refused on the header alone, before any of the body was read.
    expect(request.bodyUsed).toBe(false);
  });

  it("rejects an oversized body that arrives without a Content-Length header", async () => {
    const server = new EdgeFastMCP({ name: "test", version: "1.0.0" });
    const request = oversizedRequest(true);
    expect(request.headers.get("content-length")).toBeNull();

    const response = await server.fetch(request);

    expect(response.status).toBe(413);
  });
});
