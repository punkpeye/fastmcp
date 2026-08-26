/**
 * RED: handlePostRequest caps the body only by trusting the Content-Length
 * header. A streamed (chunked) POST carries no Content-Length, so the header
 * reads as "0", the 4 MiB check passes, and `request.json()` buffers the whole
 * body into memory unbounded.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { describe, expect, it } from "vitest";

import { WebStreamableHTTPServerTransport } from "./WebStreamableHTTPServerTransport.js";

const MiB = 1024 * 1024;

describe("POST body size cap", () => {
  it("rejects an oversized body that arrives without a Content-Length header", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });
    const server = new Server(
      { name: "TestServer", version: "1.0.0" },
      { capabilities: {} },
    );
    await server.connect(transport);

    // 8 MiB of padding inside a syntactically valid JSON-RPC notification,
    // i.e. double the documented 4 MiB maximum.
    const padding = "A".repeat(8 * MiB);
    const body = JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: { padding },
    });

    // A ReadableStream body is sent chunked: fetch/Request sets no
    // Content-Length for it, which is exactly what a streaming client does.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(body));
        controller.close();
      },
    });

    const request = new Request("http://localhost/mcp", {
      body: stream,
      duplex: "half",
      headers: {
        Accept: "application/json, text/event-stream",
        "Content-Type": "application/json",
      },
      method: "POST",
    });

    expect(request.headers.get("content-length")).toBeNull();

    const response = await transport.handleRequest(request);

    expect(response.status).toBe(413);
  });
});
