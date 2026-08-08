import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { LATEST_PROTOCOL_VERSION } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";

import { WebStreamableHTTPServerTransport } from "./WebStreamableHTTPServerTransport.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type JsonResponse = any;

const createInitializeRequest = (accept: string) =>
  new Request("http://localhost/mcp", {
    body: JSON.stringify({
      id: 1,
      jsonrpc: "2.0",
      method: "initialize",
      params: {
        capabilities: {},
        clientInfo: { name: "test-client", version: "1.0.0" },
        protocolVersion: LATEST_PROTOCOL_VERSION,
      },
    }),
    headers: {
      Accept: accept,
      "Content-Type": "application/json",
    },
    method: "POST",
  });

const createServer = () =>
  new Server({ name: "TestServer", version: "1.0.0" }, { capabilities: {} });

describe("WebStreamableHTTPServerTransport", () => {
  it("should deliver the response on the SSE stream", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      sessionIdGenerator: () => "test-session",
    });
    await createServer().connect(transport);

    const response = await transport.handleRequest(
      createInitializeRequest("application/json, text/event-stream"),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");

    // The SDK produces the response asynchronously; the stream must deliver
    // it and then close instead of hanging forever.
    const stream = response.body;
    expect(stream).not.toBeNull();
    if (!stream) {
      throw new Error("Expected an SSE stream body");
    }

    const readBody = async (): Promise<string> => {
      const reader = stream.getReader();
      const decoder = new TextDecoder();
      let text = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        text += decoder.decode(value, { stream: true });
      }
      return text;
    };

    const body = await Promise.race([
      readBody(),
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 2000)),
    ]);

    expect(body).not.toBeNull();
    expect(body).toContain("data: ");
    expect(body).toContain('"serverInfo"');
    expect(body).toContain("TestServer");
  });

  it("should respond with JSON when enableJsonResponse is set", async () => {
    const transport = new WebStreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => "test-session",
    });
    await createServer().connect(transport);

    const response = await transport.handleRequest(
      createInitializeRequest("application/json"),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.jsonrpc).toBe("2.0");
    expect(body.id).toBe(1);
    expect(body.result.serverInfo.name).toBe("TestServer");
  });
});
