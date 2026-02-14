import { LATEST_PROTOCOL_VERSION } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { EdgeFastMCP } from "./index.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type JsonResponse = any;

describe("EdgeFastMCP", () => {
  it("should handle initialize request", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    const response = await server.fetch(
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
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.jsonrpc).toBe("2.0");
    expect(body.id).toBe(1);
    expect(body.result.serverInfo.name).toBe("TestServer");
    expect(body.result.serverInfo.version).toBe("1.0.0");
  });

  it("should list tools", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    server.addTool({
      description: "Greet someone",
      execute: async ({ name }) => `Hello, ${name}!`,
      name: "greet",
      parameters: z.object({ name: z.string() }),
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 2,
          jsonrpc: "2.0",
          method: "tools/list",
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.result.tools).toHaveLength(1);
    expect(body.result.tools[0].name).toBe("greet");
    expect(body.result.tools[0].description).toBe("Greet someone");
  });

  it("should call a tool", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    server.addTool({
      description: "Greet someone",
      execute: async ({ name }) => `Hello, ${name}!`,
      name: "greet",
      parameters: z.object({ name: z.string() }),
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 3,
          jsonrpc: "2.0",
          method: "tools/call",
          params: {
            arguments: { name: "World" },
            name: "greet",
          },
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.result.content).toEqual([
      { text: "Hello, World!", type: "text" },
    ]);
  });

  it("should list resources", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    server.addResource({
      description: "A test resource",
      load: async () => "Test content",
      mimeType: "text/plain",
      name: "Test Resource",
      uri: "test://resource",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 4,
          jsonrpc: "2.0",
          method: "resources/list",
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.result.resources).toHaveLength(1);
    expect(body.result.resources[0].uri).toBe("test://resource");
  });

  it("should read a resource", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    server.addResource({
      load: async () => "Test content",
      name: "Test Resource",
      uri: "test://resource",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 5,
          jsonrpc: "2.0",
          method: "resources/read",
          params: { uri: "test://resource" },
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.result.contents[0].text).toBe("Test content");
  });

  it("should list prompts", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    server.addPrompt({
      arguments: [
        { description: "First argument", name: "arg1", required: true },
      ],
      description: "A test prompt",
      load: async (args) => `Prompt with ${args.arg1}`,
      name: "test_prompt",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 6,
          jsonrpc: "2.0",
          method: "prompts/list",
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.result.prompts).toHaveLength(1);
    expect(body.result.prompts[0].name).toBe("test_prompt");
  });

  it("should get a prompt", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    server.addPrompt({
      description: "A test prompt",
      load: async (args) => `Prompt with ${args.value ?? "default"}`,
      name: "test_prompt",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 7,
          jsonrpc: "2.0",
          method: "prompts/get",
          params: { arguments: { value: "test" }, name: "test_prompt" },
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.result.messages[0].content.text).toBe("Prompt with test");
  });

  it("should handle health check", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    const response = await server.fetch(new Request("http://localhost/health"));

    expect(response.status).toBe(200);
    const body = await response.text();
    expect(body).toContain("Ok");
  });

  it("should handle ping", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({
          id: 8,
          jsonrpc: "2.0",
          method: "ping",
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
    const body: JsonResponse = await response.json();
    expect(body.result).toEqual({});
  });

  it("should return error for invalid JSON", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: "not json",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(400);
    const body: JsonResponse = await response.json();
    expect(body.error.code).toBe(-32700);
  });

  it("should return 406 for wrong Accept header", async () => {
    const server = new EdgeFastMCP({
      name: "TestServer",
      version: "1.0.0",
    });

    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        body: JSON.stringify({}),
        headers: {
          Accept: "text/html",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(406);
  });

  it("should allow custom MCP path", async () => {
    const server = new EdgeFastMCP({
      mcpPath: "/api/mcp",
      name: "TestServer",
      version: "1.0.0",
    });

    const response = await server.fetch(
      new Request("http://localhost/api/mcp", {
        body: JSON.stringify({
          id: 1,
          jsonrpc: "2.0",
          method: "ping",
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(200);
  });
});
