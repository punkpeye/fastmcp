import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";

import { EdgeFastMCP } from "./edge/index.js";
import { FastMCP, UserError } from "./FastMCP.js";

const info = { name: "load-errors", version: "1.0.0" as const };

// A handler may delegate to another MCP server and receive an McpError.
// Keep the code and data so its caller can handle the same failure.
describe.each(["core", "edge"])("%s load errors", (runtime) => {
  it.each([
    new McpError(ErrorCode.InvalidParams, "Unknown account", { account: "42" }),
    new UserError("Account is unavailable"),
    new Error("Upstream is unavailable"),
  ])("preserves $name from resources and prompts", async (error) => {
    const server =
      runtime === "core" ? new FastMCP(info) : new EdgeFastMCP(info);
    const load = async (): Promise<never> => {
      throw error;
    };
    server.addResource({ load, name: "account", uri: "account://42" });
    server.addPrompt({ load, name: "account" });
    if (server instanceof FastMCP) {
      server.addResourceTemplate({
        arguments: [{ name: "id" }],
        load,
        name: "accounts",
        uriTemplate: "account://{id}",
      });
    }
    const client = new Client(info);
    if (server instanceof FastMCP) {
      const [clientTransport, serverTransport] =
        InMemoryTransport.createLinkedPair();
      await Promise.all([
        server.connect(serverTransport),
        client.connect(clientTransport),
      ]);
    } else {
      await client.connect(
        new StreamableHTTPClientTransport(new URL("https://edge.example/mcp"), {
          fetch: async (input, init) => server.fetch(new Request(input, init)),
        }),
      );
    }
    try {
      const calls = [
        () => client.readResource({ uri: "account://42" }),
        () => client.getPrompt({ name: "account" }),
      ];
      if (server instanceof FastMCP) {
        calls.push(() => client.readResource({ uri: "account://43" }));
      }
      for (const call of calls) {
        await expect.soft(call()).rejects.toMatchObject({
          code:
            error instanceof McpError ? error.code : ErrorCode.InternalError,
          ...(error instanceof McpError && { data: error.data }),
          message: expect.stringContaining(error.message),
        });
      }
    } finally {
      await client.close();
      if (server instanceof FastMCP) {
        await server.stop();
      }
    }
  });
});
