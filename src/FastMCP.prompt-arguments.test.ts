import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";

import { FastMCP } from "./FastMCP.js";

async function connect(server: FastMCP) {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "c", version: "0.0.0" });
  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);
  return client;
}

describe("prompts/get with a missing required argument", () => {
  it("answers -32602 Invalid params, as the spec requires", async () => {
    const server = new FastMCP({ name: "T", version: "1.0.0" });
    server.addPrompt({
      arguments: [
        { description: "Changes to commit", name: "changes", required: true },
      ],
      load: async ({ changes }) => `Commit: ${changes}`,
      name: "git-commit",
    });
    const client = await connect(server);
    try {
      await expect(client.getPrompt({ name: "git-commit" })).rejects.toEqual(
        expect.objectContaining({
          code: ErrorCode.InvalidParams,
          message: expect.stringContaining("requires argument 'changes'"),
        }),
      );
      await expect(
        client.getPrompt({ name: "git-commit" }),
      ).rejects.toBeInstanceOf(McpError);

      // The same request with the argument present still works.
      const result = await client.getPrompt({
        arguments: { changes: "add tests" },
        name: "git-commit",
      });
      expect(result.messages[0]?.content).toEqual({
        text: "Commit: add tests",
        type: "text",
      });
    } finally {
      await client.close();
      await server.stop();
    }
  });
});
