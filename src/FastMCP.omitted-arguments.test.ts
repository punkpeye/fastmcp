import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { expect, it } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

/**
 * `params.arguments` is optional in the MCP request schema, so a conformant
 * client may omit it. Zod rejects `undefined` for an object schema even when
 * every property is optional, so the raw value cannot go to the validator.
 */
const connect = async (server: FastMCP) => {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });

  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);

  return client;
};

it("accepts a tools/call that omits params.arguments", async () => {
  const server = new FastMCP({ name: "Test", version: "1.0.0" });

  server.addTool({
    execute: async (args) => `ok:${JSON.stringify(args)}`,
    name: "all_optional",
    parameters: z.object({ verbose: z.boolean().optional() }),
  });

  server.addTool({
    execute: async (args) => `ok:${JSON.stringify(args)}`,
    name: "empty_object",
    parameters: z.object({}),
  });

  const client = await connect(server);

  // client.callTool always sends `arguments`, so the raw request is the only
  // way to leave the key out entirely, which is what a conformant client may do.
  for (const name of ["all_optional", "empty_object"]) {
    const result = await client.request(
      { method: "tools/call", params: { name } },
      CallToolResultSchema,
    );

    expect(result.content).toEqual([{ text: "ok:{}", type: "text" }]);
  }
});
