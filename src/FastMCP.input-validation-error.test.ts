import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { expect, it } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

async function exercise(server: FastMCP | McpServer) {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "client", version: "1.0.0" });
  try {
    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);
    await client.listTools();
    const invalid = await client
      .callTool({
        arguments: { a: 1, b: "x" },
        name: "add",
      })
      .then(
        (result) => ({ result }),
        (error: { code?: number; message: string }) => ({
          error: { code: error.code, message: error.message },
        }),
      );
    const valid = await client.callTool({
      arguments: { a: 1, b: 2 },
      name: "add",
    });
    return { invalid, valid };
  } finally {
    await Promise.all([
      client.close(),
      serverTransport.close(),
      server instanceof FastMCP ? server.stop() : server.close(),
    ]);
  }
}

it("returns a tool error for invalid input, like SDK McpServer", async () => {
  const parameters = z.object({ a: z.number(), b: z.number() });
  const sdk = new McpServer({ name: "SDK", version: "1.0.0" });
  sdk.registerTool("add", { inputSchema: parameters }, async ({ a, b }) => ({
    content: [{ text: String(a + b), type: "text" }],
  }));
  const control = await exercise(sdk);
  expect(control.invalid).toMatchObject({ result: { isError: true } });
  expect(control.valid).toEqual({ content: [{ text: "3", type: "text" }] });

  const fastmcp = new FastMCP({ name: "FastMCP", version: "1.0.0" });
  fastmcp.addTool({
    execute: async ({ a, b }) => String(a + b),
    name: "add",
    parameters,
  });
  const observed = await exercise(fastmcp);
  console.log(JSON.stringify({ fastmcp: observed, sdk: control }));
  expect(observed.valid).toEqual({ content: [{ text: "3", type: "text" }] });
  expect(observed.invalid).toMatchObject({ result: { isError: true } });
});
