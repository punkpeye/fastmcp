import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { getRandomPort } from "get-port-please";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

const runWithTestServer = async ({
  run,
  server: createServer,
}: {
  run: ({
    client,
    server,
  }: {
    client: Client;
    server: FastMCP;
  }) => Promise<void>;
  server: () => Promise<FastMCP>;
}) => {
  const port = await getRandomPort();
  const server = await createServer();

  await server.start({
    httpStream: { port },
    transportType: "httpStream",
  });

  const client = new Client(
    { name: "test-client", version: "1.0.0" },
    { capabilities: {} },
  );

  const transport = new StreamableHTTPClientTransport(
    new URL(`http://localhost:${port}/mcp`),
  );

  await client.connect(transport);

  try {
    await run({ client, server });
  } finally {
    await client.close();
    await server.stop();
  }
};

describe("Tool Execution AbortSignal and Cancellation", () => {
  it("passes an active AbortSignal in tool execution context", async () => {
    let capturedSignal: AbortSignal | undefined;

    await runWithTestServer({
      run: async ({ client }) => {
        const result = await client.callTool({
          arguments: {},
          name: "checkSignal",
        });

        expect(result).toEqual({
          content: [{ text: "ok", type: "text" }],
        });
        expect(capturedSignal).toBeDefined();
        expect(capturedSignal?.aborted).toBe(false);
      },
      server: async () => {
        const server = new FastMCP({ name: "Test", version: "1.0.0" });
        server.addTool({
          description: "Checks signal in context",
          execute: async (_args, context) => {
            capturedSignal = context.signal;
            return "ok";
          },
          name: "checkSignal",
          parameters: z.object({}),
        });
        return server;
      },
    });
  });

  it("aborts the signal when tool execution times out", async () => {
    let abortedAtTimeout = false;

    await runWithTestServer({
      run: async ({ client }) => {
        const result = await client.callTool({
          arguments: {},
          name: "slowTool",
        });

        expect(result).toMatchObject({
          content: [
            {
              text: expect.stringContaining("timed out after 50ms"),
              type: "text",
            },
          ],
          isError: true,
        });
        expect(abortedAtTimeout).toBe(true);
      },
      server: async () => {
        const server = new FastMCP({ name: "Test", version: "1.0.0" });
        server.addTool({
          description: "Tool that runs longer than timeoutMs",
          execute: async (_args, context) => {
            context.signal.addEventListener("abort", () => {
              abortedAtTimeout = true;
            });
            await new Promise((resolve) => setTimeout(resolve, 200));
            return "done";
          },
          name: "slowTool",
          parameters: z.object({}),
          timeoutMs: 50,
        });
        return server;
      },
    });
  });

  it("executes standard tools without timeout normally", async () => {
    await runWithTestServer({
      run: async ({ client }) => {
        const result = await client.callTool({
          arguments: { a: 2, b: 3 },
          name: "add",
        });

        expect(result).toEqual({
          content: [{ text: "5", type: "text" }],
        });
      },
      server: async () => {
        const server = new FastMCP({ name: "Test", version: "1.0.0" });
        server.addTool({
          execute: async ({ a, b }, context) => {
            expect(context.signal).toBeDefined();
            expect(context.signal.aborted).toBe(false);
            return String(a + b);
          },
          name: "add",
          parameters: z.object({ a: z.number(), b: z.number() }),
        });
        return server;
      },
    });
  });
});
