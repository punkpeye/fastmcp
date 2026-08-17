import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
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
    await client.close().catch(() => {});
    await server.stop();
  }
};

/**
 * Resolves once `signal` aborts, or rejects if it stays live past `timeoutMs`.
 * Lets a test wait on the abort itself instead of sleeping long enough to
 * assume it happened.
 */
const abortReason = (signal: AbortSignal, timeoutMs = 2000) =>
  new Promise<unknown>((resolve, reject) => {
    if (signal.aborted) {
      resolve(signal.reason);
      return;
    }

    const timer = setTimeout(
      () => reject(new Error(`signal did not abort within ${timeoutMs}ms`)),
      timeoutMs,
    );

    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        resolve(signal.reason);
      },
      { once: true },
    );
  });

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

        // Attaching cleanup to the signal has to stay safe for tools that
        // finish normally, so a completed call must not abort retroactively
        // once its timeout would have elapsed.
        await new Promise((resolve) => setTimeout(resolve, 50));
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

  it("aborts the signal when the client cancels the call", async () => {
    let observed: Promise<unknown> | undefined;
    let started: (() => void) | undefined;
    const toolStarted = new Promise<void>((resolve) => {
      started = resolve;
    });

    await runWithTestServer({
      run: async ({ client }) => {
        const cancel = new AbortController();

        const call = client
          .callTool({ arguments: {}, name: "slowTool" }, undefined, {
            signal: cancel.signal,
          })
          .catch(() => "cancelled");

        await toolStarted;
        cancel.abort();

        await expect(call).resolves.toBe("cancelled");

        // The SDK turns the caller's abort into `notifications/cancelled`,
        // which is the one path where the request's own signal fires.
        await expect(observed).resolves.toBeDefined();
      },
      server: async () => {
        const server = new FastMCP({ name: "Test", version: "1.0.0" });
        server.addTool({
          description: "Runs until cancelled",
          execute: async (_args, context) => {
            observed = abortReason(context.signal);
            started?.();
            await new Promise((resolve) => setTimeout(resolve, 5000));
            return "done";
          },
          name: "slowTool",
          parameters: z.object({}),
        });
        return server;
      },
    });
  });

  it("aborts the signal when the transport drops mid-call", async () => {
    let observed: Promise<unknown> | undefined;
    let started: (() => void) | undefined;
    const toolStarted = new Promise<void>((resolve) => {
      started = resolve;
    });

    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    server.addTool({
      description: "Runs until the connection drops",
      execute: async (_args, context) => {
        observed = abortReason(context.signal);
        started?.();
        await new Promise((resolve) => setTimeout(resolve, 5000));
        return "done";
      },
      name: "slowTool",
      parameters: z.object({}),
    });

    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();

    const client = new Client(
      { name: "test-client", version: "1.0.0" },
      { capabilities: {} },
    );

    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);

    const call = client
      .callTool({ arguments: {}, name: "slowTool" })
      .catch(() => "dropped");

    await toolStarted;

    // A connection that just goes away carries no `notifications/cancelled`,
    // so the request's own signal never fires. The session-scoped one is what
    // reaches the tool here.
    await clientTransport.close();

    await expect(observed).resolves.toBeInstanceOf(Error);
    await expect(call).resolves.toBe("dropped");
  });

  it("aborts the signal when tool execution times out", async () => {
    let observed: Promise<unknown> | undefined;

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

        // The tool is handed the same error the caller sees, so it can tell a
        // timeout apart from a cancellation without guessing.
        await expect(observed).resolves.toMatchObject({
          message: expect.stringContaining("timed out after 50ms"),
        });
      },
      server: async () => {
        const server = new FastMCP({ name: "Test", version: "1.0.0" });
        server.addTool({
          description: "Tool that runs longer than timeoutMs",
          execute: async (_args, context) => {
            observed = abortReason(context.signal);
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

  it("keeps the signal live for a tool that throws synchronously", async () => {
    await runWithTestServer({
      run: async ({ client }) => {
        const result = await client.callTool({
          arguments: {},
          name: "throwsSync",
        });

        expect(result).toMatchObject({ isError: true });
      },
      server: async () => {
        const server = new FastMCP({ name: "Test", version: "1.0.0" });
        server.addTool({
          description: "Throws before returning a promise",
          // Not `async`: this throws during the call itself, before FastMCP
          // ever has a promise to hang cleanup off.
          execute: () => {
            throw new Error("boom");
          },
          name: "throwsSync",
          parameters: z.object({}),
          timeoutMs: 50,
        });
        return server;
      },
    });
  });
});
