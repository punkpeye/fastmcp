import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { getRandomPort } from "get-port-please";
import { setTimeout as delay } from "timers/promises";
import { describe, expect, it } from "vitest";

import { FastMCP, FastMCPSession } from "./FastMCP.js";

const runWithTestServer = async ({
  run,
  server: providedServer,
}: {
  run: ({
    client,
    server,
    session,
  }: {
    client: Client;
    server: FastMCP;
    session: FastMCPSession;
  }) => Promise<void>;
  server?: FastMCP;
}) => {
  const port = await getRandomPort();

  const server =
    providedServer ??
    new FastMCP({
      name: "Test",
      version: "1.0.0",
    });

  await server.start({
    httpStream: {
      host: "127.0.0.1",
      port,
    },
    transportType: "httpStream",
  });

  try {
    const client = new Client(
      {
        name: "example-client",
        version: "1.0.0",
      },
      {
        capabilities: {
          roots: { listChanged: true },
          sampling: {},
        },
      },
    );

    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${port}/mcp`),
    );

    const session = await new Promise<FastMCPSession>((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(new Error("Connection timeout")),
        10000,
      );
      server.on("connect", async (event) => {
        clearTimeout(timeout);
        await event.session.waitForReady();
        resolve(event.session);
      });

      client.connect(transport).catch(reject);
    });

    await delay(100); // Small grace period
    await run({ client, server, session });
  } finally {
    await server.stop();
  }
};

describe("FastMCP Completions", () => {
  it("supports prompt completions", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    server.addPrompt({
      arguments: [
        {
          description: "First argument",
          name: "arg1",
        },
      ],
      complete: async (name, value) => {
        if (name === "arg1" && value === "abc") {
          return {
            values: ["abc1", "abc2"],
          };
        }
        return {
          values: [],
        };
      },
      load: async () => ({
        messages: [],
      }),
      name: "test-prompt",
    });

    await runWithTestServer({
      run: async ({ client }) => {
        const result = await client.complete({
          argument: {
            name: "arg1",
            value: "abc",
          },
          ref: {
            name: "test-prompt",
            type: "ref/prompt",
          },
        });

        expect(result.completion.values).toEqual(["abc1", "abc2"]);
      },
      server,
    });
  });

  it("supports resource completions", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    server.addResourceTemplate({
      arguments: [{ name: "id", required: true }],
      complete: async (_name, value) => ({
        values: ["1", "2"].filter((v) => v.startsWith(value)),
      }),
      load: async () => ({
        text: "content",
        uri: "test://resource/1",
      }),
      name: "test-resource",
      uriTemplate: "test://resource/{id}",
    });

    await runWithTestServer({
      run: async ({ client }) => {
        const result = await client.complete({
          argument: {
            name: "id",
            value: "1",
          },
          ref: {
            type: "ref/resource",
            uri: "test://resource/{id}",
          },
        });

        expect(result.completion.values).toEqual(["1"]);
      },
      server,
    });
  });

  it("prioritizes argument-level completion over prompt-level completion", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    server.addPrompt({
      arguments: [
        {
          complete: async (value) => ({
            values: [`arg-level-${value}`],
          }),
          name: "arg1",
        },
      ],
      complete: async (_name, value) => ({
        values: [`prompt-level-${value}`],
      }),
      load: async () => ({ messages: [] }),
      name: "priority-test",
    });

    await runWithTestServer({
      run: async ({ client }) => {
        const result = await client.complete({
          argument: {
            name: "arg1",
            value: "abc",
          },
          ref: {
            name: "priority-test",
            type: "ref/prompt",
          },
        });

        expect(result.completion.values).toEqual(["arg-level-abc"]);
      },
      server,
    });
  });

  it("throws error for unknown prompt", async () => {
    await runWithTestServer({
      run: async ({ client }) => {
        await expect(
          client.complete({
            argument: {
              name: "arg",
              value: "val",
            },
            ref: {
              name: "unknown-prompt",
              type: "ref/prompt",
            },
          }),
        ).rejects.toThrow();
      },
    });
  });

  it("throws error for unknown resource", async () => {
    await runWithTestServer({
      run: async ({ client }) => {
        await expect(
          client.complete({
            argument: {
              name: "arg",
              value: "val",
            },
            ref: {
              type: "ref/resource",
              uri: "unknown://uri",
            },
          }),
        ).rejects.toThrow();
      },
    });
  });
});
