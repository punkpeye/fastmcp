import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { expect, it } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * A client that hangs up while a tool is still running makes every later
 * `context.log.*` call reject with "Not connected". The four log methods are
 * the only notification senders in this file that do not catch that, and an
 * unhandled rejection is fatal under Node's default --unhandled-rejections=throw.
 */
it("does not leave an unhandled rejection when the client hangs up mid-tool", async () => {
  const rejections: unknown[] = [];
  const onRejection = (reason: unknown) => rejections.push(reason);
  process.on("unhandledRejection", onRejection);

  try {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    server.addTool({
      execute: async (_args, { log }) => {
        for (let index = 0; index < 10; index++) {
          log.info(`step ${index}`);
          await sleep(20);
        }

        return "done";
      },
      name: "slow",
      parameters: z.object({}),
    });

    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "test-client", version: "0.0.0" });

    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);

    client.callTool({ arguments: {}, name: "slow" }).catch(() => {});
    await sleep(60);
    await client.close();
    await sleep(300);

    expect(rejections).toEqual([]);
  } finally {
    process.off("unhandledRejection", onRejection);
  }
});
