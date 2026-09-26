import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { LoggingMessageNotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { setTimeout as delay } from "timers/promises";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

/**
 * Connects a client to a server that logs once at each of the four levels the
 * `log` context object exposes, and collects the levels that reach the client.
 */
const connectNoisyServer = async () => {
  const server = new FastMCP({ name: "Test", version: "1.0.0" });

  server.addTool({
    description: "Logs at every level",
    execute: async (_args, { log }) => {
      log.debug("debug line");
      log.info("info line");
      log.warn("warning line");
      log.error("error line");

      return "done";
    },
    name: "noisy",
    parameters: z.object({}),
  });

  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();

  const client = new Client({ name: "test-client", version: "0.0.0" });

  const [session] = await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);

  const levels: string[] = [];

  client.setNotificationHandler(
    LoggingMessageNotificationSchema,
    (notification) => {
      levels.push(notification.params.level);
    },
  );

  const run = async () => {
    await client.callTool({ arguments: {}, name: "noisy" });
    await delay(100);

    return levels;
  };

  return { client, run, session };
};

describe("client logging level", () => {
  it("drops messages below the level the client set", async () => {
    const { client, run } = await connectNoisyServer();

    await client.setLoggingLevel("error");

    expect(await run()).toEqual(["error"]);

    await client.close();
  });

  it("keeps the level the client set and everything more severe", async () => {
    const { client, run } = await connectNoisyServer();

    await client.setLoggingLevel("warning");

    expect(await run()).toEqual(["warning", "error"]);

    await client.close();
  });

  it("sends every level until the client asks for one", async () => {
    const { client, run, session } = await connectNoisyServer();

    expect(session.loggingLevel).toBe("info");

    // `info` is what the property reads by default, but nothing is filtered
    // until `logging/setLevel` arrives, so a `debug` line still goes out.
    expect(await run()).toEqual(["debug", "info", "warning", "error"]);

    await client.close();
  });

  it("applies a level the client lowers again", async () => {
    const { client, run } = await connectNoisyServer();

    await client.setLoggingLevel("error");
    await client.setLoggingLevel("debug");

    expect(await run()).toEqual(["debug", "info", "warning", "error"]);

    await client.close();
  });
});
