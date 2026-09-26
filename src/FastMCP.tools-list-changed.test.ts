import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ToolListChangedNotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { setTimeout as delay } from "timers/promises";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

const connectInMemory = async (server: FastMCP) => {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();

  const client = new Client({ name: "test-client", version: "0.0.0" });

  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);

  return client;
};

const serverWithOneTool = () => {
  const server = new FastMCP({ name: "Test", version: "1.0.0" });

  server.addTool({
    description: "Add two numbers",
    execute: async (args) => String(args.a + args.b),
    name: "add",
    parameters: z.object({ a: z.number(), b: z.number() }),
  });

  return server;
};

describe("tools listChanged capability", () => {
  it("advertises listChanged on the tools capability", async () => {
    const client = await connectInMemory(serverWithOneTool());

    expect(client.getServerCapabilities()?.tools).toEqual({
      listChanged: true,
    });

    await client.close();
  });

  it("sends the notification the capability advertises", async () => {
    const server = serverWithOneTool();
    const client = await connectInMemory(server);

    // A client is entitled to register the handler only because the
    // capability says the notification is coming.
    expect(client.getServerCapabilities()?.tools?.listChanged).toBe(true);

    let notified = 0;
    client.setNotificationHandler(ToolListChangedNotificationSchema, () => {
      notified += 1;
    });

    server.addTool({
      description: "Subtract two numbers",
      execute: async (args) => String(args.a - args.b),
      name: "subtract",
      parameters: z.object({ a: z.number(), b: z.number() }),
    });

    await delay(100);

    expect(notified).toBe(1);
    expect((await client.listTools()).tools.map((tool) => tool.name)).toEqual([
      "add",
      "subtract",
    ]);

    await client.close();
  });
});
