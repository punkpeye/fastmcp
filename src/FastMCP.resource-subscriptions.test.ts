import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ResourceUpdatedNotificationSchema } from "@modelcontextprotocol/sdk/types.js";
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
        capabilities: {},
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

const createServerWithResource = () => {
  const server = new FastMCP({ name: "Test", version: "1.0.0" });

  server.addResource({
    load: async () => ({ text: "content" }),
    name: "example",
    uri: "test://example",
  });

  return server;
};

describe("FastMCP resource subscriptions", () => {
  it("advertises resource subscribe and listChanged capabilities", async () => {
    await runWithTestServer({
      run: async ({ client }) => {
        expect(client.getServerCapabilities()?.resources).toEqual({
          listChanged: true,
          subscribe: true,
        });
      },
      server: createServerWithResource(),
    });
  });

  it("advertises prompt listChanged capability", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    server.addPrompt({
      load: async () => "hello",
      name: "example",
    });

    await runWithTestServer({
      run: async ({ client }) => {
        expect(client.getServerCapabilities()?.prompts).toEqual({
          listChanged: true,
        });
      },
      server,
    });
  });

  it("notifies a subscribed client when a resource is updated", async () => {
    await runWithTestServer({
      run: async ({ client, server }) => {
        const updates: string[] = [];

        client.setNotificationHandler(
          ResourceUpdatedNotificationSchema,
          (notification) => {
            updates.push(notification.params.uri);
          },
        );

        await client.subscribeResource({ uri: "test://example" });

        await server.sendResourceUpdated("test://example");
        await delay(200);

        expect(updates).toEqual(["test://example"]);
      },
      server: createServerWithResource(),
    });
  });

  it("does not notify a client that has not subscribed", async () => {
    await runWithTestServer({
      run: async ({ client, server }) => {
        const updates: string[] = [];

        client.setNotificationHandler(
          ResourceUpdatedNotificationSchema,
          (notification) => {
            updates.push(notification.params.uri);
          },
        );

        await server.sendResourceUpdated("test://example");
        await delay(200);

        expect(updates).toEqual([]);
      },
      server: createServerWithResource(),
    });
  });

  it("stops notifying after the client unsubscribes", async () => {
    await runWithTestServer({
      run: async ({ client, server }) => {
        const updates: string[] = [];

        client.setNotificationHandler(
          ResourceUpdatedNotificationSchema,
          (notification) => {
            updates.push(notification.params.uri);
          },
        );

        await client.subscribeResource({ uri: "test://example" });
        await client.unsubscribeResource({ uri: "test://example" });

        await server.sendResourceUpdated("test://example");
        await delay(200);

        expect(updates).toEqual([]);
      },
      server: createServerWithResource(),
    });
  });
});
