import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

type Auth = { userId: string };

async function connect(server: FastMCP<Auth>, auth: Auth) {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "c", version: "0.0.0" });
  await Promise.all([
    server.connect(serverTransport, auth),
    client.connect(clientTransport),
  ]);
  return client;
}

function createServer() {
  const server = new FastMCP<Auth>({ name: "T", version: "1.0.0" });
  server.addResource({
    load: async (auth, context) => ({
      text: `profile of ${auth?.userId} via ${context?.client.version?.name}`,
    }),
    name: "Profile",
    uri: "user://me",
  });
  server.addResourceTemplate({
    arguments: [{ name: "id", required: true }],
    load: async ({ id }, auth) => ({ text: `note ${id} of ${auth?.userId}` }),
    name: "Notes",
    uriTemplate: "notes://{id}",
  });
  server.addTool({
    execute: async ({ uri, withContext }, context) => ({
      content: [
        {
          resource: await server.embedded(
            uri,
            withContext ? context : undefined,
          ),
          type: "resource",
        },
      ],
    }),
    name: "embed",
    parameters: z.object({ uri: z.string(), withContext: z.boolean() }),
  });
  return server;
}

async function embed(client: Client, uri: string, withContext: boolean) {
  const result = await client.callTool({
    arguments: { uri, withContext },
    name: "embed",
  });
  return (result.content as [{ resource: { text: string } }])[0].resource.text;
}

describe("embedded() with the calling tool's context", () => {
  it("passes the session auth and context to a resource loader", async () => {
    const server = createServer();
    const client = await connect(server, { userId: "u1" });
    try {
      expect(await embed(client, "user://me", true)).toBe(
        "profile of u1 via c",
      );
    } finally {
      await client.close();
      await server.stop();
    }
  });

  it("passes the session auth to a resource template loader", async () => {
    const server = createServer();
    const client = await connect(server, { userId: "u1" });
    try {
      expect(await embed(client, "notes://a", true)).toBe("note a of u1");
    } finally {
      await client.close();
      await server.stop();
    }
  });

  it("still loads without a context", async () => {
    const server = createServer();
    const client = await connect(server, { userId: "u1" });
    try {
      expect(await embed(client, "notes://a", false)).toBe(
        "note a of undefined",
      );
    } finally {
      await client.close();
      await server.stop();
    }
  });
});
