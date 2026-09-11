import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

type Auth = { role: string };

function adminOnlyServer() {
  const server = new FastMCP<Auth>({ name: "T", version: "1.0.0" });
  server.addTool({
    canAccess: (auth) => auth?.role === "admin",
    description: "Admin only",
    execute: async () => "secret",
    name: "admin-only",
    parameters: z.object({}),
  });
  return server;
}

async function connectAs(server: FastMCP<Auth>, auth: Auth) {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "c", version: "0.0.0" });
  await Promise.all([
    server.connect(serverTransport, auth),
    client.connect(clientTransport),
  ]);
  return client;
}

describe("canAccess filtering every tool out of a session (#370)", () => {
  it("still advertises the tools capability and answers tools/list with an empty list", async () => {
    const server = adminOnlyServer();
    const client = await connectAs(server, { role: "user" });
    try {
      expect(client.getServerCapabilities()?.tools).toBeDefined();
      await expect(client.listTools()).resolves.toEqual({ tools: [] });
    } finally {
      await client.close();
      await server.stop();
    }
  });

  it("lets addTool() run while such a session is connected", async () => {
    const server = adminOnlyServer();
    const client = await connectAs(server, { role: "user" });
    try {
      expect(() =>
        server.addTool({
          description: "For everyone",
          execute: async () => "hi",
          name: "public",
          parameters: z.object({}),
        }),
      ).not.toThrow();
      // The list-changed refresh is asynchronous; the next list reflects it.
      await new Promise((resolve) => setTimeout(resolve, 0));
      const { tools } = await client.listTools();
      expect(tools.map((tool) => tool.name)).toEqual(["public"]);
    } finally {
      await client.close();
      await server.stop();
    }
  });

  it("keeps a session that may see the tool unchanged", async () => {
    const server = adminOnlyServer();
    const client = await connectAs(server, { role: "admin" });
    try {
      const { tools } = await client.listTools();
      expect(tools.map((tool) => tool.name)).toEqual(["admin-only"]);
    } finally {
      await client.close();
      await server.stop();
    }
  });

  it("does not advertise tools for a server that has none", async () => {
    const server = new FastMCP<Auth>({ name: "T", version: "1.0.0" });
    const client = await connectAs(server, { role: "user" });
    try {
      expect(client.getServerCapabilities()?.tools).toBeUndefined();
    } finally {
      await client.close();
      await server.stop();
    }
  });
});
