import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ToolListChangedNotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it, vi } from "vitest";

import { FastMCP } from "./FastMCP.js";

type Auth = { role: string; user: string };

const connectInMemory = async (server: FastMCP<Auth>, auth: Auth) => {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });
  const [session] = await Promise.all([
    server.connect(serverTransport, auth),
    client.connect(clientTransport),
  ]);

  return { client, session };
};

const createServer = () => {
  const server = new FastMCP<Auth>({ name: "Test", version: "1.0.0" });
  server.addTool({
    canAccess: (auth) => auth.role === "admin",
    description: "Admin only",
    execute: async (_args, { session }) => `admin:${session?.user}`,
    name: "admin",
  });
  server.addTool({
    description: "Current user",
    execute: async (_args, { session }) => session?.user ?? "anonymous",
    name: "identity",
  });

  return server;
};

describe("tool access after updateAuth", () => {
  it("rechecks access when the auth object is updated in place", async () => {
    const server = createServer();
    const auth = { role: "admin", user: "alice" };
    const { client, session } = await connectInMemory(server, auth);

    try {
      auth.role = "reader";
      session.updateAuth(auth);

      await expect(client.callTool({ name: "admin" })).rejects.toThrow(
        "Unknown tool: admin",
      );
    } finally {
      await client.close();
    }
  });

  it("revokes access when the refreshed auth no longer allows a tool", async () => {
    const server = createServer();
    const { client, session } = await connectInMemory(server, {
      role: "admin",
      user: "alice",
    });

    try {
      session.updateAuth({ role: "reader", user: "alice" });

      await expect(client.callTool({ name: "admin" })).rejects.toThrow(
        "Unknown tool: admin",
      );
      expect((await client.listTools()).tools.map((tool) => tool.name)).toEqual(
        ["identity"],
      );
    } finally {
      await client.close();
    }
  });

  it("grants access when the refreshed auth allows a previously hidden tool", async () => {
    const server = createServer();
    const { client, session } = await connectInMemory(server, {
      role: "reader",
      user: "alice",
    });

    try {
      session.updateAuth({ role: "admin", user: "alice" });

      expect(await client.callTool({ name: "admin" })).toEqual({
        content: [{ text: "admin:alice", type: "text" }],
      });
      expect((await client.listTools()).tools.map((tool) => tool.name)).toEqual(
        ["admin", "identity"],
      );
    } finally {
      await client.close();
    }
  });

  it("notifies the client only when the visible tools change", async () => {
    const server = createServer();
    const { client, session } = await connectInMemory(server, {
      role: "reader",
      user: "alice",
    });
    const changed = vi.fn();
    client.setNotificationHandler(ToolListChangedNotificationSchema, changed);

    try {
      session.updateAuth({ role: "admin", user: "alice" });
      await client.ping();
      expect(changed).toHaveBeenCalledTimes(1);

      session.updateAuth({ role: "admin", user: "bob" });
      await client.ping();
      expect(changed).toHaveBeenCalledTimes(1);
      expect(await client.callTool({ name: "identity" })).toEqual({
        content: [{ text: "bob", type: "text" }],
      });
    } finally {
      await client.close();
    }
  });

  it("uses current registrations after an auth refresh", async () => {
    const server = createServer();
    const { client, session } = await connectInMemory(server, {
      role: "reader",
      user: "alice",
    });

    try {
      server.removeTool("admin");
      server.addTool({
        canAccess: (auth) => auth.role === "admin",
        description: "Added at runtime",
        execute: async () => "late",
        name: "late",
      });
      session.updateAuth({ role: "admin", user: "alice" });

      expect((await client.listTools()).tools.map((tool) => tool.name)).toEqual(
        ["identity", "late"],
      );
      expect(await client.callTool({ name: "late" })).toEqual({
        content: [{ text: "late", type: "text" }],
      });
      await expect(client.callTool({ name: "admin" })).rejects.toThrow(
        "Unknown tool: admin",
      );
    } finally {
      await client.close();
    }
  });

  it("keeps other sessions' access unchanged", async () => {
    const server = createServer();
    const alice = await connectInMemory(server, {
      role: "admin",
      user: "alice",
    });
    const bob = await connectInMemory(server, { role: "admin", user: "bob" });

    try {
      alice.session.updateAuth({ role: "reader", user: "alice" });

      await expect(alice.client.callTool({ name: "admin" })).rejects.toThrow(
        "Unknown tool: admin",
      );
      expect(await bob.client.callTool({ name: "admin" })).toEqual({
        content: [{ text: "admin:bob", type: "text" }],
      });
    } finally {
      await Promise.all([alice.client.close(), bob.client.close()]);
    }
  });
});
