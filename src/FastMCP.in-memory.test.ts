import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { type ContentResult, FastMCP } from "./FastMCP.js";

/**
 * Connects a client to a server over a linked in-memory transport pair, the
 * pattern documented in the README's "Testing your server" section.
 */
const connectInMemory = async (server: FastMCP) => {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();

  const client = new Client({ name: "test-client", version: "0.0.0" });

  const [session] = await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);

  return { client, session };
};

describe("FastMCP in-memory transport", () => {
  it("serves tools registered on the FastMCP instance", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    server.addTool({
      description: "Add two numbers",
      execute: async (args) => String(args.a + args.b),
      name: "add",
      parameters: z.object({ a: z.number(), b: z.number() }),
    });

    const { client } = await connectInMemory(server);

    expect((await client.listTools()).tools.map((tool) => tool.name)).toEqual([
      "add",
    ]);

    const result = (await client.callTool({
      arguments: { a: 2, b: 3 },
      name: "add",
    })) as ContentResult;

    expect(result).toEqual({ content: [{ text: "5", type: "text" }] });

    await client.close();
  });

  it("serves resources and prompts", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    server.addResource({
      async load() {
        return { text: "log contents" };
      },
      mimeType: "text/plain",
      name: "Logs",
      uri: "file:///logs/app.log",
    });

    server.addPrompt({
      arguments: [{ name: "name", required: true }],
      description: "Greet someone",
      load: async (args) => `Hello, ${args.name}!`,
      name: "greet",
    });

    const { client } = await connectInMemory(server);

    expect((await client.listResources()).resources[0].uri).toBe(
      "file:///logs/app.log",
    );

    const contents = (await client.readResource({
      uri: "file:///logs/app.log",
    })) as { contents: Array<{ text: string }> };

    expect(contents.contents[0].text).toBe("log contents");

    expect((await client.listPrompts()).prompts.map((p) => p.name)).toEqual([
      "greet",
    ]);

    const prompt = (await client.getPrompt({
      arguments: { name: "World" },
      name: "greet",
    })) as { messages: Array<{ content: { text: string } }> };

    expect(prompt.messages[0].content.text).toBe("Hello, World!");

    await client.close();
  });

  it("tracks the session and emits connect", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    const onConnect = vi.fn();
    server.on("connect", onConnect);

    const { client, session } = await connectInMemory(server);

    expect(server.sessions).toEqual([session]);
    expect(onConnect).toHaveBeenCalledWith({ session });

    await client.close();
  });

  it("removes the session and emits disconnect when the transport closes", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    const onDisconnect = vi.fn();
    server.on("disconnect", onDisconnect);

    const { client, session } = await connectInMemory(server);

    expect(server.sessions).toHaveLength(1);

    await client.close();
    await session.close();

    expect(server.sessions).toEqual([]);
    expect(onDisconnect).toHaveBeenCalledWith({ session });
  });

  it("passes auth through to the tool context and applies canAccess", async () => {
    type Auth = { id: number; role: string };

    const server = new FastMCP<Auth>({ name: "Test", version: "1.0.0" });

    server.addTool({
      description: "Return the caller id",
      execute: async (_args, { session }) => String(session?.id),
      name: "whoami",
      parameters: z.object({}),
    });

    server.addTool({
      canAccess: (auth) => auth?.role === "admin",
      description: "Admin only",
      execute: async () => "secret",
      name: "admin-only",
      parameters: z.object({}),
    });

    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "test-client", version: "0.0.0" });

    await Promise.all([
      server.connect(serverTransport, { id: 7, role: "user" }),
      client.connect(clientTransport),
    ]);

    // canAccess filtering runs exactly as it does for HTTP sessions.
    expect((await client.listTools()).tools.map((tool) => tool.name)).toEqual([
      "whoami",
    ]);

    const result = (await client.callTool({
      arguments: {},
      name: "whoami",
    })) as ContentResult;

    expect(result).toEqual({ content: [{ text: "7", type: "text" }] });

    await client.close();
  });

  it("supports two independent sessions on one server", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    server.addTool({
      description: "Echo",
      execute: async (args) => args.value,
      name: "echo",
      parameters: z.object({ value: z.string() }),
    });

    const first = await connectInMemory(server);
    const second = await connectInMemory(server);

    expect(server.sessions).toHaveLength(2);

    expect(
      await first.client.callTool({ arguments: { value: "a" }, name: "echo" }),
    ).toEqual({ content: [{ text: "a", type: "text" }] });
    expect(
      await second.client.callTool({ arguments: { value: "b" }, name: "echo" }),
    ).toEqual({ content: [{ text: "b", type: "text" }] });

    await first.client.close();
    await second.client.close();
  });
});
