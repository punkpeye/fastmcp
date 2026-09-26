import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it, vi } from "vitest";
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

const silentLogger = () => ({
  debug: vi.fn(),
  error: vi.fn(),
  info: vi.fn(),
  log: vi.fn(),
  warn: vi.fn(),
});

/**
 * A server with one tool and nothing else, so the session it hands out
 * advertises `tools` and neither `resources` nor `prompts`.
 */
const serverWithOnlyATool = (logger: ReturnType<typeof silentLogger>) => {
  const server = new FastMCP({ logger, name: "Test", version: "1.0.0" });

  server.addTool({
    description: "Echo",
    execute: async (args) => args.value,
    name: "echo",
    parameters: z.object({ value: z.string() }),
  });

  return server;
};

describe("runtime registration on a session without the capability", () => {
  it("does not throw out of addResource", async () => {
    const logger = silentLogger();
    const server = serverWithOnlyATool(logger);
    const client = await connectInMemory(server);

    expect(() =>
      server.addResource({
        load: async () => ({ text: "late" }),
        mimeType: "text/plain",
        name: "Late",
        uri: "file:///late",
      }),
    ).not.toThrow();

    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining("advertised no 'resources' capability"),
    );

    await client.close();
  });

  it("does not throw out of addResourceTemplate", async () => {
    const logger = silentLogger();
    const server = serverWithOnlyATool(logger);
    const client = await connectInMemory(server);

    expect(() =>
      server.addResourceTemplate({
        arguments: [{ name: "id" }],
        load: async () => ({ text: "late" }),
        mimeType: "text/plain",
        name: "LateTemplate",
        uriTemplate: "file:///late/{id}",
      }),
    ).not.toThrow();

    await client.close();
  });

  it("does not throw out of addPrompt", async () => {
    const logger = silentLogger();
    const server = serverWithOnlyATool(logger);
    const client = await connectInMemory(server);

    expect(() =>
      server.addPrompt({ load: async () => "late", name: "late" }),
    ).not.toThrow();

    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining("advertised no 'prompts' capability"),
    );

    await client.close();
  });

  it("does not throw out of addTool on a server that started with none", async () => {
    const logger = silentLogger();
    const server = new FastMCP({ logger, name: "Test", version: "1.0.0" });
    const client = await connectInMemory(server);

    expect(client.getServerCapabilities()?.tools).toBeUndefined();

    expect(() =>
      server.addTool({
        description: "Late",
        execute: async () => "late",
        name: "late-tool",
        parameters: z.object({}),
      }),
    ).not.toThrow();

    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining("advertised no 'tools' capability"),
    );

    await client.close();
  });

  it("warns once per capability however many are registered", async () => {
    const logger = silentLogger();
    const server = serverWithOnlyATool(logger);
    const client = await connectInMemory(server);

    for (const index of [1, 2, 3]) {
      server.addResource({
        load: async () => ({ text: "late" }),
        mimeType: "text/plain",
        name: `Late ${index}`,
        uri: `file:///late/${index}`,
      });
    }

    expect(
      logger.warn.mock.calls.filter((call) =>
        String(call[0]).includes("'resources' capability"),
      ),
    ).toHaveLength(1);

    await client.close();
  });

  it("keeps serving the sessions that did negotiate the capability", async () => {
    const logger = silentLogger();
    const server = new FastMCP({ logger, name: "Test", version: "1.0.0" });

    server.addResource({
      load: async () => ({ text: "first" }),
      mimeType: "text/plain",
      name: "First",
      uri: "file:///first",
    });

    // The first session advertises `resources` but not `prompts`, so the
    // prompt registration below has to skip it and carry on.
    const withResources = await connectInMemory(server);

    server.addPrompt({ load: async () => "late", name: "late" });

    server.addResource({
      load: async () => ({ text: "second" }),
      mimeType: "text/plain",
      name: "Second",
      uri: "file:///second",
    });

    expect(
      (await withResources.listResources()).resources.map(
        (resource) => resource.uri,
      ),
    ).toEqual(["file:///first", "file:///second"]);

    await withResources.close();
  });

  it("serves the late registrations to a session that connects afterwards", async () => {
    const logger = silentLogger();
    const server = serverWithOnlyATool(logger);
    const early = await connectInMemory(server);

    server.addResource({
      load: async () => ({ text: "late" }),
      mimeType: "text/plain",
      name: "Late",
      uri: "file:///late",
    });
    server.addPrompt({ load: async () => "late", name: "late" });

    const late = await connectInMemory(server);

    expect((await late.listResources()).resources.map((r) => r.uri)).toEqual([
      "file:///late",
    ]);
    expect((await late.listPrompts()).prompts.map((p) => p.name)).toEqual([
      "late",
    ]);

    await early.close();
    await late.close();
  });
});
