import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  ContentBlockSchema,
  ListRootsRequestSchema,
  PromptListChangedNotificationSchema,
  ResourceLink,
  ResourceLinkSchema,
  ResourceListChangedNotificationSchema,
  ToolListChangedNotificationSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { type Content, type ContentResult, FastMCP } from "./FastMCP.js";

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

  return { client, serverTransport, session };
};

describe("FastMCP in-memory transport", () => {
  it.each(["tools", "resources", "resource templates", "prompts"])(
    "updates remaining sessions' %s when another closes during notification",
    async (registry) => {
      const server = new FastMCP({ name: "Test", version: "1.0.0" });
      server.addTool({ execute: async () => "old", name: "old" });
      server.addResource({
        load: async () => ({ text: "old" }),
        name: "old",
        uri: "file:///old",
      });
      server.addResourceTemplate({
        arguments: [{ name: "id" }],
        load: async () => ({ text: "old" }),
        name: "old",
        uriTemplate: "file:///old/{id}",
      });
      server.addPrompt({ load: async () => "old", name: "old" });
      const first = await connectInMemory(server);
      const second = await connectInMemory(server);
      const changed = vi.fn();
      if (registry === "tools") {
        second.client.setNotificationHandler(
          ToolListChangedNotificationSchema,
          changed,
        );
      } else if (registry === "prompts") {
        second.client.setNotificationHandler(
          PromptListChangedNotificationSchema,
          changed,
        );
      } else {
        second.client.setNotificationHandler(
          ResourceListChangedNotificationSchema,
          changed,
        );
      }
      const send = first.serverTransport.send.bind(first.serverTransport);
      // A transport may detect closure and report it synchronously from send().
      first.serverTransport.send = async (message, options) => {
        if ("method" in message && message.method.endsWith("/list_changed")) {
          const onclose = first.serverTransport.onclose;
          first.serverTransport.onclose = undefined;
          onclose?.();
          await first.serverTransport.close();
          return;
        }
        await send(message, options);
      };

      try {
        await server.stop();
        switch (registry) {
          case "prompts":
            server.addPrompt({ load: async () => "new", name: "new" });
            expect(
              (await second.client.listPrompts()).prompts.map(
                (prompt) => prompt.name,
              ),
            ).toEqual(["old", "new"]);
            expect(
              await second.client.getPrompt({ name: "new" }),
            ).toMatchObject({ messages: [{ content: { text: "new" } }] });
            break;
          case "resources":
            server.addResource({
              load: async () => ({ text: "new" }),
              name: "new",
              uri: "file:///new",
            });
            expect(
              (await second.client.listResources()).resources.map(
                (resource) => resource.uri,
              ),
            ).toEqual(["file:///old", "file:///new"]);
            expect(
              await second.client.readResource({ uri: "file:///new" }),
            ).toMatchObject({ contents: [{ text: "new" }] });
            break;
          case "resource templates":
            server.addResourceTemplate({
              arguments: [{ name: "id" }],
              load: async () => ({ text: "new" }),
              name: "new",
              uriTemplate: "file:///new/{id}",
            });
            expect(
              (
                await second.client.listResourceTemplates()
              ).resourceTemplates.map((resource) => resource.uriTemplate),
            ).toEqual(["file:///old/{id}", "file:///new/{id}"]);
            expect(
              await second.client.readResource({ uri: "file:///new/1" }),
            ).toMatchObject({ contents: [{ text: "new" }] });
            break;
          case "tools":
            server.addTool({ execute: async () => "new", name: "new" });
            expect(
              (await second.client.listTools()).tools.map((tool) => tool.name),
            ).toEqual(["old", "new"]);
            expect(await second.client.callTool({ name: "new" })).toMatchObject(
              { content: [{ text: "new" }] },
            );
            break;
        }
        expect(server.sessions).toEqual([second.session]);
        await expect.poll(() => changed.mock.calls.length).toBe(1);
      } finally {
        await first.client.close();
        await first.session.close();
        await second.client.close();
        await second.session.close();
      }
    },
  );

  it.each([false, true])(
    "keeps caller-owned sessions' tools current after stop (batch: %s)",
    async (batch) => {
      const server = new FastMCP({ name: "Test", version: "1.0.0" });
      server.addTool({ execute: async () => "old", name: "old" });
      const connections = [
        await connectInMemory(server),
        await connectInMemory(server),
      ];
      const notifications = connections.map(({ client }) => {
        const changed = vi.fn();
        client.setNotificationHandler(
          ToolListChangedNotificationSchema,
          changed,
        );
        return changed;
      });

      try {
        await server.stop();
        const tool = { execute: async () => "new", name: "new" };
        if (batch) {
          server.addTools([tool]);
        } else {
          server.addTool(tool);
        }
        for (const changed of notifications) {
          await expect.poll(() => changed.mock.calls.length).toBe(1);
        }
        if (batch) {
          server.removeTools(["old"]);
        } else {
          server.removeTool("old");
        }

        for (const { client, session } of connections) {
          expect(session.isReady).toBe(true);
          expect(
            (await client.listTools()).tools.map((tool) => tool.name),
          ).toEqual(["new"]);
          expect(await client.callTool({ name: "new" })).toEqual({
            content: [{ text: "new", type: "text" }],
          });
          await expect(client.callTool({ name: "old" })).rejects.toThrow(
            "Unknown tool",
          );
        }
        for (const changed of notifications) {
          await expect.poll(() => changed.mock.calls.length).toBe(2);
        }
      } finally {
        for (const { client, session } of connections) {
          await client.close();
          await session.close();
        }
      }
    },
  );

  it.each([false, true])(
    "keeps caller-owned sessions' resources current after stop (batch: %s)",
    async (batch) => {
      const server = new FastMCP({ name: "Test", version: "1.0.0" });
      server.addResource({
        load: async () => ({ text: "old" }),
        name: "old",
        uri: "file:///old",
      });
      const { client, session } = await connectInMemory(server);
      const changed = vi.fn();
      client.setNotificationHandler(
        ResourceListChangedNotificationSchema,
        changed,
      );

      try {
        await server.stop();
        const resource = {
          load: async () => ({ text: "new" }),
          name: "new",
          uri: "file:///new",
        };
        if (batch) {
          server.addResources([resource]);
        } else {
          server.addResource(resource);
        }
        await expect.poll(() => changed.mock.calls.length).toBe(1);
        if (batch) {
          server.removeResources(["old"]);
        } else {
          server.removeResource("old");
        }

        expect(
          (await client.listResources()).resources.map(
            (resource) => resource.uri,
          ),
        ).toEqual(["file:///new"]);
        expect(await client.readResource({ uri: "file:///new" })).toMatchObject(
          { contents: [{ text: "new" }] },
        );
        await expect(
          client.readResource({ uri: "file:///old" }),
        ).rejects.toThrow("Resource not found");
        await expect.poll(() => changed.mock.calls.length).toBe(2);
      } finally {
        await client.close();
        await session.close();
      }
    },
  );

  it.each([false, true])(
    "keeps caller-owned sessions' resource templates current after stop (batch: %s)",
    async (batch) => {
      const server = new FastMCP({ name: "Test", version: "1.0.0" });
      server.addResourceTemplate({
        arguments: [{ name: "id" }],
        load: async () => ({ text: "old" }),
        name: "old",
        uriTemplate: "file:///old/{id}",
      });
      const { client, session } = await connectInMemory(server);
      const changed = vi.fn();
      client.setNotificationHandler(
        ResourceListChangedNotificationSchema,
        changed,
      );

      try {
        await server.stop();
        const resource = {
          arguments: [{ name: "id" }],
          load: async () => ({ text: "new" }),
          name: "new",
          uriTemplate: "file:///new/{id}",
        };
        if (batch) {
          server.addResourceTemplates([resource]);
        } else {
          server.addResourceTemplate(resource);
        }
        await expect.poll(() => changed.mock.calls.length).toBe(1);
        if (batch) {
          server.removeResourceTemplates(["old"]);
        } else {
          server.removeResourceTemplate("old");
        }

        expect(
          (await client.listResourceTemplates()).resourceTemplates.map(
            (resource) => resource.uriTemplate,
          ),
        ).toEqual(["file:///new/{id}"]);
        expect(
          await client.readResource({ uri: "file:///new/1" }),
        ).toMatchObject({ contents: [{ text: "new" }] });
        await expect(
          client.readResource({ uri: "file:///old/1" }),
        ).rejects.toThrow("Resource not found");
        await expect.poll(() => changed.mock.calls.length).toBe(2);
      } finally {
        await client.close();
        await session.close();
      }
    },
  );

  it.each([false, true])(
    "keeps caller-owned sessions' prompts current after stop (batch: %s)",
    async (batch) => {
      const server = new FastMCP({ name: "Test", version: "1.0.0" });
      server.addPrompt({ load: async () => "old", name: "old" });
      const { client, session } = await connectInMemory(server);
      const changed = vi.fn();
      client.setNotificationHandler(
        PromptListChangedNotificationSchema,
        changed,
      );

      try {
        await server.stop();
        const prompt = { load: async () => "new", name: "new" };
        if (batch) {
          server.addPrompts([prompt]);
        } else {
          server.addPrompt(prompt);
        }
        await expect.poll(() => changed.mock.calls.length).toBe(1);
        if (batch) {
          server.removePrompts(["old"]);
        } else {
          server.removePrompt("old");
        }

        expect(
          (await client.listPrompts()).prompts.map((prompt) => prompt.name),
        ).toEqual(["new"]);
        expect(await client.getPrompt({ name: "new" })).toMatchObject({
          messages: [{ content: { text: "new" } }],
        });
        await expect(client.getPrompt({ name: "old" })).rejects.toThrow(
          "Unknown prompt",
        );
        await expect.poll(() => changed.mock.calls.length).toBe(2);
      } finally {
        await client.close();
        await session.close();
      }
    },
  );

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

  it.each<{ content: Content; name: string }>([
    {
      content: {
        annotations: { audience: ["assistant"] },
        text: "For the model",
        type: "text",
      },
      name: "text annotations",
    },
    {
      content: {
        _meta: { source: "search" },
        text: "For the model",
        type: "text",
      },
      name: "text _meta",
    },
    {
      content: {
        _meta: { source: "search" },
        annotations: { audience: ["assistant"] },
        data: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
        mimeType: "image/png",
        type: "image",
      },
      name: "image annotations and _meta",
    },
    {
      content: {
        _meta: { source: "search" },
        annotations: { audience: ["assistant"] },
        data: "UklGRiQAAABXQVZFZm10IBAAAAABAAEAIAAgAAAAZGF0YQAAAAA=",
        mimeType: "audio/wav",
        type: "audio",
      },
      name: "audio annotations and _meta",
    },
    {
      content: {
        _meta: { source: "search" },
        annotations: { audience: ["assistant"] },
        resource: {
          _meta: { source: "document" },
          text: "Report contents",
          uri: "file:///report.txt",
        },
        type: "resource",
      },
      name: "embedded text annotations and _meta",
    },
    {
      content: {
        _meta: { source: "search" },
        annotations: { audience: ["assistant"] },
        resource: {
          _meta: { source: "document" },
          blob: "aGVsbG8=",
          uri: "file:///report.bin",
        },
        type: "resource",
      },
      name: "embedded blob annotations and _meta",
    },
  ])("preserves $name on tool result content", async ({ content }) => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    server.addTool({ execute: async () => content, name: "annotatedContent" });

    const { client, session } = await connectInMemory(server);
    try {
      expect(ContentBlockSchema.safeParse(content).success).toBe(true);
      expect(await client.callTool({ name: "annotatedContent" })).toEqual({
        content: [content],
      });
    } finally {
      await client.close();
      await session.close();
    }
  });

  it.each([
    { data: "not base64!", type: "image" },
    { data: "YQ", type: "image" },
    { data: "not base64!", type: "audio" },
    { data: "YQ", type: "audio" },
  ])("rejects invalid base64 $data in $type tool content", async (content) => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    server.addTool({
      execute: async () => ({
        ...content,
        mimeType: "application/octet-stream",
      }),
      name: "invalidContent",
    });

    const { client, session } = await connectInMemory(server);
    try {
      expect(await client.callTool({ name: "invalidContent" })).toEqual({
        content: [{ text: expect.stringContaining("base64"), type: "text" }],
        isError: true,
      });
    } finally {
      await client.close();
      await session.close();
    }
  });

  it.each([
    { text: "Report", type: "text" },
    { data: "aGVsbG8=", mimeType: "image/png", type: "image" },
    { data: "aGVsbG8=", mimeType: "audio/wav", type: "audio" },
    {
      resource: { text: "Report", uri: "file:///report.txt" },
      type: "resource",
    },
  ])("rejects unknown fields in $type tool content", async (content) => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    server.addTool({
      execute: async () => ({ ...content, unexpected: true }),
      name: "invalidContent",
    });

    const { client, session } = await connectInMemory(server);
    try {
      expect(await client.callTool({ name: "invalidContent" })).toEqual({
        content: [
          { text: expect.stringContaining("unexpected"), type: "text" },
        ],
        isError: true,
      });
    } finally {
      await client.close();
      await session.close();
    }
  });

  it.each([false, true])(
    "preserves resource link metadata in tool results (explicit result: %s)",
    async (explicitResult) => {
      const server = new FastMCP({ name: "Test", version: "1.0.0" });
      const link: ResourceLink = {
        _meta: { source: "search" },
        annotations: { audience: ["assistant"], priority: 0.8 },
        icons: [
          { mimeType: "image/png", src: "https://example.com/report.png" },
        ],
        name: "report",
        type: "resource_link",
        uri: "file:///report.txt",
      };
      server.addTool({
        execute: async () => (explicitResult ? { content: [link] } : link),
        name: "findReport",
      });

      const { client, session } = await connectInMemory(server);
      try {
        expect(ResourceLinkSchema.safeParse(link).success).toBe(true);
        expect(await client.callTool({ name: "findReport" })).toEqual({
          content: [link],
        });
      } finally {
        await client.close();
        await session.close();
      }
    },
  );

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

  it("uses a re-registered resource consistently for reads and embedded tool results", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    const uri = "file:///report.txt";
    server.addResource({
      load: async () => ({ text: "Previous report" }),
      name: "Previous report",
      uri,
    });
    server.addTool({
      execute: async () => ({
        resource: await server.embedded(uri),
        type: "resource",
      }),
      name: "embedReport",
    });

    const { client, session } = await connectInMemory(server);
    try {
      server.addResource({
        load: async () => ({ text: "Current report" }),
        name: "Current report",
        uri,
      });

      expect(await client.readResource({ uri })).toMatchObject({
        contents: [{ text: "Current report", uri }],
      });
      expect(await client.callTool({ name: "embedReport" })).toEqual({
        content: [
          { resource: { text: "Current report", uri }, type: "resource" },
        ],
      });

      server.removeResource("Current report");
      expect((await client.listResources()).resources).toEqual([]);
    } finally {
      await client.close();
      await session.close();
    }
  });

  it.each([false, true])(
    "uses the last resource in a batch for each URI (replacing existing: %s)",
    async (replaceExisting) => {
      const server = new FastMCP({ name: "Test", version: "1.0.0" });
      const uri = "file:///report.txt";
      if (replaceExisting) {
        server.addResource({
          load: async () => ({ text: "Previous report" }),
          name: "Previous report",
          uri,
        });
      }
      server.addResources([
        {
          load: async () => ({ text: "Intermediate report" }),
          name: "Intermediate report",
          uri,
        },
        {
          load: async () => ({ text: "Current report" }),
          name: "Current report",
          uri,
        },
      ]);
      server.addTool({
        execute: async () => ({
          resource: await server.embedded(uri),
          type: "resource",
        }),
        name: "embedReport",
      });

      const { client, session } = await connectInMemory(server);
      try {
        expect(await client.readResource({ uri })).toMatchObject({
          contents: [{ text: "Current report", uri }],
        });
        expect(await client.callTool({ name: "embedReport" })).toEqual({
          content: [
            { resource: { text: "Current report", uri }, type: "resource" },
          ],
        });

        server.removeResources(["Current report"]);
        expect((await client.listResources()).resources).toEqual([]);
      } finally {
        await client.close();
        await session.close();
      }
    },
  );

  it("uses the last resource in a batch for each name", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    server.addResources([
      {
        load: async () => ({ text: "Previous report" }),
        name: "Report",
        uri: "file:///previous.txt",
      },
      {
        load: async () => ({ text: "Current report" }),
        name: "Report",
        uri: "file:///current.txt",
      },
    ]);

    const { client, session } = await connectInMemory(server);
    try {
      expect((await client.listResources()).resources).toEqual([
        { name: "Report", uri: "file:///current.txt" },
      ]);
    } finally {
      await client.close();
      await session.close();
    }
  });

  it("completes enum arguments whose names match Object.prototype properties", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    server.addPrompt({
      arguments: ["toString", "constructor"].map((name) => ({
        enum: ["Germany"],
        name,
      })),
      load: async () => "Test",
      name: "countries",
    });

    const { client, session } = await connectInMemory(server);
    try {
      for (const name of ["toString", "constructor"]) {
        for (const value of ["", "Germ"]) {
          expect(
            await client.complete({
              argument: { name, value },
              ref: { name: "countries", type: "ref/prompt" },
            }),
          ).toEqual({ completion: { total: 1, values: ["Germany"] } });
        }
      }
    } finally {
      await client.close();
      await session.close();
    }
  });

  it("uses prompt-level completion for prototype property argument names", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    server.addPrompt({
      arguments: [{ name: "toString" }],
      complete: async (name, value) => ({ values: [`${name}:${value}`] }),
      load: async () => "Test",
      name: "fallback",
    });

    const { client, session } = await connectInMemory(server);
    try {
      expect(
        await client.complete({
          argument: { name: "toString", value: "test" },
          ref: { name: "fallback", type: "ref/prompt" },
        }),
      ).toEqual({ completion: { values: ["toString:test"] } });
    } finally {
      await client.close();
      await session.close();
    }
  });

  it("uses resource-level completion for prototype property argument names", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    server.addResourceTemplate({
      arguments: [{ name: "constructor" }],
      complete: async (name, value) => ({ values: [`${name}:${value}`] }),
      load: async () => ({ text: "Test" }),
      name: "fallback",
      uriTemplate: "test:///{constructor}",
    });

    const { client, session } = await connectInMemory(server);
    try {
      expect(
        await client.complete({
          argument: { name: "constructor", value: "test" },
          ref: { type: "ref/resource", uri: "test:///{constructor}" },
        }),
      ).toEqual({ completion: { values: ["constructor:test"] } });
    } finally {
      await client.close();
      await session.close();
    }
  });

  it("returns no completions for a prototype property without a completer", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    server.addPrompt({
      arguments: [{ name: "hasOwnProperty" }],
      load: async () => "Test",
      name: "empty",
    });

    const { client, session } = await connectInMemory(server);
    try {
      expect(
        await client.complete({
          argument: { name: "hasOwnProperty", value: "test" },
          ref: { name: "empty", type: "ref/prompt" },
        }),
      ).toEqual({ completion: { values: [] } });
    } finally {
      await client.close();
      await session.close();
    }
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

  it("leaves no session behind when the client hangs up during setup", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    const onConnect = vi.fn();
    const onDisconnect = vi.fn();
    server.on("connect", onConnect);
    server.on("disconnect", onDisconnect);

    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();

    const client = new Client(
      { name: "test-client", version: "0.0.0" },
      { capabilities: { roots: { listChanged: true } } },
    );

    let rootsRequested!: () => void;
    const rootsAsked = new Promise<void>((resolve) => {
      rootsRequested = resolve;
    });

    // Never answered, so the session is still being set up when the client
    // hangs up.
    client.setRequestHandler(ListRootsRequestSchema, () => {
      rootsRequested();

      return new Promise(() => {});
    });

    const connecting = server.connect(serverTransport);

    await client.connect(clientTransport);
    await rootsAsked;
    await client.close();

    const session = await connecting;

    expect(session.isReady).toBe(false);
    expect(server.sessions).toEqual([]);
    expect(onConnect).not.toHaveBeenCalled();
    expect(onDisconnect).not.toHaveBeenCalled();
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

  it("knows the client's capabilities and roots once connect resolves", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();

    const client = new Client(
      { name: "test-client", version: "0.0.0" },
      { capabilities: { roots: { listChanged: true } } },
    );

    client.setRequestHandler(ListRootsRequestSchema, () => ({
      roots: [{ name: "Frontend", uri: "file:///frontend" }],
    }));

    const [session] = await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);

    expect(session.clientCapabilities).toEqual({
      roots: { listChanged: true },
    });
    expect(session.roots).toEqual([
      { name: "Frontend", uri: "file:///frontend" },
    ]);
    expect(session.isReady).toBe(true);

    await client.close();
  });
});
