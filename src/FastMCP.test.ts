import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import {
  CreateMessageRequestSchema,
  ErrorCode,
  ListRootsRequestSchema,
  LoggingMessageNotificationSchema,
  McpError,
  PingRequestSchema,
  Root,
} from "@modelcontextprotocol/sdk/types.js";
import { createEventSource, EventSourceClient } from "eventsource-client";
import { getRandomPort } from "get-port-please";
import { setTimeout as delay } from "timers/promises";
import { expect, test, vi } from "vitest";
import { z } from "zod";

import { FastMCP, FastMCPSession, imageContent, UserError } from "./FastMCP.js";

const runWithTestServer = async ({
  client: createClient,
  run,
  server: createServer,
}: {
  client?: () => Promise<Client>;
  run: ({
    client,
    server,
  }: {
    client: Client;
    server: FastMCP;
    session: FastMCPSession;
  }) => Promise<void>;
  server?: () => Promise<FastMCP>;
}) => {
  const port = await getRandomPort();

  const server = createServer
    ? await createServer()
    : new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

  await server.start({
    sse: {
      endpoint: "/sse",
      port,
    },
    transportType: "sse",
  });

  try {
    const client = createClient
      ? await createClient()
      : new Client(
          {
            name: "example-client",
            version: "1.0.0",
          },
          {
            capabilities: {},
          },
        );

    const transport = new SSEClientTransport(
      new URL(`http://localhost:${port}/sse`),
    );

    const session = await new Promise<FastMCPSession>((resolve) => {
      server.on("connect", (event) => {
        resolve(event.session);
      });

      client.connect(transport);
    });

    await run({ client, server, session });
  } finally {
    await server.stop();
  }

  return port;
};

test("adds tools", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      expect(await client.listTools()).toEqual({
        tools: [
          {
            description: "Add two numbers",
            inputSchema: {
              $schema: "http://json-schema.org/draft-07/schema#",
              additionalProperties: false,
              properties: {
                a: { type: "number" },
                b: { type: "number" },
              },
              required: ["a", "b"],
              type: "object",
            },
            name: "add",
          },
        ],
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addTool({
        description: "Add two numbers",
        execute: async (args) => {
          return String(args.a + args.b);
        },
        name: "add",
        parameters: z.object({
          a: z.number(),
          b: z.number(),
        }),
      });

      return server;
    },
  });
});

test("calls a tool", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      expect(
        await client.callTool({
          arguments: {
            a: 1,
            b: 2,
          },
          name: "add",
        }),
      ).toEqual({
        content: [{ text: "3", type: "text" }],
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addTool({
        description: "Add two numbers",
        execute: async (args) => {
          return String(args.a + args.b);
        },
        name: "add",
        parameters: z.object({
          a: z.number(),
          b: z.number(),
        }),
      });

      return server;
    },
  });
});

test("returns a list", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      expect(
        await client.callTool({
          arguments: {
            a: 1,
            b: 2,
          },
          name: "add",
        }),
      ).toEqual({
        content: [
          { text: "a", type: "text" },
          { text: "b", type: "text" },
        ],
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addTool({
        description: "Add two numbers",
        execute: async () => {
          return {
            content: [
              { text: "a", type: "text" },
              { text: "b", type: "text" },
            ],
          };
        },
        name: "add",
        parameters: z.object({
          a: z.number(),
          b: z.number(),
        }),
      });

      return server;
    },
  });
});

test("returns an image", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      expect(
        await client.callTool({
          arguments: {
            a: 1,
            b: 2,
          },
          name: "add",
        }),
      ).toEqual({
        content: [
          {
            data: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
            mimeType: "image/png",
            type: "image",
          },
        ],
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addTool({
        description: "Add two numbers",
        execute: async () => {
          return imageContent({
            buffer: Buffer.from(
              "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
              "base64",
            ),
          });
        },
        name: "add",
        parameters: z.object({
          a: z.number(),
          b: z.number(),
        }),
      });

      return server;
    },
  });
});

test("handles UserError errors", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      expect(
        await client.callTool({
          arguments: {
            a: 1,
            b: 2,
          },
          name: "add",
        }),
      ).toEqual({
        content: [{ text: "Something went wrong", type: "text" }],
        isError: true,
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addTool({
        description: "Add two numbers",
        execute: async () => {
          throw new UserError("Something went wrong");
        },
        name: "add",
        parameters: z.object({
          a: z.number(),
          b: z.number(),
        }),
      });

      return server;
    },
  });
});

test("calling an unknown tool throws McpError with MethodNotFound code", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      try {
        await client.callTool({
          arguments: {
            a: 1,
            b: 2,
          },
          name: "add",
        });
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);

        // @ts-expect-error - we know that error is an McpError
        expect(error.code).toBe(ErrorCode.MethodNotFound);
      }
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      return server;
    },
  });
});

test("tracks tool progress", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      const onProgress = vi.fn();

      await client.callTool(
        {
          arguments: {
            a: 1,
            b: 2,
          },
          name: "add",
        },
        undefined,
        {
          onprogress: onProgress,
        },
      );

      expect(onProgress).toHaveBeenCalledTimes(1);
      expect(onProgress).toHaveBeenCalledWith({
        progress: 0,
        total: 10,
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addTool({
        description: "Add two numbers",
        execute: async (args, { reportProgress }) => {
          reportProgress({
            progress: 0,
            total: 10,
          });

          await delay(100);

          return String(args.a + args.b);
        },
        name: "add",
        parameters: z.object({
          a: z.number(),
          b: z.number(),
        }),
      });

      return server;
    },
  });
});

test("sets logging levels", async () => {
  await runWithTestServer({
    run: async ({ client, session }) => {
      await client.setLoggingLevel("debug");

      expect(session.loggingLevel).toBe("debug");

      await client.setLoggingLevel("info");

      expect(session.loggingLevel).toBe("info");
    },
  });
});

test("sends logging messages to the client", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      const onLog = vi.fn();

      client.setNotificationHandler(
        LoggingMessageNotificationSchema,
        (message) => {
          if (message.method === "notifications/message") {
            onLog({
              level: message.params.level,
              ...(message.params.data ?? {}),
            });
          }
        },
      );

      await client.callTool({
        arguments: {
          a: 1,
          b: 2,
        },
        name: "add",
      });

      expect(onLog).toHaveBeenCalledTimes(4);
      expect(onLog).toHaveBeenNthCalledWith(1, {
        context: {
          foo: "bar",
        },
        level: "debug",
        message: "debug message",
      });
      expect(onLog).toHaveBeenNthCalledWith(2, {
        level: "error",
        message: "error message",
      });
      expect(onLog).toHaveBeenNthCalledWith(3, {
        level: "info",
        message: "info message",
      });
      expect(onLog).toHaveBeenNthCalledWith(4, {
        level: "warning",
        message: "warn message",
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addTool({
        description: "Add two numbers",
        execute: async (args, { log }) => {
          log.debug("debug message", {
            foo: "bar",
          });
          log.error("error message");
          log.info("info message");
          log.warn("warn message");

          return String(args.a + args.b);
        },
        name: "add",
        parameters: z.object({
          a: z.number(),
          b: z.number(),
        }),
      });

      return server;
    },
  });
});

test("adds resources", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      expect(await client.listResources()).toEqual({
        resources: [
          {
            mimeType: "text/plain",
            name: "Application Logs",
            uri: "file:///logs/app.log",
          },
        ],
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addResource({
        async load() {
          return {
            text: "Example log content",
          };
        },
        mimeType: "text/plain",
        name: "Application Logs",
        uri: "file:///logs/app.log",
      });

      return server;
    },
  });
});

test("clients reads a resource", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      expect(
        await client.readResource({
          uri: "file:///logs/app.log",
        }),
      ).toEqual({
        contents: [
          {
            mimeType: "text/plain",
            name: "Application Logs",
            text: "Example log content",
            uri: "file:///logs/app.log",
          },
        ],
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addResource({
        async load() {
          return {
            text: "Example log content",
          };
        },
        mimeType: "text/plain",
        name: "Application Logs",
        uri: "file:///logs/app.log",
      });

      return server;
    },
  });
});

test("clients reads a resource that returns multiple resources", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      expect(
        await client.readResource({
          uri: "file:///logs/app.log",
        }),
      ).toEqual({
        contents: [
          {
            mimeType: "text/plain",
            name: "Application Logs",
            text: "a",
            uri: "file:///logs/app.log",
          },
          {
            mimeType: "text/plain",
            name: "Application Logs",
            text: "b",
            uri: "file:///logs/app.log",
          },
        ],
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addResource({
        async load() {
          return [
            {
              text: "a",
            },
            {
              text: "b",
            },
          ];
        },
        mimeType: "text/plain",
        name: "Application Logs",
        uri: "file:///logs/app.log",
      });

      return server;
    },
  });
});

test("adds prompts", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      expect(
        await client.getPrompt({
          arguments: {
            changes: "foo",
          },
          name: "git-commit",
        }),
      ).toEqual({
        description: "Generate a Git commit message",
        messages: [
          {
            content: {
              text: "Generate a concise but descriptive commit message for these changes:\n\nfoo",
              type: "text",
            },
            role: "user",
          },
        ],
      });

      expect(await client.listPrompts()).toEqual({
        prompts: [
          {
            arguments: [
              {
                description: "Git diff or description of changes",
                name: "changes",
                required: true,
              },
            ],
            description: "Generate a Git commit message",
            name: "git-commit",
          },
        ],
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addPrompt({
        arguments: [
          {
            description: "Git diff or description of changes",
            name: "changes",
            required: true,
          },
        ],
        description: "Generate a Git commit message",
        load: async (args) => {
          return `Generate a concise but descriptive commit message for these changes:\n\n${args.changes}`;
        },
        name: "git-commit",
      });

      return server;
    },
  });
});

test("uses events to notify server of client connect/disconnect", async () => {
  const port = await getRandomPort();

  const server = new FastMCP({
    name: "Test",
    version: "1.0.0",
  });

  const onConnect = vi.fn();
  const onDisconnect = vi.fn();

  server.on("connect", onConnect);
  server.on("disconnect", onDisconnect);

  await server.start({
    sse: {
      endpoint: "/sse",
      port,
    },
    transportType: "sse",
  });

  const client = new Client(
    {
      name: "example-client",
      version: "1.0.0",
    },
    {
      capabilities: {},
    },
  );

  const transport = new SSEClientTransport(
    new URL(`http://localhost:${port}/sse`),
  );

  await client.connect(transport);

  await delay(100);

  expect(onConnect).toHaveBeenCalledTimes(1);
  expect(onDisconnect).toHaveBeenCalledTimes(0);

  expect(server.sessions).toEqual([expect.any(FastMCPSession)]);

  await client.close();

  await delay(100);

  expect(onConnect).toHaveBeenCalledTimes(1);
  expect(onDisconnect).toHaveBeenCalledTimes(1);

  await server.stop();
});

test("handles multiple clients", async () => {
  const port = await getRandomPort();

  const server = new FastMCP({
    name: "Test",
    version: "1.0.0",
  });

  await server.start({
    sse: {
      endpoint: "/sse",
      port,
    },
    transportType: "sse",
  });

  const client1 = new Client(
    {
      name: "example-client",
      version: "1.0.0",
    },
    {
      capabilities: {},
    },
  );

  const transport1 = new SSEClientTransport(
    new URL(`http://localhost:${port}/sse`),
  );

  await client1.connect(transport1);

  const client2 = new Client(
    {
      name: "example-client",
      version: "1.0.0",
    },
    {
      capabilities: {},
    },
  );

  const transport2 = new SSEClientTransport(
    new URL(`http://localhost:${port}/sse`),
  );

  await client2.connect(transport2);

  await delay(100);

  expect(server.sessions).toEqual([
    expect.any(FastMCPSession),
    expect.any(FastMCPSession),
  ]);

  await server.stop();
});

test("session knows about client capabilities", async () => {
  await runWithTestServer({
    client: async () => {
      const client = new Client(
        {
          name: "example-client",
          version: "1.0.0",
        },
        {
          capabilities: {
            roots: {
              listChanged: true,
            },
          },
        },
      );

      client.setRequestHandler(ListRootsRequestSchema, () => {
        return {
          roots: [
            {
              name: "Frontend Repository",
              uri: "file:///home/user/projects/frontend",
            },
          ],
        };
      });

      return client;
    },
    run: async ({ session }) => {
      expect(session.clientCapabilities).toEqual({
        roots: {
          listChanged: true,
        },
      });
    },
  });
});

test("session knows about roots", async () => {
  await runWithTestServer({
    client: async () => {
      const client = new Client(
        {
          name: "example-client",
          version: "1.0.0",
        },
        {
          capabilities: {
            roots: {
              listChanged: true,
            },
          },
        },
      );

      client.setRequestHandler(ListRootsRequestSchema, () => {
        return {
          roots: [
            {
              name: "Frontend Repository",
              uri: "file:///home/user/projects/frontend",
            },
          ],
        };
      });

      return client;
    },
    run: async ({ session }) => {
      expect(session.roots).toEqual([
        {
          name: "Frontend Repository",
          uri: "file:///home/user/projects/frontend",
        },
      ]);
    },
  });
});

test("session listens to roots changes", async () => {
  const clientRoots: Root[] = [
    {
      name: "Frontend Repository",
      uri: "file:///home/user/projects/frontend",
    },
  ];

  await runWithTestServer({
    client: async () => {
      const client = new Client(
        {
          name: "example-client",
          version: "1.0.0",
        },
        {
          capabilities: {
            roots: {
              listChanged: true,
            },
          },
        },
      );

      client.setRequestHandler(ListRootsRequestSchema, () => {
        return {
          roots: clientRoots,
        };
      });

      return client;
    },
    run: async ({ client, session }) => {
      expect(session.roots).toEqual([
        {
          name: "Frontend Repository",
          uri: "file:///home/user/projects/frontend",
        },
      ]);

      clientRoots.push({
        name: "Backend Repository",
        uri: "file:///home/user/projects/backend",
      });

      await client.sendRootsListChanged();

      const onRootsChanged = vi.fn();

      session.on("rootsChanged", onRootsChanged);

      await delay(100);

      expect(session.roots).toEqual([
        {
          name: "Frontend Repository",
          uri: "file:///home/user/projects/frontend",
        },
        {
          name: "Backend Repository",
          uri: "file:///home/user/projects/backend",
        },
      ]);

      expect(onRootsChanged).toHaveBeenCalledTimes(1);
      expect(onRootsChanged).toHaveBeenCalledWith({
        roots: [
          {
            name: "Frontend Repository",
            uri: "file:///home/user/projects/frontend",
          },
          {
            name: "Backend Repository",
            uri: "file:///home/user/projects/backend",
          },
        ],
      });
    },
  });
});

test("session sends pings to the client", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      const onPing = vi.fn().mockReturnValue({});

      client.setRequestHandler(PingRequestSchema, onPing);

      await delay(2000);

      expect(onPing).toHaveBeenCalledTimes(1);
    },
  });
});

test("completes prompt arguments", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      const response = await client.complete({
        argument: {
          name: "name",
          value: "Germ",
        },
        ref: {
          name: "countryPoem",
          type: "ref/prompt",
        },
      });

      expect(response).toEqual({
        completion: {
          values: ["Germany"],
        },
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addPrompt({
        arguments: [
          {
            complete: async (value) => {
              if (value === "Germ") {
                return {
                  values: ["Germany"],
                };
              }

              return {
                values: [],
              };
            },
            description: "Name of the country",
            name: "name",
            required: true,
          },
        ],
        description: "Writes a poem about a country",
        load: async ({ name }) => {
          return `Hello, ${name}!`;
        },
        name: "countryPoem",
      });

      return server;
    },
  });
});

test("adds automatic prompt argument completion when enum is provided", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      const response = await client.complete({
        argument: {
          name: "name",
          value: "Germ",
        },
        ref: {
          name: "countryPoem",
          type: "ref/prompt",
        },
      });

      expect(response).toEqual({
        completion: {
          total: 1,
          values: ["Germany"],
        },
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addPrompt({
        arguments: [
          {
            description: "Name of the country",
            enum: ["Germany", "France", "Italy"],
            name: "name",
            required: true,
          },
        ],
        description: "Writes a poem about a country",
        load: async ({ name }) => {
          return `Hello, ${name}!`;
        },
        name: "countryPoem",
      });

      return server;
    },
  });
});

test("completes template resource arguments", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      const response = await client.complete({
        argument: {
          name: "issueId",
          value: "123",
        },
        ref: {
          type: "ref/resource",
          uri: "issue:///{issueId}",
        },
      });

      expect(response).toEqual({
        completion: {
          values: ["123456"],
        },
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addResourceTemplate({
        arguments: [
          {
            complete: async (value) => {
              if (value === "123") {
                return {
                  values: ["123456"],
                };
              }

              return {
                values: [],
              };
            },
            description: "ID of the issue",
            name: "issueId",
          },
        ],
        load: async ({ issueId }) => {
          return {
            text: `Issue ${issueId}`,
          };
        },
        mimeType: "text/plain",
        name: "Issue",
        uriTemplate: "issue:///{issueId}",
      });

      return server;
    },
  });
});

test("lists resource templates", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      expect(await client.listResourceTemplates()).toEqual({
        resourceTemplates: [
          {
            name: "Application Logs",
            uriTemplate: "file:///logs/{name}.log",
          },
        ],
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addResourceTemplate({
        arguments: [
          {
            description: "Name of the log",
            name: "name",
            required: true,
          },
        ],
        load: async ({ name }) => {
          return {
            text: `Example log content for ${name}`,
          };
        },
        mimeType: "text/plain",
        name: "Application Logs",
        uriTemplate: "file:///logs/{name}.log",
      });

      return server;
    },
  });
});

test("clients reads a resource accessed via a resource template", async () => {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const loadSpy = vi.fn((_args) => {
    return {
      text: "Example log content",
    };
  });

  await runWithTestServer({
    run: async ({ client }) => {
      expect(
        await client.readResource({
          uri: "file:///logs/app.log",
        }),
      ).toEqual({
        contents: [
          {
            mimeType: "text/plain",
            name: "Application Logs",
            text: "Example log content",
            uri: "file:///logs/app.log",
          },
        ],
      });

      expect(loadSpy).toHaveBeenCalledWith({
        name: "app",
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addResourceTemplate({
        arguments: [
          {
            description: "Name of the log",
            name: "name",
          },
        ],
        async load(args) {
          return loadSpy(args);
        },
        mimeType: "text/plain",
        name: "Application Logs",
        uriTemplate: "file:///logs/{name}.log",
      });

      return server;
    },
  });
});

test("makes a sampling request", async () => {
  const onMessageRequest = vi.fn(() => {
    return {
      content: {
        text: "The files are in the current directory.",
        type: "text",
      },
      model: "gpt-3.5-turbo",
      role: "assistant",
    };
  });

  await runWithTestServer({
    client: async () => {
      const client = new Client(
        {
          name: "example-client",
          version: "1.0.0",
        },
        {
          capabilities: {
            sampling: {},
          },
        },
      );
      return client;
    },
    run: async ({ client, session }) => {
      client.setRequestHandler(CreateMessageRequestSchema, onMessageRequest);

      const response = await session.requestSampling({
        includeContext: "thisServer",
        maxTokens: 100,
        messages: [
          {
            content: {
              text: "What files are in the current directory?",
              type: "text",
            },
            role: "user",
          },
        ],
        systemPrompt: "You are a helpful file system assistant.",
      });

      expect(response).toEqual({
        content: {
          text: "The files are in the current directory.",
          type: "text",
        },
        model: "gpt-3.5-turbo",
        role: "assistant",
      });

      expect(onMessageRequest).toHaveBeenCalledTimes(1);
    },
  });
});

test("throws ErrorCode.InvalidParams if tool parameters do not match zod schema", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      try {
        await client.callTool({
          arguments: {
            a: 1,
            b: "invalid",
          },
          name: "add",
        });
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);

        // @ts-expect-error - we know that error is an McpError
        expect(error.code).toBe(ErrorCode.InvalidParams);

        // @ts-expect-error - we know that error is an McpError
        expect(error.message).toBe(
          "MCP error -32602: MCP error -32602: Invalid add parameters: [{\"code\":\"invalid_type\",\"expected\":\"number\",\"received\":\"string\",\"path\":[\"b\"],\"message\":\"Expected number, received string\"}]",
        );
      }
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addTool({
        description: "Add two numbers",
        execute: async (args) => {
          return String(args.a + args.b);
        },
        name: "add",
        parameters: z.object({
          a: z.number(),
          b: z.number(),
        }),
      });

      return server;
    },
  });
});

test("server remains usable after InvalidParams error", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      try {
        await client.callTool({
          arguments: {
            a: 1,
            b: "invalid",
          },
          name: "add",
        });
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);

        // @ts-expect-error - we know that error is an McpError
        expect(error.code).toBe(ErrorCode.InvalidParams);

        // @ts-expect-error - we know that error is an McpError
        expect(error.message).toBe(
          "MCP error -32602: MCP error -32602: Invalid add parameters: [{\"code\":\"invalid_type\",\"expected\":\"number\",\"received\":\"string\",\"path\":[\"b\"],\"message\":\"Expected number, received string\"}]",
        );
      }

      expect(
        await client.callTool({
          arguments: {
            a: 1,
            b: 2,
          },
          name: "add",
        }),
      ).toEqual({
        content: [{ text: "3", type: "text" }],
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addTool({
        description: "Add two numbers",
        execute: async (args) => {
          return String(args.a + args.b);
        },
        name: "add",
        parameters: z.object({
          a: z.number(),
          b: z.number(),
        }),
      });

      return server;
    },
  });
});

test("allows new clients to connect after a client disconnects", async () => {
  const port = await getRandomPort();

  const server = new FastMCP({
    name: "Test",
    version: "1.0.0",
  });

  server.addTool({
    description: "Add two numbers",
    execute: async (args) => {
      return String(args.a + args.b);
    },
    name: "add",
    parameters: z.object({
      a: z.number(),
      b: z.number(),
    }),
  });

  await server.start({
    sse: {
      endpoint: "/sse",
      port,
    },
    transportType: "sse",
  });

  const client1 = new Client(
    {
      name: "example-client",
      version: "1.0.0",
    },
    {
      capabilities: {},
    },
  );

  const transport1 = new SSEClientTransport(
    new URL(`http://localhost:${port}/sse`),
  );

  await client1.connect(transport1);

  expect(
    await client1.callTool({
      arguments: {
        a: 1,
        b: 2,
      },
      name: "add",
    }),
  ).toEqual({
    content: [{ text: "3", type: "text" }],
  });

  await client1.close();

  const client2 = new Client(
    {
      name: "example-client",
      version: "1.0.0",
    },
    {
      capabilities: {},
    },
  );

  const transport2 = new SSEClientTransport(
    new URL(`http://localhost:${port}/sse`),
  );

  await client2.connect(transport2);

  expect(
    await client2.callTool({
      arguments: {
        a: 1,
        b: 2,
      },
      name: "add",
    }),
  ).toEqual({
    content: [{ text: "3", type: "text" }],
  });

  await client2.close();

  await server.stop();
});

test("able to close server immediately after starting it", async () => {
  const port = await getRandomPort();

  const server = new FastMCP({
    name: "Test",
    version: "1.0.0",
  });

  await server.start({
    sse: {
      endpoint: "/sse",
      port,
    },
    transportType: "sse",
  });

  // We were previously not waiting for the server to start.
  // Therefore, this would have caused error 'Server is not running.'.
  await server.stop();
});

test("closing event source does not produce error", async () => {
  const port = await getRandomPort();

  const server = new FastMCP({
    name: "Test",
    version: "1.0.0",
  });

  server.addTool({
    description: "Add two numbers",
    execute: async (args) => {
      return String(args.a + args.b);
    },
    name: "add",
    parameters: z.object({
      a: z.number(),
      b: z.number(),
    }),
  });

  await server.start({
    sse: {
      endpoint: "/sse",
      port,
    },
    transportType: "sse",
  });

  const eventSource = await new Promise<EventSourceClient>((onMessage) => {
    const eventSource = createEventSource({
      onConnect: () => {
        console.info("connected");
      },
      onDisconnect: () => {
        console.info("disconnected");
      },
      onMessage: () => {
        onMessage(eventSource);
      },
      url: `http://127.0.0.1:${port}/sse`,
    });
  });

  expect(eventSource.readyState).toBe("open");

  eventSource.close();

  // We were getting unhandled error 'Not connected'
  // https://github.com/punkpeye/mcp-proxy/commit/62cf27d5e3dfcbc353e8d03c7714a62c37177b52
  await delay(1000);

  await server.stop();
});

test("provides auth to tools", async () => {
  const port = await getRandomPort();

  const authenticate = vi.fn(async () => {
    return {
      id: 1,
    };
  });

  const server = new FastMCP<{ id: number }>({
    authenticate,
    name: "Test",
    version: "1.0.0",
  });

  const execute = vi.fn(async (args) => {
    return String(args.a + args.b);
  });

  server.addTool({
    description: "Add two numbers",
    execute,
    name: "add",
    parameters: z.object({
      a: z.number(),
      b: z.number(),
    }),
  });

  await server.start({
    sse: {
      endpoint: "/sse",
      port,
    },
    transportType: "sse",
  });

  const client = new Client(
    {
      name: "example-client",
      version: "1.0.0",
    },
    {
      capabilities: {},
    },
  );

  const transport = new SSEClientTransport(
    new URL(`http://localhost:${port}/sse`),
    {
      eventSourceInit: {
        fetch: async (url, init) => {
          return fetch(url, {
            ...init,
            headers: {
              ...init?.headers,
              "x-api-key": "123",
            },
          });
        },
      },
    },
  );

  await client.connect(transport);

  expect(
    authenticate,
    "authenticate should have been called",
  ).toHaveBeenCalledTimes(1);

  expect(
    await client.callTool({
      arguments: {
        a: 1,
        b: 2,
      },
      name: "add",
    }),
  ).toEqual({
    content: [{ text: "3", type: "text" }],
  });

  expect(execute, "execute should have been called").toHaveBeenCalledTimes(1);

  expect(execute).toHaveBeenCalledWith(
    {
      a: 1,
      b: 2,
    },
    {
      log: {
        debug: expect.any(Function),
        error: expect.any(Function),
        info: expect.any(Function),
        warn: expect.any(Function),
      },
      reportProgress: expect.any(Function),
      session: { id: 1 },
    },
  );
});

test("blocks unauthorized requests", async () => {
  const port = await getRandomPort();

  const server = new FastMCP<{ id: number }>({
    authenticate: async () => {
      throw new Response(null, {
        status: 401,
        statusText: "Unauthorized",
      });
    },
    name: "Test",
    version: "1.0.0",
  });

  await server.start({
    sse: {
      endpoint: "/sse",
      port,
    },
    transportType: "sse",
  });

  const client = new Client(
    {
      name: "example-client",
      version: "1.0.0",
    },
    {
      capabilities: {},
    },
  );

  const transport = new SSEClientTransport(
    new URL(`http://localhost:${port}/sse`),
  );

  expect(async () => {
    await client.connect(transport);
  }).rejects.toThrow("SSE error: Non-200 status code (401)");
});
