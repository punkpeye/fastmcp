import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
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
import { fetch } from "undici";
import { expect, test, vi } from "vitest";
import { z } from "zod";
import { z as z4 } from "zod/v4";

import {
  audioContent,
  type ContentResult,
  FastMCP,
  FastMCPSession,
  imageContent,
  type TextContent,
  UserError,
} from "./FastMCP.js";

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
    httpStream: {
      port,
    },
    transportType: "httpStream",
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
      server.on("connect", async (event) => {
        // Wait for session to be fully ready before resolving
        await event.session.waitForReady();
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

test("adds tools with Zod v4 schema", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      expect(await client.listTools()).toEqual({
        tools: [
          {
            description: "Add two numbers (using Zod v4 schema)",
            inputSchema: {
              $schema: "https://json-schema.org/draft/2020-12/schema",
              additionalProperties: false,
              properties: {
                a: { type: "number" },
                b: { type: "number" },
              },
              required: ["a", "b"],
              type: "object",
            },
            name: "add-zod-v4",
          },
        ],
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      const AddParamsZod4 = z4.object({
        a: z4.number(),
        b: z4.number(),
      });

      server.addTool({
        description: "Add two numbers (using Zod v4 schema)",
        execute: async (args) => {
          return String(args.a + args.b);
        },
        name: "add-zod-v4",
        parameters: AddParamsZod4,
      });

      return server;
    },
  });
});

test("health endpoint returns ok", async () => {
  const port = await getRandomPort();

  const server = new FastMCP({
    health: { message: "healthy", path: "/healthz" },
    name: "Test",
    version: "1.0.0",
  });

  await server.start({
    httpStream: { port },
    transportType: "httpStream",
  });

  try {
    const response = await fetch(`http://localhost:${port}/healthz`);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("healthy");
  } finally {
    await server.stop();
  }
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

test("returns an audio", async () => {
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
            data: "UklGRhwMAABXQVZFZm10IBAAAAABAAEAgD4AAIA+AAABAAgAZGF0Ya4LAACAgICAgICAgICAgICAgICAgICAgICAgICAf3hxeH+AfXZ1eHx6dnR5fYGFgoOKi42aloubq6GOjI2Op7ythXJ0eYF5aV1AOFFib32HmZSHhpCalIiYi4SRkZaLfnhxaWptb21qaWBea2BRYmZTVmFgWFNXVVVhaGdbYGhZbXh1gXZ1goeIlot1k6yxtKaOkaWhq7KonKCZoaCjoKWuqqmurK6ztrO7tbTAvru/vb68vbW6vLGqsLOfm5yal5KKhoyBeHt2dXBnbmljVlJWUEBBPDw9Mi4zKRwhIBYaGRQcHBURGB0XFxwhGxocJSstMjg6PTc6PUxVV1lWV2JqaXN0coCHhIyPjpOenqWppK6xu72yxMu9us7Pw83Wy9nY29ve6OPr6uvs6ezu6ejk6erm3uPj3dbT1sjBzdDFuMHAt7m1r7W6qaCupJOTkpWPgHqAd3JrbGlnY1peX1hTUk9PTFRKR0RFQkRBRUVEQkdBPjs9Pzo6NT04Njs+PTxAPzo/Ojk6PEA5PUJAQD04PkRCREZLUk1KT1BRUVdXU1VRV1tZV1xgXltcXF9hXl9eY2VmZmlna3J0b3F3eHyBfX+JgIWJiouTlZCTmpybnqSgnqyrqrO3srK2uL2/u7jAwMLFxsfEv8XLzcrIy83JzcrP0s3M0dTP0drY1dPR1dzc19za19XX2dnU1NjU0dXPzdHQy8rMysfGxMLBvLu3ta+sraeioJ2YlI+MioeFfX55cnJsaWVjXVlbVE5RTktHRUVAPDw3NC8uLyknKSIiJiUdHiEeGx4eHRwZHB8cHiAfHh8eHSEhISMoJyMnKisrLCszNy8yOTg9QEJFRUVITVFOTlJVWltaXmNfX2ZqZ21xb3R3eHqAhoeJkZKTlZmhpJ6kqKeur6yxtLW1trW4t6+us7axrbK2tLa6ury7u7u9u7vCwb+/vr7Ev7y9v8G8vby6vru4uLq+tri8ubi5t7W4uLW5uLKxs7G0tLGwt7Wvs7avr7O0tLW4trS4uLO1trW1trm1tLm0r7Kyr66wramsqaKlp52bmpeWl5KQkImEhIB8fXh3eHJrbW5mYGNcWFhUUE1LRENDQUI9ODcxLy8vMCsqLCgoKCgpKScoKCYoKygpKyssLi0sLi0uMDIwMTIuLzQ0Njg4Njc8ODlBQ0A/RUdGSU5RUVFUV1pdXWFjZGdpbG1vcXJ2eXh6fICAgIWIio2OkJGSlJWanJqbnZ2cn6Kkp6enq62srbCysrO1uLy4uL+/vL7CwMHAvb/Cvbq9vLm5uba2t7Sysq+urqyqqaalpqShoJ+enZuamZqXlZWTkpGSkpCNjpCMioqLioiHhoeGhYSGg4GDhoKDg4GBg4GBgoGBgoOChISChISChIWDg4WEgoSEgYODgYGCgYGAgICAgX99f398fX18e3p6e3t7enp7fHx4e3x6e3x7fHx9fX59fn1+fX19fH19fnx9fn19fX18fHx7fHx6fH18fXx8fHx7fH1+fXx+f319fn19fn1+gH9+f4B/fn+AgICAgH+AgICAgIGAgICAgH9+f4B+f35+fn58e3t8e3p5eXh4d3Z1dHRzcXBvb21sbmxqaWhlZmVjYmFfX2BfXV1cXFxaWVlaWVlYV1hYV1hYWVhZWFlaWllbXFpbXV5fX15fYWJhYmNiYWJhYWJjZGVmZ2hqbG1ub3Fxc3V3dnd6e3t8e3x+f3+AgICAgoGBgoKDhISFh4aHiYqKi4uMjYyOj4+QkZKUlZWXmJmbm52enqCioqSlpqeoqaqrrK2ur7CxsrGys7O0tbW2tba3t7i3uLe4t7a3t7i3tre2tba1tLSzsrKysbCvrq2sq6qop6alo6OioJ+dnJqZmJeWlJKSkI+OjoyLioiIh4WEg4GBgH9+fXt6eXh3d3V0c3JxcG9ubWxsamppaWhnZmVlZGRjYmNiYWBhYGBfYF9fXl5fXl1dXVxdXF1dXF1cXF1cXF1dXV5dXV5fXl9eX19gYGFgYWJhYmFiY2NiY2RjZGNkZWRlZGVmZmVmZmVmZ2dmZ2hnaGhnaGloZ2hpaWhpamlqaWpqa2pra2xtbGxtbm1ubm5vcG9wcXBxcnFycnN0c3N0dXV2d3d4eHh5ent6e3x9fn5/f4CAgIGCg4SEhYaGh4iIiYqLi4uMjY2Oj5CQkZGSk5OUlJWWlpeYl5iZmZqbm5ybnJ2cnZ6en56fn6ChoKChoqGio6KjpKOko6SjpKWkpaSkpKSlpKWkpaSlpKSlpKOkpKOko6KioaKhoaCfoJ+enp2dnJybmpmZmJeXlpWUk5STkZGQj4+OjYyLioqJh4eGhYSEgoKBgIB/fn59fHt7enl5eHd3dnZ1dHRzc3JycXBxcG9vbm5tbWxrbGxraWppaWhpaGdnZ2dmZ2ZlZmVmZWRlZGVkY2RjZGNkZGRkZGRkZGRkZGRjZGRkY2RjZGNkZWRlZGVmZWZmZ2ZnZ2doaWhpaWpra2xsbW5tbm9ub29wcXFycnNzdHV1dXZ2d3d4eXl6enp7fHx9fX5+f4CAgIGAgYGCgoOEhISFhoWGhoeIh4iJiImKiYqLiouLjI2MjI2OjY6Pj46PkI+QkZCRkJGQkZGSkZKRkpGSkZGRkZKRkpKRkpGSkZKRkpGSkZKRkpGSkZCRkZCRkI+Qj5CPkI+Pjo+OjY6Njo2MjYyLjIuMi4qLioqJiomJiImIh4iHh4aHhoaFhoWFhIWEg4SDg4KDgoKBgoGAgYCBgICAgICAf4CAf39+f35/fn1+fX59fHx9fH18e3x7fHt6e3p7ent6e3p5enl6enl6eXp5eXl4eXh5eHl4eXh5eHl4eXh5eHh3eHh4d3h4d3h3d3h4d3l4eHd4d3h3eHd4d3h3eHh4eXh5eHl4eHl4eXh5enl6eXp5enl6eXp5ent6ent6e3x7fHx9fH18fX19fn1+fX5/fn9+f4B/gH+Af4CAgICAgIGAgYCBgoGCgYKCgoKDgoOEg4OEg4SFhIWEhYSFhoWGhYaHhoeHhoeGh4iHiIiHiImIiImKiYqJiYqJiouKi4qLiouKi4qLiouKi4qLiouKi4qLi4qLiouKi4qLiomJiomIiYiJiImIh4iIh4iHhoeGhYWGhYaFhIWEg4OEg4KDgoOCgYKBgIGAgICAgH+Af39+f359fn18fX19fHx8e3t6e3p7enl6eXp5enl6enl5eXh5eHh5eHl4eXh5eHl4eHd5eHd3eHl4d3h3eHd4d3h3eHh4d3h4d3h3d3h5eHl4eXh5eHl5eXp5enl6eXp7ent6e3p7e3t7fHt8e3x8fHx9fH1+fX59fn9+f35/gH+AgICAgICAgYGAgYKBgoGCgoKDgoOEg4SEhIWFhIWFhoWGhYaGhoaHhoeGh4aHhoeIh4iHiIeHiIeIh4iHiIeIiIiHiIeIh4iHiIiHiIeIh4iHiIeIh4eIh4eIh4aHh4aHhoeGh4aHhoWGhYaFhoWFhIWEhYSFhIWEhISDhIOEg4OCg4OCg4KDgYKCgYKCgYCBgIGAgYCBgICAgICAgICAf4B/f4B/gH+Af35/fn9+f35/fn1+fn19fn1+fX59fn19fX19fH18fXx9fH18fXx9fH18fXx8fHt8e3x7fHt8e3x7fHt8e3x7fHt8e3x7fHt8e3x7fHt8e3x8e3x7fHt8e3x7fHx8fXx9fH18fX5+fX59fn9+f35+f35/gH+Af4B/gICAgICAgICAgICAgYCBgIGAgIGAgYGBgoGCgYKBgoGCgYKBgoGCgoKDgoOCg4KDgoOCg4KDgoOCg4KDgoOCg4KDgoOCg4KDgoOCg4KDgoOCg4KDgoOCg4KDgoOCg4KDgoOCg4KCgoGCgYKBgoGCgYKBgoGCgYKBgoGCgYKBgoGCgYKBgoGCgYKBgoGCgYKBgoGBgYCBgIGAgYCBgIGAgYCBgIGAgYCBgIGAgYCBgIGAgYCAgICBgIGAgYCBgIGAgYCBgIGAgYCBgExJU1RCAAAASU5GT0lDUkQMAAAAMjAwOC0wOS0yMQAASUVORwMAAAAgAAABSVNGVBYAAABTb255IFNvdW5kIEZvcmdlIDguMAAA",
            mimeType: "audio/wav",
            type: "audio",
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
          return audioContent({
            buffer: Buffer.from(
              "UklGRhwMAABXQVZFZm10IBAAAAABAAEAgD4AAIA+AAABAAgAZGF0Ya4LAACAgICAgICAgICAgICAgICAgICAgICAgICAf3hxeH+AfXZ1eHx6dnR5fYGFgoOKi42aloubq6GOjI2Op7ythXJ0eYF5aV1AOFFib32HmZSHhpCalIiYi4SRkZaLfnhxaWptb21qaWBea2BRYmZTVmFgWFNXVVVhaGdbYGhZbXh1gXZ1goeIlot1k6yxtKaOkaWhq7KonKCZoaCjoKWuqqmurK6ztrO7tbTAvru/vb68vbW6vLGqsLOfm5yal5KKhoyBeHt2dXBnbmljVlJWUEBBPDw9Mi4zKRwhIBYaGRQcHBURGB0XFxwhGxocJSstMjg6PTc6PUxVV1lWV2JqaXN0coCHhIyPjpOenqWppK6xu72yxMu9us7Pw83Wy9nY29ve6OPr6uvs6ezu6ejk6erm3uPj3dbT1sjBzdDFuMHAt7m1r7W6qaCupJOTkpWPgHqAd3JrbGlnY1peX1hTUk9PTFRKR0RFQkRBRUVEQkdBPjs9Pzo6NT04Njs+PTxAPzo/Ojk6PEA5PUJAQD04PkRCREZLUk1KT1BRUVdXU1VRV1tZV1xgXltcXF9hXl9eY2VmZmlna3J0b3F3eHyBfX+JgIWJiouTlZCTmpybnqSgnqyrqrO3srK2uL2/u7jAwMLFxsfEv8XLzcrIy83JzcrP0s3M0dTP0drY1dPR1dzc19za19XX2dnU1NjU0dXPzdHQy8rMysfGxMLBvLu3ta+sraeioJ2YlI+MioeFfX55cnJsaWVjXVlbVE5RTktHRUVAPDw3NC8uLyknKSIiJiUdHiEeGx4eHRwZHB8cHiAfHh8eHSEhISMoJyMnKisrLCszNy8yOTg9QEJFRUVITVFOTlJVWltaXmNfX2ZqZ21xb3R3eHqAhoeJkZKTlZmhpJ6kqKeur6yxtLW1trW4t6+us7axrbK2tLa6ury7u7u9u7vCwb+/vr7Ev7y9v8G8vby6vru4uLq+tri8ubi5t7W4uLW5uLKxs7G0tLGwt7Wvs7avr7O0tLW4trS4uLO1trW1trm1tLm0r7Kyr66wramsqaKlp52bmpeWl5KQkImEhIB8fXh3eHJrbW5mYGNcWFhUUE1LRENDQUI9ODcxLy8vMCsqLCgoKCgpKScoKCYoKygpKyssLi0sLi0uMDIwMTIuLzQ0Njg4Njc8ODlBQ0A/RUdGSU5RUVFUV1pdXWFjZGdpbG1vcXJ2eXh6fICAgIWIio2OkJGSlJWanJqbnZ2cn6Kkp6enq62srbCysrO1uLy4uL+/vL7CwMHAvb/Cvbq9vLm5uba2t7Sysq+urqyqqaalpqShoJ+enZuamZqXlZWTkpGSkpCNjpCMioqLioiHhoeGhYSGg4GDhoKDg4GBg4GBgoGBgoOChISChISChIWDg4WEgoSEgYODgYGCgYGAgICAgX99f398fX18e3p6e3t7enp7fHx4e3x6e3x7fHx9fX59fn1+fX19fH19fnx9fn19fX18fHx7fHx6fH18fXx8fHx7fH1+fXx+f319fn19fn1+gH9+f4B/fn+AgICAgH+AgICAgIGAgICAgH9+f4B+f35+fn58e3t8e3p5eXh4d3Z1dHRzcXBvb21sbmxqaWhlZmVjYmFfX2BfXV1cXFxaWVlaWVlYV1hYV1hYWVhZWFlaWllbXFpbXV5fX15fYWJhYmNiYWJhYWJjZGVmZ2hqbG1ub3Fxc3V3dnd6e3t8e3x+f3+AgICAgoGBgoKDhISFh4aHiYqKi4uMjYyOj4+QkZKUlZWXmJmbm52enqCioqSlpqeoqaqrrK2ur7CxsrGys7O0tbW2tba3t7i3uLe4t7a3t7i3tre2tba1tLSzsrKysbCvrq2sq6qop6alo6OioJ+dnJqZmJeWlJKSkI+OjoyLioiIh4WEg4GBgH9+fXt6eXh3d3V0c3JxcG9ubWxsamppaWhnZmVlZGRjYmNiYWBhYGBfYF9fXl5fXl1dXVxdXF1dXF1cXF1cXF1dXV5dXV5fXl9eX19gYGFgYWJhYmFiY2NiY2RjZGNkZWRlZGVmZmVmZmVmZ2dmZ2hnaGhnaGloZ2hpaWhpamlqaWpqa2pra2xtbGxtbm1ubm5vcG9wcXBxcnFycnN0c3N0dXV2d3d4eHh5ent6e3x9fn5/f4CAgIGCg4SEhYaGh4iIiYqLi4uMjY2Oj5CQkZGSk5OUlJWWlpeYl5iZmZqbm5ybnJ2cnZ6en56fn6ChoKChoqGio6KjpKOko6SjpKWkpaSkpKSlpKWkpaSlpKSlpKOkpKOko6KioaKhoaCfoJ+enp2dnJybmpmZmJeXlpWUk5STkZGQj4+OjYyLioqJh4eGhYSEgoKBgIB/fn59fHt7enl5eHd3dnZ1dHRzc3JycXBxcG9vbm5tbWxrbGxraWppaWhpaGdnZ2dmZ2ZlZmVmZWRlZGVkY2RjZGNkZGRkZGRkZGRkZGRjZGRkY2RjZGNkZWRlZGVmZWZmZ2ZnZ2doaWhpaWpra2xsbW5tbm9ub29wcXFycnNzdHV1dXZ2d3d4eXl6enp7fHx9fX5+f4CAgIGAgYGCgoOEhISFhoWGhoeIh4iJiImKiYqLiouLjI2MjI2OjY6Pj46PkI+QkZCRkJGQkZGSkZKRkpGSkZGRkZKRkpKRkpGSkZKRkpGSkZKRkpGSkZCRkZCRkI+Qj5CPkI+Pjo+OjY6Njo2MjYyLjIuMi4qLioqJiomJiImIh4iHh4aHhoaFhoWFhIWEg4SDg4KDgoKBgoGAgYCBgICAgICAf4CAf39+f35/fn1+fX59fHx9fH18e3x7fHt6e3p7ent6e3p5enl6enl6eXp5eXl4eXh5eHl4eXh5eHl4eXh5eHh3eHh4d3h4d3h3d3h4d3l4eHd4d3h3eHd4d3h3eHh4eXh5eHl4eHl4eXh5enl6eXp5enl6eXp5ent6ent6e3x7fHx9fH18fX19fn1+fX5/fn9+f4B/gH+Af4CAgICAgIGAgYCBgoGCgYKCgoKDgoOEg4OEg4SFhIWEhYSFhoWGhYaHhoeHhoeGh4iHiIiHiImIiImKiYqJiYqJiouKi4qLiouKi4qLiouKi4qLiouKi4qLi4qLiouKi4qLiomJiomIiYiJiImIh4iIh4iHhoeGhYWGhYaFhIWEg4OEg4KDgoOCgYKBgIGAgICAgH+Af39+f359fn18fX19fHx8e3t6e3p7enl6eXp5enl6enl5eXh5eHh5eHl4eXh5eHl4eHd5eHd3eHl4d3h3eHd4d3h3eHh4d3h4d3h3d3h5eHl4eXh5eHl5eXp5enl6eXp7ent6e3p7e3t7fHt8e3x8fHx9fH1+fX59fn9+f35/gH+AgICAgICAgYGAgYKBgoGCgoKDgoOEg4SEhIWFhIWFhoWGhYaGhoaHhoeGh4aHhoeIh4iHiIeHiIeIh4iHiIeIiIiHiIeIh4iHiIiHiIeIh4iHiIeIh4eIh4eIh4aHh4aHhoeGh4aHhoWGhYaFhoWFhIWEhYSFhIWEhISDhIOEg4OCg4OCg4KDgYKCgYKCgYCBgIGAgYCBgICAgICAgICAf4B/f4B/gH+Af35/fn9+f35/fn1+fn19fn1+fX59fn19fX19fH18fXx9fH18fXx9fH18fXx8fHt8e3x7fHt8e3x7fHt8e3x7fHt8e3x7fHt8e3x7fHt8e3x8e3x7fHt8e3x7fHx8fXx9fH18fX5+fX59fn9+f35+f35/gH+Af4B/gICAgICAgICAgICAgYCBgIGAgIGAgYGBgoGCgYKBgoGCgYKBgoGCgoKDgoOCg4KDgoOCg4KDgoOCg4KDgoOCg4KDgoOCg4KDgoOCg4KDgoOCg4KDgoOCg4KDgoOCg4KDgoOCg4KCgoGCgYKBgoGCgYKBgoGCgYKBgoGCgYKBgoGCgYKBgoGCgYKBgoGCgYKBgoGBgYCBgIGAgYCBgIGAgYCBgIGAgYCBgIGAgYCBgIGAgYCAgICBgIGAgYCBgIGAgYCBgIGAgYCBgExJU1RCAAAASU5GT0lDUkQMAAAAMjAwOC0wOS0yMQAASUVORwMAAAAgAAABSVNGVBYAAABTb255IFNvdW5kIEZvcmdlIDguMAAA",
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

test(
  "reports multiple progress updates without buffering",
  {
    // Earlier this test was flaky because the last progress update was not reported.
    // We are now running it 10 times to make sure that future updates do not regress.
    repeats: 10,
  },
  async () => {
    await runWithTestServer({
      run: async ({ client }) => {
        const progressCalls: Array<{ progress: number; total: number }> = [];

        const onProgress = vi.fn((data) => {
          progressCalls.push(data);
        });

        await client.callTool(
          {
            arguments: {
              steps: 3,
            },
            name: "progress-test",
          },
          undefined,
          {
            onprogress: onProgress,
          },
        );

        expect(onProgress).toHaveBeenCalledTimes(4);

        expect(progressCalls).toEqual([
          { progress: 0, total: 100 },
          { progress: 50, total: 100 },
          { progress: 90, total: 100 },
          { progress: 100, total: 100 }, // This was previously lost due to buffering
        ]);
      },
      server: async () => {
        const server = new FastMCP({
          name: "Test",
          version: "1.0.0",
        });

        server.addTool({
          description: "Test tool for progress buffering fix",
          execute: async (args, { reportProgress }) => {
            const { steps } = args;

            // Initial
            await reportProgress({ progress: 0, total: 100 });

            for (let i = 1; i <= steps; i++) {
              await delay(50); // Small delay to simulate work

              if (i === 1) {
                await reportProgress({ progress: 50, total: 100 });
              } else if (i === 2) {
                await reportProgress({ progress: 90, total: 100 });
              }
            }

            // This was the critical test case that failed before the fix
            // because there's no await after it, causing it to be buffered
            await reportProgress({ progress: 100, total: 100 });

            return "Progress test completed";
          },
          name: "progress-test",
          parameters: z.object({
            steps: z.number(),
          }),
        });

        return server;
      },
    });
  },
);

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

test("handles tool timeout", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      const result = await client.callTool({
        arguments: {
          a: 1500,
          b: 2,
        },
        name: "add",
      });

      expect(result.isError).toBe(true);

      const result_typed = result as ContentResult;

      expect(Array.isArray(result_typed.content)).toBe(true);
      expect(result_typed.content.length).toBe(1);

      const firstItem = result_typed.content[0] as TextContent;

      expect(firstItem.type).toBe("text");
      expect(firstItem.text).toBeDefined();
      expect(firstItem.text).toContain("timed out");
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addTool({
        description: "Add two numbers with potential timeout",
        execute: async (args) => {
          console.log(`Adding ${args.a} and ${args.b}`);

          if (args.a > 1000 || args.b > 1000) {
            await new Promise((resolve) => setTimeout(resolve, 3000));
          }

          return String(args.a + args.b);
        },
        name: "add",
        parameters: z.object({
          a: z.number(),
          b: z.number(),
        }),
        timeoutMs: 1000,
      });

      return server;
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

test("embedded resources work in tools", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      expect(
        await client.callTool({
          arguments: {
            userId: "123",
          },
          name: "get_user_profile",
        }),
      ).toEqual({
        content: [
          {
            resource: {
              mimeType: "application/json",
              text: '{"id":"123","name":"User","email":"user@example.com"}',
              uri: "user://profile/123",
            },
            type: "resource",
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
            name: "userId",
            required: true,
          },
        ],
        async load(args) {
          return {
            text: `{"id":"${args.userId}","name":"User","email":"user@example.com"}`,
          };
        },
        mimeType: "application/json",
        name: "User Profile",
        uriTemplate: "user://profile/{userId}",
      });

      server.addTool({
        description: "Get user profile data",
        execute: async (args) => {
          return {
            content: [
              {
                resource: await server.embedded(
                  `user://profile/${args.userId}`,
                ),
                type: "resource",
              },
            ],
          };
        },
        name: "get_user_profile",
        parameters: z.object({
          userId: z.string(),
        }),
      });

      return server;
    },
  });
});

test("embedded resources work with direct resources", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      expect(
        await client.callTool({
          arguments: {},
          name: "get_logs",
        }),
      ).toEqual({
        content: [
          {
            resource: {
              mimeType: "text/plain",
              text: "Example log content",
              uri: "file:///logs/app.log",
            },
            type: "resource",
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

      server.addTool({
        description: "Get application logs",
        execute: async () => {
          return {
            content: [
              {
                resource: await server.embedded("file:///logs/app.log"),
                type: "resource",
              },
            ],
          };
        },
        name: "get_logs",
        parameters: z.object({}),
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

  const onConnect = vi.fn().mockResolvedValue(undefined);
  const onDisconnect = vi.fn().mockResolvedValue(undefined);

  server.on("connect", onConnect);
  server.on("disconnect", onDisconnect);

  await server.start({
    httpStream: {
      port,
    },
    transportType: "httpStream",
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
    httpStream: {
      port,
    },
    transportType: "httpStream",
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

      expect(onPing.mock.calls.length).toBeGreaterThanOrEqual(1);
      expect(onPing.mock.calls.length).toBeLessThanOrEqual(3);
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        ping: {
          enabled: true,
          intervalMs: 1000,
        },
        version: "1.0.0",
      });
      return server;
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
            mimeType: "text/plain",
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

test(
  "HTTP Stream: custom endpoint works with /another-mcp",
  { timeout: 20000 },
  async () => {
    const port = await getRandomPort();

    // Create server with custom endpoint
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
      httpStream: {
        endpoint: "/another-mcp",
        port,
      },
      transportType: "httpStream",
    });

    try {
      // Create client
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
        new URL(`http://localhost:${port}/another-mcp`),
      );

      // Connect client to server and wait for session to be ready
      const sessionPromise = new Promise<FastMCPSession>((resolve) => {
        server.on("connect", async (event) => {
          await event.session.waitForReady();
          resolve(event.session);
        });
      });

      await client.connect(transport);
      await sessionPromise;

      // Call tool
      const result = await client.callTool({
        arguments: {
          a: 5,
          b: 7,
        },
        name: "add",
      });

      // Check result
      expect(result).toEqual({
        content: [{ text: "12", type: "text" }],
      });

      // Clean up connection
      await transport.terminateSession();
      await client.close();
    } finally {
      await server.stop();
    }
  },
);

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
          "MCP error -32602: MCP error -32602: Tool 'add' parameter validation failed: b: Expected number, received string. Please check the parameter types and values according to the tool's schema.",
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
          "MCP error -32602: MCP error -32602: Tool 'add' parameter validation failed: b: Expected number, received string. Please check the parameter types and values according to the tool's schema.",
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
    httpStream: {
      port,
    },
    transportType: "httpStream",
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
    httpStream: {
      port,
    },
    transportType: "httpStream",
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
    httpStream: {
      port,
    },
    transportType: "httpStream",
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
    httpStream: {
      port,
    },
    transportType: "httpStream",
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
      streamContent: expect.any(Function),
    },
  );
});

test("provides auth to resources", async () => {
  const port = await getRandomPort();

  const authenticate = vi.fn(async () => {
    return {
      role: "admin",
      userId: 42,
    };
  });

  const server = new FastMCP<{ role: string; userId: number }>({
    authenticate,
    name: "Test",
    version: "1.0.0",
  });

  const resourceLoad = vi.fn(async (auth) => {
    return {
      text: `User ${auth?.userId} with role ${auth?.role} loaded this resource`,
    };
  });

  server.addResource({
    load: resourceLoad,
    mimeType: "text/plain",
    name: "Auth Resource",
    uri: "auth://resource",
  });

  await server.start({
    httpStream: {
      port,
    },
    transportType: "httpStream",
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

  const result = await client.readResource({
    uri: "auth://resource",
  });

  expect(resourceLoad).toHaveBeenCalledTimes(1);
  expect(resourceLoad).toHaveBeenCalledWith({
    role: "admin",
    userId: 42,
  });

  expect(result).toEqual({
    contents: [
      {
        mimeType: "text/plain",
        name: "Auth Resource",
        text: "User 42 with role admin loaded this resource",
        uri: "auth://resource",
      },
    ],
  });
});

test("provides auth to resource templates", async () => {
  const port = await getRandomPort();

  const authenticate = vi.fn(async () => {
    return {
      permissions: ["read", "write"],
      userId: 99,
    };
  });

  const server = new FastMCP<{ permissions: string[]; userId: number }>({
    authenticate,
    name: "Test",
    version: "1.0.0",
  });

  const templateLoad = vi.fn(async (args, auth) => {
    return {
      text: `Resource ${args.resourceId} accessed by user ${auth?.userId} with permissions: ${auth?.permissions?.join(", ")}`,
    };
  });

  server.addResourceTemplate({
    arguments: [
      {
        name: "resourceId",
        required: true,
      },
    ],
    load: templateLoad,
    mimeType: "text/plain",
    name: "Auth Template",
    uriTemplate: "auth://template/{resourceId}",
  });

  await server.start({
    httpStream: {
      port,
    },
    transportType: "httpStream",
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

  const result = await client.readResource({
    uri: "auth://template/resource-123",
  });

  expect(templateLoad).toHaveBeenCalledTimes(1);
  expect(templateLoad).toHaveBeenCalledWith(
    { resourceId: "resource-123" },
    { permissions: ["read", "write"], userId: 99 },
  );

  expect(result).toEqual({
    contents: [
      {
        mimeType: "text/plain",
        name: "Auth Template",
        text: "Resource resource-123 accessed by user 99 with permissions: read, write",
        uri: "auth://template/resource-123",
      },
    ],
  });
});

test("provides auth to resource templates returning arrays", async () => {
  const port = await getRandomPort();

  const authenticate = vi.fn(async () => {
    return {
      accessLevel: 3,
      teamId: "team-alpha",
    };
  });

  const server = new FastMCP<{ accessLevel: number; teamId: string }>({
    authenticate,
    name: "Test",
    version: "1.0.0",
  });

  const templateLoad = vi.fn(async (args, auth) => {
    return [
      {
        text: `Document 1 for ${args.category} - Team: ${auth?.teamId}`,
      },
      {
        text: `Document 2 for ${args.category} - Access Level: ${auth?.accessLevel}`,
      },
    ];
  });

  server.addResourceTemplate({
    arguments: [
      {
        name: "category",
        required: true,
      },
    ],
    load: templateLoad,
    mimeType: "text/plain",
    name: "Multi Doc Template",
    uriTemplate: "docs://category/{category}",
  });

  await server.start({
    httpStream: {
      port,
    },
    transportType: "httpStream",
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

  const result = await client.readResource({
    uri: "docs://category/reports",
  });

  expect(templateLoad).toHaveBeenCalledTimes(1);
  expect(templateLoad).toHaveBeenCalledWith(
    { category: "reports" },
    { accessLevel: 3, teamId: "team-alpha" },
  );

  expect(result).toEqual({
    contents: [
      {
        mimeType: "text/plain",
        name: "Multi Doc Template",
        text: "Document 1 for reports - Team: team-alpha",
        uri: "docs://category/reports",
      },
      {
        mimeType: "text/plain",
        name: "Multi Doc Template",
        text: "Document 2 for reports - Access Level: 3",
        uri: "docs://category/reports",
      },
    ],
  });
});

test("provides auth to prompt argument completion", async () => {
  const port = await getRandomPort();

  const authenticate = vi.fn(async () => {
    return {
      department: "engineering",
      userId: 100,
    };
  });

  const server = new FastMCP<{ department: string; userId: number }>({
    authenticate,
    name: "Test",
    version: "1.0.0",
  });

  const promptCompleter = vi.fn(async (value: string, auth) => {
    return {
      values: [
        `${value}_user${auth?.userId}`,
        `${value}_dept${auth?.department}`,
      ],
    };
  });

  server.addPrompt({
    arguments: [
      {
        complete: promptCompleter,
        description: "Project name",
        name: "project",
        required: true,
      },
    ],
    async load(args) {
      return `Loading project: ${args.project}`;
    },
    name: "load-project",
  });

  await server.start({
    httpStream: {
      port,
    },
    transportType: "httpStream",
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

  const completionResult = await client.complete({
    argument: {
      name: "project",
      value: "test",
    },
    ref: {
      name: "load-project",
      type: "ref/prompt",
    },
  });

  expect(promptCompleter).toHaveBeenCalledTimes(1);
  expect(promptCompleter).toHaveBeenCalledWith("test", {
    department: "engineering",
    userId: 100,
  });

  expect(completionResult).toEqual({
    completion: {
      values: ["test_user100", "test_deptengineering"],
    },
  });
});

test("provides auth to prompt load function", async () => {
  const port = await getRandomPort();

  const authenticate = vi.fn(async () => {
    return {
      level: "admin",
      username: "testuser",
    };
  });

  const server = new FastMCP<{ level: string; username: string }>({
    authenticate,
    name: "Test",
    version: "1.0.0",
  });

  const promptLoad = vi.fn(async (args, auth) => {
    return `Welcome ${auth?.username} (${auth?.level}): You selected ${args.option}`;
  });

  server.addPrompt({
    arguments: [
      {
        description: "Option to select",
        name: "option",
        required: true,
      },
    ],
    load: promptLoad,
    name: "auth-prompt",
  });

  await server.start({
    httpStream: {
      port,
    },
    transportType: "httpStream",
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

  const result = await client.getPrompt({
    arguments: { option: "dashboard" },
    name: "auth-prompt",
  });

  expect(promptLoad).toHaveBeenCalledTimes(1);
  expect(promptLoad).toHaveBeenCalledWith(
    { option: "dashboard" },
    { level: "admin", username: "testuser" },
  );

  expect(result).toEqual({
    messages: [
      {
        content: {
          text: "Welcome testuser (admin): You selected dashboard",
          type: "text",
        },
        role: "user",
      },
    ],
  });
});

test("provides auth to resource template argument completion", async () => {
  const port = await getRandomPort();

  const authenticate = vi.fn(async () => {
    return {
      region: "us-west",
      teamId: "alpha",
    };
  });

  const server = new FastMCP<{ region: string; teamId: string }>({
    authenticate,
    name: "Test",
    version: "1.0.0",
  });

  const resourceCompleter = vi.fn(async (value: string, auth) => {
    return {
      values: [`${value}_${auth?.region}`, `${value}_team_${auth?.teamId}`],
    };
  });

  server.addResourceTemplate({
    arguments: [
      {
        complete: resourceCompleter,
        description: "Service ID",
        name: "serviceId",
        required: true,
      },
    ],
    async load(args) {
      return {
        text: `Service ${args.serviceId} data`,
      };
    },
    mimeType: "text/plain",
    name: "Service Resource",
    uriTemplate: "service://{serviceId}",
  });

  await server.start({
    httpStream: {
      port,
    },
    transportType: "httpStream",
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

  const completionResult = await client.complete({
    argument: {
      name: "serviceId",
      value: "api",
    },
    ref: {
      type: "ref/resource",
      uri: "service://{serviceId}",
    },
  });

  expect(resourceCompleter).toHaveBeenCalledTimes(1);
  expect(resourceCompleter).toHaveBeenCalledWith("api", {
    region: "us-west",
    teamId: "alpha",
  });

  expect(completionResult).toEqual({
    completion: {
      values: ["api_us-west", "api_team_alpha"],
    },
  });
});

test("supports streaming output from tools", async () => {
  let streamResult: { content: Array<{ text: string; type: string }> };

  await runWithTestServer({
    run: async ({ client }) => {
      const result = await client.callTool({
        arguments: {},
        name: "streaming-void-tool",
      });

      expect(result).toEqual({
        content: [],
      });

      streamResult = (await client.callTool({
        arguments: {},
        name: "streaming-with-result",
      })) as { content: Array<{ text: string; type: string }> };

      expect(streamResult).toEqual({
        content: [{ text: "Final result after streaming", type: "text" }],
      });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      server.addTool({
        annotations: {
          streamingHint: true,
        },
        description: "A streaming tool that returns void",
        execute: async (_args, context) => {
          await context.streamContent({
            text: "Streaming content 1",
            type: "text",
          });

          await context.streamContent({
            text: "Streaming content 2",
            type: "text",
          });

          // Return void
          return;
        },
        name: "streaming-void-tool",
        parameters: z.object({}),
      });

      server.addTool({
        annotations: {
          streamingHint: true,
        },
        description: "A streaming tool that returns a result.",
        execute: async (_args, context) => {
          await context.streamContent({
            text: "Streaming content 1",
            type: "text",
          });

          await context.streamContent({
            text: "Streaming content 2",
            type: "text",
          });

          return "Final result after streaming";
        },
        name: "streaming-with-result",
        parameters: z.object({}),
      });

      return server;
    },
  });
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
    httpStream: {
      port,
    },
    transportType: "httpStream",
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

test("filters tools based on canAccess property", async () => {
  const port = await getRandomPort();

  const server = new FastMCP<{ role: string }>({
    authenticate: async (request) => {
      const role = request.headers["x-role"] as string;
      return { role: role || "user" };
    },
    name: "Test",
    version: "1.0.0",
  });

  server.addTool({
    canAccess: (auth) => auth?.role === "admin",
    description: "Admin only",
    execute: async () => "admin",
    name: "admin-tool",
  });

  server.addTool({
    description: "Available to all",
    execute: async () => "public",
    name: "public-tool",
  });

  await server.start({ httpStream: { port }, transportType: "httpStream" });

  try {
    // Admin gets both tools
    const adminClient = new Client(
      { name: "admin", version: "1.0.0" },
      { capabilities: {} },
    );
    const adminTransport = new SSEClientTransport(
      new URL(`http://localhost:${port}/sse`),
      {
        eventSourceInit: {
          fetch: (url, init) =>
            fetch(url, {
              ...init,
              headers: { ...init?.headers, "x-role": "admin" },
            }),
        },
      },
    );
    await adminClient.connect(adminTransport);

    const adminTools = await adminClient.listTools();
    expect(adminTools.tools.map((t) => t.name).sort()).toEqual([
      "admin-tool",
      "public-tool",
    ]);

    // User gets only public tool
    const userClient = new Client(
      { name: "user", version: "1.0.0" },
      { capabilities: {} },
    );
    const userTransport = new SSEClientTransport(
      new URL(`http://localhost:${port}/sse`),
      {
        eventSourceInit: {
          fetch: (url, init) =>
            fetch(url, {
              ...init,
              headers: { ...init?.headers, "x-role": "user" },
            }),
        },
      },
    );
    await userClient.connect(userTransport);

    const userTools = await userClient.listTools();
    expect(userTools.tools.map((t) => t.name)).toEqual(["public-tool"]);

    await adminClient.close();
    await userClient.close();
  } finally {
    await server.stop();
  }
});

test("tools without canAccess are accessible to all", async () => {
  await runWithTestServer({
    run: async ({ client }) => {
      const tools = await client.listTools();
      expect(tools.tools).toHaveLength(1);
      expect(tools.tools[0].name).toBe("test-tool");

      const result = await client.callTool({
        arguments: {},
        name: "test-tool",
      });
      expect(
        (result.content as Array<{ text: string; type: string }>)[0],
      ).toEqual({ text: "success", type: "text" });
    },
    server: async () => {
      const server = new FastMCP({ name: "Test", version: "1.0.0" });
      server.addTool({
        description: "Test tool",
        execute: async () => "success",
        name: "test-tool",
      });
      return server;
    },
  });
});

test("canAccess works without authentication", async () => {
  const port = await getRandomPort();

  const server = new FastMCP<{ role: string }>({
    name: "Test",
    version: "1.0.0",
  });

  server.addTool({
    canAccess: (auth) => auth?.role === "admin",
    execute: async () => "admin",
    name: "admin-tool",
  });

  server.addTool({
    execute: async () => "public",
    name: "public-tool",
  });

  await server.start({ httpStream: { port }, transportType: "httpStream" });

  try {
    const client = new Client(
      { name: "test-client", version: "1.0.0" },
      { capabilities: {} },
    );
    const transport = new SSEClientTransport(
      new URL(`http://localhost:${port}/sse`),
    );
    await client.connect(transport);

    const tools = await client.listTools();
    expect(tools.tools.map((t) => t.name).sort()).toEqual([
      "admin-tool",
      "public-tool",
    ]);

    await client.close();
  } finally {
    await server.stop();
  }
});

// We now use a direct approach for testing HTTP Stream functionality
// rather than a helper function

// Set longer timeout for HTTP Stream tests
test("HTTP Stream: calls a tool", { timeout: 20000 }, async () => {
  console.log("Starting HTTP Stream test...");

  const port = await getRandomPort();

  // Create server directly (don't use helper function)
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
    httpStream: {
      port,
    },
    transportType: "httpStream",
  });

  try {
    // Create client
    const client = new Client(
      {
        name: "example-client",
        version: "1.0.0",
      },
      {
        capabilities: {},
      },
    );

    // IMPORTANT: Don't provide sessionId manually with HTTP streaming
    // The server will generate a session ID automatically
    const transport = new StreamableHTTPClientTransport(
      new URL(`http://localhost:${port}/mcp`),
    );

    // Connect client to server and wait for session to be ready
    const sessionPromise = new Promise<FastMCPSession>((resolve) => {
      server.on("connect", async (event) => {
        await event.session.waitForReady();
        resolve(event.session);
      });
    });

    await client.connect(transport);
    await sessionPromise;

    // Call tool
    const result = await client.callTool({
      arguments: {
        a: 1,
        b: 2,
      },
      name: "add",
    });

    // Check result
    expect(result).toEqual({
      content: [{ text: "3", type: "text" }],
    });

    // Clean up connection
    await transport.terminateSession();

    await client.close();
  } finally {
    await server.stop();
  }
});

test("uses `formatInvalidParamsErrorMessage` callback to build ErrorCode.InvalidParams error message", async () => {
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
          `MCP error -32602: MCP error -32602: Tool 'add' parameter validation failed: My custom error message: Field b failed with error 'Expected number, received string'. Please check the parameter types and values according to the tool's schema.`,
        );
      }
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        utils: {
          formatInvalidParamsErrorMessage: (issues) => {
            const message = issues
              .map((issue) => {
                const path = issue.path?.join(".") || "root";
                return `Field ${path} failed with error '${issue.message}'`;
              })
              .join(", ");
            return `My custom error message: ${message}`;
          },
        },
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

test("stateless mode works correctly", async () => {
  const port = await getRandomPort();

  const server = new FastMCP({
    name: "Test server",
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
    httpStream: {
      port,
      stateless: true,
    },
    transportType: "httpStream",
  });

  try {
    const client = new Client(
      {
        name: "Test client",
        version: "1.0.0",
      },
      {
        capabilities: {},
      },
    );

    const transport = new StreamableHTTPClientTransport(
      new URL(`http://localhost:${port}/mcp`),
    );

    await client.connect(transport);

    // Tool call should work in stateless mode
    const result = await client.callTool({
      arguments: { a: 5, b: 7 },
      name: "add",
    });

    expect(result.content).toEqual([
      {
        text: "12",
        type: "text",
      },
    ]);

    // Multiple calls should work independently in stateless mode
    const result2 = await client.callTool({
      arguments: { a: 10, b: 20 },
      name: "add",
    });

    expect(result2.content).toEqual([
      {
        text: "30",
        type: "text",
      },
    ]);

    // Server should not track sessions in stateless mode
    expect(server.sessions.length).toBe(0);

    await client.close();
  } finally {
    await server.stop();
  }
});

test("stateless mode health check includes mode indicator", async () => {
  const port = await getRandomPort();

  const server = new FastMCP({
    name: "Test server",
    version: "1.0.0",
  });

  await server.start({
    httpStream: {
      port,
      stateless: true,
    },
    transportType: "httpStream",
  });

  try {
    const response = await fetch(`http://localhost:${port}/ready`);
    expect(response.status).toBe(200);

    const json = await response.json();
    expect(json).toEqual({
      mode: "stateless",
      ready: 1,
      status: "ready",
      total: 1,
    });
  } finally {
    await server.stop();
  }
});
