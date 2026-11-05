import { extractWWWAuthenticateParams } from "@modelcontextprotocol/sdk/client/auth.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { expect, test, vi } from "vitest";

import { FastMCP, type ServerOptions } from "./FastMCP.js";
import { getTestPort } from "./getTestPort.js";

/**
 * A tool's `scopes` keep it listed but stop a call without them, with MCP's 403
 * `insufficient_scope` challenge over HTTP (2025-11-25, Scope Challenge
 * Handling) and with a JSON-RPC error elsewhere.
 *
 * Requested in #212.
 */

type Auth = { scopes: string[] };

/** The bearer tokens `authenticate` accepts, and what each one grants. */
const TOKENS = new Map<string, Auth>([
  ["Bearer read-write", { scopes: ["files:read", "files:write"] }],
  ["Bearer read", { scopes: ["files:read"] }],
]);

const DESCRIPTION =
  "Insufficient scope for tool 'write_file': requires files:write";

const createServer = (options: Partial<ServerOptions<Auth>> = {}) => {
  const execute = vi.fn(async () => "written");
  const server = new FastMCP<Auth>({
    authenticate: async (request) =>
      TOKENS.get(request.headers.authorization ?? ""),
    name: "Test",
    version: "1.0.0",
    ...options,
  });

  server.addTool({
    description: "Writes a file",
    execute,
    name: "write_file",
    scopes: ["files:write"],
  });
  server.addTool({
    description: "Reads a file",
    execute: async () => "read",
    name: "read_file",
  });

  return { execute, server };
};

const connectInMemory = async (server: FastMCP<Auth>, auth?: Auth) => {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "client", version: "1.0.0" });

  await Promise.all([
    server.connect(serverTransport, auth),
    client.connect(clientTransport),
  ]);

  return client;
};

/** POSTs JSON-RPC to the `/mcp` endpoint with a bearer token. */
const post = (port: number, token: string, body: unknown, sessionId?: string) =>
  fetch(`http://localhost:${port}/mcp`, {
    body: JSON.stringify(body),
    headers: {
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      "mcp-protocol-version": "2025-11-25",
      ...(sessionId ? { "mcp-session-id": sessionId } : {}),
    },
    method: "POST",
  });

/** Opens a stateful session and returns its id. */
const openSession = async (port: number, token: string) => {
  const initialize = await post(port, token, {
    id: 0,
    jsonrpc: "2.0",
    method: "initialize",
    params: {
      capabilities: {},
      clientInfo: { name: "client", version: "1.0.0" },
      protocolVersion: "2025-11-25",
    },
  });
  await initialize.text();

  const sessionId = initialize.headers.get("mcp-session-id")!;
  const initialized = await post(
    port,
    token,
    { jsonrpc: "2.0", method: "notifications/initialized" },
    sessionId,
  );
  await initialized.text();

  return sessionId;
};

const callTool = (name: string, id: number) => ({
  id,
  jsonrpc: "2.0",
  method: "tools/call",
  params: { arguments: {}, name },
});

/** The JSON-RPC message in a 200, sent as JSON or as an SSE `data:` line. */
const readMessage = async (response: Response) => {
  const text = await response.text();
  const data = text
    .split("\n")
    .filter((line) => line.startsWith("data: {"))
    .pop();

  return JSON.parse(data ? data.slice("data: ".length) : text);
};

test("lists a tool whose scopes the session lacks", async () => {
  const { server } = createServer();
  const client = await connectInMemory(server, { scopes: ["files:read"] });

  try {
    expect(
      (await client.listTools()).tools.map((tool) => tool.name).sort(),
    ).toEqual(["read_file", "write_file"]);
  } finally {
    await client.close();
  }
});

test("answers an HTTP call without the tool's scopes with a 403 scope challenge", async () => {
  const port = await getTestPort();
  const { execute, server } = createServer();

  await server.start({ httpStream: { port }, transportType: "httpStream" });

  try {
    const sessionId = await openSession(port, "read");
    const response = await post(
      port,
      "read",
      callTool("write_file", 7),
      sessionId,
    );

    expect(response.status).toBe(403);
    // The scopes the session has plus the ones the tool needs, so that the
    // new token does not drop any.
    expect(response.headers.get("www-authenticate")).toBe(
      `Bearer error="insufficient_scope", scope="files:read files:write", error_description="${DESCRIPTION}"`,
    );
    // What the MCP SDK's client reads from it before it re-authorizes.
    expect(extractWWWAuthenticateParams(response)).toEqual({
      error: "insufficient_scope",
      resourceMetadataUrl: undefined,
      scope: "files:read files:write",
    });
    expect(await response.json()).toEqual({
      error: {
        code: -32003,
        data: {
          error: "insufficient_scope",
          required_scopes: ["files:read", "files:write"],
        },
        message: DESCRIPTION,
      },
      id: 7,
      jsonrpc: "2.0",
    });
    expect(execute).not.toHaveBeenCalled();

    // A tool without scopes is unaffected.
    const read = await post(port, "read", callTool("read_file", 8), sessionId);

    expect(read.status).toBe(200);
    expect((await readMessage(read)).result.content).toEqual([
      { text: "read", type: "text" },
    ]);
  } finally {
    await server.stop();
  }
});

test("runs the call once the same session presents a token with the scopes", async () => {
  const port = await getTestPort();
  const { server } = createServer();

  await server.start({ httpStream: { port }, transportType: "httpStream" });

  try {
    const sessionId = await openSession(port, "read");
    const denied = await post(
      port,
      "read",
      callTool("write_file", 1),
      sessionId,
    );
    await denied.text();

    expect(denied.status).toBe(403);

    // The client re-authorized for the challenged scopes and retries.
    const retried = await post(
      port,
      "read-write",
      callTool("write_file", 2),
      sessionId,
    );

    expect(retried.status).toBe(200);
    expect((await readMessage(retried)).result.content).toEqual([
      { text: "written", type: "text" },
    ]);
  } finally {
    await server.stop();
  }
});

test("points the challenge at the protected resource metadata when OAuth is enabled", async () => {
  const port = await getTestPort();
  const { server } = createServer({
    oauth: {
      enabled: true,
      protectedResource: {
        authorizationServers: ["https://auth.example.com"],
        resource: `http://localhost:${port}/mcp`,
      },
    },
  });

  await server.start({ httpStream: { port }, transportType: "httpStream" });

  try {
    const sessionId = await openSession(port, "read");
    const response = await post(
      port,
      "read",
      callTool("write_file", 1),
      sessionId,
    );
    await response.text();

    expect(response.status).toBe(403);
    expect(extractWWWAuthenticateParams(response)).toEqual({
      error: "insufficient_scope",
      resourceMetadataUrl: new URL(
        `http://localhost:${port}/.well-known/oauth-protected-resource/mcp`,
      ),
      scope: "files:read files:write",
    });
  } finally {
    await server.stop();
  }
});

test("challenges a stateless HTTP call", async () => {
  const port = await getTestPort();
  const { execute, server } = createServer();

  await server.start({
    httpStream: { port, stateless: true },
    transportType: "httpStream",
  });

  try {
    const response = await post(port, "read", callTool("write_file", 1));
    await response.text();

    expect(response.status).toBe(403);
    expect(execute).not.toHaveBeenCalled();
  } finally {
    await server.stop();
  }
});

test("challenges a call sent inside a batch", async () => {
  const port = await getTestPort();
  const { execute, server } = createServer();

  await server.start({ httpStream: { port }, transportType: "httpStream" });

  try {
    const sessionId = await openSession(port, "read");
    const response = await post(
      port,
      "read",
      [{ id: 1, jsonrpc: "2.0", method: "ping" }, callTool("write_file", 2)],
      sessionId,
    );

    expect(response.status).toBe(403);
    // Answered for the message that needed the scope.
    expect(await response.json()).toMatchObject({ id: 2 });
    expect(execute).not.toHaveBeenCalled();
  } finally {
    await server.stop();
  }
});

test("answers a tool the session may not see with Unknown tool, not a challenge", async () => {
  const port = await getTestPort();
  const { server } = createServer();

  server.addTool({
    canAccess: () => false,
    description: "Hidden from every session",
    execute: async () => "hidden",
    name: "hidden_tool",
    scopes: ["admin"],
  });

  await server.start({ httpStream: { port }, transportType: "httpStream" });

  try {
    const sessionId = await openSession(port, "read");
    const response = await post(
      port,
      "read",
      callTool("hidden_tool", 1),
      sessionId,
    );

    expect(response.status).toBe(200);
    expect((await readMessage(response)).error).toMatchObject({
      code: -32602,
      message: expect.stringContaining("Unknown tool: hidden_tool"),
    });
  } finally {
    await server.stop();
  }
});

test("rejects the call with a JSON-RPC error on transports without HTTP", async () => {
  const { execute, server } = createServer();
  const client = await connectInMemory(server, { scopes: ["files:read"] });

  try {
    const error = await client
      .callTool({ arguments: {}, name: "write_file" })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(McpError);
    expect(error).toMatchObject({
      code: -32003,
      data: {
        error: "insufficient_scope",
        required_scopes: ["files:read", "files:write"],
      },
    });
    expect(execute).not.toHaveBeenCalled();
  } finally {
    await client.close();
  }
});

test("grants nothing to a session without auth when authenticate is configured", async () => {
  // As on stdio, where the server carries on when `authenticate` fails.
  const { execute, server } = createServer();
  const client = await connectInMemory(server);

  try {
    await expect(
      client.callTool({ arguments: {}, name: "write_file" }),
    ).rejects.toMatchObject({
      code: -32003,
      data: { required_scopes: ["files:write"] },
    });
    expect(execute).not.toHaveBeenCalled();
  } finally {
    await client.close();
  }
});

test("accepts scopes granted as a Set", async () => {
  const { server } = createServer();
  const client = await connectInMemory(server, {
    scopes: new Set(["files:write"]),
  } as unknown as Auth);

  try {
    expect(
      await client.callTool({ arguments: {}, name: "write_file" }),
    ).toEqual({ content: [{ text: "written", type: "text" }] });
  } finally {
    await client.close();
  }
});

test("does not enforce scopes on a server without authenticate", async () => {
  const { server } = createServer({ authenticate: undefined });
  const client = await connectInMemory(server);

  try {
    expect(
      await client.callTool({ arguments: {}, name: "write_file" }),
    ).toEqual({ content: [{ text: "written", type: "text" }] });
  } finally {
    await client.close();
  }
});
