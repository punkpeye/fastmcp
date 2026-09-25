import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

// start({ transportType: "stdio" }) constructs its own StdioServerTransport;
// handing it one end of an in-memory pair lets a real client talk to the
// session that start() builds. Module-level so the hoisted factory can reach it.
let serverTransport: Transport;

// Must use a regular function (not arrow) so `new StdioServerTransport()` works.
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
  StdioServerTransport: vi.fn(function () {
    return serverTransport;
  }),
}));

type Auth = { role: string };

function serverAuthenticatedAs(auth: Auth) {
  const server = new FastMCP<Auth>({
    authenticate: async () => auth,
    name: "T",
    version: "1.0.0",
  });
  server.addTool({
    canAccess: (session) => session.role === "admin",
    description: "Admin only",
    execute: async () => "secret",
    name: "admin-only",
    parameters: z.object({}),
  });
  return server;
}

async function startOverStdio(server: FastMCP<Auth>) {
  const [clientTransport, stdioTransport] =
    InMemoryTransport.createLinkedPair();
  serverTransport = stdioTransport;
  const client = new Client({ name: "c", version: "0.0.0" });
  await Promise.all([
    server.start({ transportType: "stdio" }),
    client.connect(clientTransport),
  ]);
  return client;
}

describe("canAccess on a stdio session", () => {
  beforeEach(() => {
    // start() watches process.stdin for the client going away; keep the test
    // worker's own stdin out of it.
    vi.spyOn(process.stdin, "on").mockReturnValue(process.stdin);
    vi.spyOn(process.stdin, "off").mockReturnValue(process.stdin);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("hides and refuses a tool whose canAccess rejects the authenticated session", async () => {
    const server = serverAuthenticatedAs({ role: "user" });
    server.addTool({
      description: "For everyone",
      execute: async () => "hi",
      name: "public",
      parameters: z.object({}),
    });
    const client = await startOverStdio(server);
    try {
      const { tools } = await client.listTools();
      expect(tools.map((tool) => tool.name)).toEqual(["public"]);
      await expect(
        client.callTool({ arguments: {}, name: "admin-only" }),
      ).rejects.toThrow(/Unknown tool/);
    } finally {
      await client.close();
      await server.stop();
    }
  });

  it("shows the tool to a session its canAccess allows", async () => {
    const server = serverAuthenticatedAs({ role: "admin" });
    const client = await startOverStdio(server);
    try {
      const { tools } = await client.listTools();
      expect(tools.map((tool) => tool.name)).toEqual(["admin-only"]);
    } finally {
      await client.close();
      await server.stop();
    }
  });

  it("still advertises tools when canAccess hides every one of them (#370)", async () => {
    const server = serverAuthenticatedAs({ role: "user" });
    const client = await startOverStdio(server);
    try {
      expect(client.getServerCapabilities()?.tools).toBeDefined();
      await expect(client.listTools()).resolves.toEqual({ tools: [] });
    } finally {
      await client.close();
      await server.stop();
    }
  });
});
