import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it, vi } from "vitest";

import { requireAll, requireAny, requireAuth } from "./auth/helpers.js";
import { FastMCP, type Logger, type Tool } from "./FastMCP.js";

type Auth = { role: string };

type CanAccess = NonNullable<Tool<Auth>["canAccess"]>;

const createLogger = () =>
  ({
    debug: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    log: vi.fn(),
    warn: vi.fn(),
  }) satisfies Logger;

/**
 * Connects a non-admin to a server whose one tool is guarded by `canAccess`,
 * then lists the tools and calls the guarded one directly.
 */
async function exercise(canAccess: CanAccess, auth: Auth = { role: "user" }) {
  const logger = createLogger();
  const server = new FastMCP<Auth>({ logger, name: "T", version: "1.0.0" });
  let executions = 0;

  server.addTool({
    canAccess,
    description: "Admin only",
    execute: async () => {
      executions++;
      return "ADMIN DATA";
    },
    name: "admin-dashboard",
  });

  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "c", version: "0.0.0" });

  await Promise.all([
    server.connect(serverTransport, auth),
    client.connect(clientTransport),
  ]);

  try {
    const { tools } = await client.listTools();
    const call = await client
      .callTool({ arguments: {}, name: "admin-dashboard" })
      .then(
        (result) => result.content,
        (error: Error) => error.message,
      );

    return {
      call,
      executions,
      names: tools.map((tool) => tool.name),
      warnings: logger.warn.mock.calls.map(([message]) => String(message)),
    };
  } finally {
    await client.close();
    await server.stop();
  }
}

// What a JavaScript or transpile-only caller can pass: the type refuses it.
const untyped = (canAccess: (auth: Auth) => unknown) => canAccess as CanAccess;

describe("canAccess admits a session only by returning true", () => {
  it.each([
    ["resolves to false", async () => false],
    ["resolves to true", async () => true],
    [
      "rejects",
      async () => {
        throw new Error("lookup failed");
      },
    ],
  ])("hides a tool whose async canAccess %s", async (_, canAccess) => {
    const result = await exercise(untyped(canAccess));

    expect(result.names).toEqual([]);
    expect(result.call).toContain("Unknown tool: admin-dashboard");
    expect(result.executions).toBe(0);
    expect(result.warnings).toEqual([
      "[FastMCP warning] Tool 'admin-dashboard' is hidden: its canAccess returned a Promise. canAccess must return a boolean synchronously.",
    ]);
  });

  it.each([
    ["a string", () => "admin"],
    ["an empty array", () => []],
    ["an object", () => ({ allowed: false })],
    ["a number", () => 1],
  ])("hides a tool whose canAccess returns %s", async (_, canAccess) => {
    const result = await exercise(untyped(canAccess));

    expect(result.names).toEqual([]);
    expect(result.executions).toBe(0);
    expect(result.warnings).toEqual([
      "[FastMCP warning] Tool 'admin-dashboard' is hidden: its canAccess returned a non-boolean value. canAccess must return a boolean synchronously.",
    ]);
  });

  it.each([
    ["undefined", () => undefined],
    ["null", () => null],
    ["false", () => false],
  ])(
    "hides a tool whose canAccess returns %s without a warning",
    async (_, canAccess) => {
      const result = await exercise(untyped(canAccess));

      expect(result.names).toEqual([]);
      expect(result.executions).toBe(0);
      expect(result.warnings).toEqual([]);
    },
  );

  it("shows and runs a tool whose canAccess returns true", async () => {
    const result = await exercise((auth) => auth.role === "admin", {
      role: "admin",
    });

    expect(result.names).toEqual(["admin-dashboard"]);
    expect(result.call).toEqual([{ text: "ADMIN DATA", type: "text" }]);
    expect(result.executions).toBe(1);
    expect(result.warnings).toEqual([]);
  });

  it("warns once however often the session's tools are filtered", async () => {
    const logger = createLogger();
    const server = new FastMCP<Auth>({ logger, name: "T", version: "1.0.0" });

    server.addTool({
      canAccess: untyped(async () => false),
      description: "Admin only",
      execute: async () => "ADMIN DATA",
      name: "admin-dashboard",
    });

    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "c", version: "0.0.0" });
    const [session] = await Promise.all([
      server.connect(serverTransport, { role: "user" }),
      client.connect(clientTransport),
    ]);

    try {
      session.updateAuth({ role: "user" });
      session.updateAuth({ role: "admin" });

      expect((await client.listTools()).tools).toEqual([]);
      expect(logger.warn).toHaveBeenCalledTimes(1);
    } finally {
      await client.close();
      await server.stop();
    }
  });

  it.each([
    ["requireAll", requireAll],
    ["requireAny", requireAny],
  ])("%s does not pass an async check", async (_, combine) => {
    const asyncCheck = untyped(async () => false) as (auth: Auth) => boolean;
    const result = await exercise(combine(asyncCheck));

    expect(result.names).toEqual([]);
    expect(result.executions).toBe(0);
  });

  it("requireAll and requireAny still pass on true", async () => {
    const admin = (auth: Auth) => auth.role === "admin";

    expect(requireAll<Auth>(requireAuth, admin)({ role: "admin" })).toBe(true);
    expect(requireAll<Auth>(requireAuth, admin)({ role: "user" })).toBe(false);
    expect(requireAny<Auth>(admin, false)({ role: "admin" })).toBe(true);
    expect(requireAny<Auth>(admin, false)({ role: "user" })).toBe(false);
    expect(requireAll<Auth>(true, admin)({ role: "admin" })).toBe(true);
  });
});
