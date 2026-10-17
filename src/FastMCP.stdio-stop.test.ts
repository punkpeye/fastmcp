import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  ReadBuffer,
  serializeMessage,
} from "@modelcontextprotocol/sdk/shared/stdio.js";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FastMCP, ServerState } from "./FastMCP.js";

// Drive start()'s owned stdio session with a real MCP client, without attaching
// the test worker's own stdin to a transport.
let stdioTransport: Transport;
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
  StdioServerTransport: vi.fn(function () {
    return stdioTransport;
  }),
}));

/** A client transport that writes to the server's stdin and reads its stdout. */
function pipeTransport(stdin: PassThrough, stdout: PassThrough): Transport {
  const buffer = new ReadBuffer();
  const transport: Transport = {
    close: async () => {
      stdout.removeAllListeners("data");
      transport.onclose?.();
    },
    send: async (message) => {
      stdin.write(serializeMessage(message));
    },
    start: async () => {
      stdout.on("data", (chunk: Buffer) => {
        buffer.append(chunk);
        for (
          let message = buffer.readMessage();
          message;
          message = buffer.readMessage()
        ) {
          transport.onmessage?.(message);
        }
      });
    },
  };
  return transport;
}

async function startStdio(server: FastMCP) {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  stdioTransport = serverTransport;
  const client = new Client({ name: "test-client", version: "1.0.0" });
  await Promise.all([
    server.start({ transportType: "stdio" }),
    client.connect(clientTransport),
  ]);
  return client;
}

describe("stopping owned stdio sessions", () => {
  beforeEach(() => {
    vi.spyOn(process.stdin, "on").mockReturnValue(process.stdin);
    vi.spyOn(process.stdin, "off").mockReturnValue(process.stdin);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("closes its session, cancels running tools and emits disconnect once", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    let signal: AbortSignal | undefined;
    let toolStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      toolStarted = resolve;
    });
    server.addTool({
      execute: async (_args, context) => {
        signal = context.signal;
        toolStarted();
        await new Promise<void>((resolve) => {
          context.signal.addEventListener("abort", () => resolve(), {
            once: true,
          });
        });
        return "done";
      },
      name: "waitForClose",
    });
    const onDisconnect = vi.fn();
    server.on("disconnect", onDisconnect);
    const client = await startStdio(server);
    const session = server.sessions[0];
    const close = vi.spyOn(stdioTransport, "close");
    const call = client.callTool({ name: "waitForClose" }).catch(() => {});

    try {
      await started;
      await server.stop();
      await server.stop();

      expect(server.serverState).toBe(ServerState.Stopped);
      expect(server.sessions).toEqual([]);
      expect(session.isReady).toBe(false);
      expect(signal?.aborted).toBe(true);
      expect(close).toHaveBeenCalled();
      expect(onDisconnect).toHaveBeenCalledExactlyOnceWith({ session });
      await expect(client.ping()).rejects.toThrow(/Not connected/);
    } finally {
      await session.close();
      await client.close();
      await call;
    }
  });

  it("leaves caller-owned sessions connected when stopping stdio", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    const externalClient = new Client({ name: "external", version: "1.0.0" });
    const [externalSession] = await Promise.all([
      server.connect(serverTransport),
      externalClient.connect(clientTransport),
    ]);
    const client = await startStdio(server);

    try {
      await server.stop();

      expect(server.sessions).toEqual([externalSession]);
      expect(externalSession.isReady).toBe(true);
      await expect(externalClient.ping()).resolves.toEqual({});
    } finally {
      await client.close();
      await externalSession.close();
      await externalClient.close();
    }
  });

  it("closes an owned transport while session setup is still waiting", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    const [, serverTransport] = InMemoryTransport.createLinkedPair();
    stdioTransport = serverTransport;
    const close = vi.spyOn(serverTransport, "close");
    const onConnect = vi.fn();
    server.on("connect", onConnect);
    const starting = server.start({ transportType: "stdio" });

    try {
      await server.stop();
      await starting;

      expect(close).toHaveBeenCalled();
      expect(server.serverState).toBe(ServerState.Stopped);
      expect(server.sessions).toEqual([]);
      expect(onConnect).not.toHaveBeenCalled();
    } finally {
      await serverTransport.close();
      await starting;
    }
  });

  it("closes an owned transport when starting it fails", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    const [, serverTransport] = InMemoryTransport.createLinkedPair();
    stdioTransport = serverTransport;
    vi.spyOn(serverTransport, "start").mockRejectedValue(
      new Error("start failed"),
    );
    const close = vi.spyOn(serverTransport, "close");

    await expect(server.start({ transportType: "stdio" })).rejects.toThrow(
      "start failed",
    );
    await server.stop();

    expect(close).toHaveBeenCalled();
    expect(server.serverState).toBe(ServerState.Stopped);
    expect(server.sessions).toEqual([]);
  });

  it("starts stdio again after stopping", async () => {
    const { StdioServerTransport } = await vi.importActual<
      typeof import("@modelcontextprotocol/sdk/server/stdio.js")
    >("@modelcontextprotocol/sdk/server/stdio.js");
    // Stands in for the process's stdin, which the real transport's close()
    // leaves paused.
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    vi.spyOn(process, "stdin", "get").mockReturnValue(
      stdin as unknown as typeof process.stdin,
    );
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    for (let run = 0; run < 2; run++) {
      stdioTransport = new StdioServerTransport(stdin, stdout);
      const client = new Client({ name: "test-client", version: "1.0.0" });
      await Promise.all([
        server.start({ transportType: "stdio" }),
        client.connect(pipeTransport(stdin, stdout)),
      ]);

      try {
        await expect(client.ping()).resolves.toEqual({});
      } finally {
        await server.stop();
        await client.close();
      }
    }
  });
});
