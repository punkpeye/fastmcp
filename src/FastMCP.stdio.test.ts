import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { PingRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FastMCP } from "./FastMCP.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFakeTransport() {
  return {
    close: vi.fn().mockResolvedValue(undefined),
    onclose: undefined as (() => void) | undefined,
    onerror: undefined as ((e: Error) => void) | undefined,
    onmessage: undefined as ((msg: unknown) => void) | undefined,
    send: vi.fn().mockResolvedValue(undefined),
    start: vi.fn().mockResolvedValue(undefined),
  };
}

// Module-level so the vi.mock factory (hoisted) can close over it.
// Each test reassigns this in beforeEach.
let stdioTransport: Transport;

// Must use a regular function (not arrow) so `new StdioServerTransport()` works.
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
  StdioServerTransport: vi.fn(function () {
    return stdioTransport;
  }),
}));

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// session.connect() retries getClientCapabilities() 10×100ms (~1s real time).
// Give waitFor enough headroom beyond that.
const LISTENER_TIMEOUT = 3000;

describe("stdio stdin listener lifecycle", () => {
  let fakeTransport: ReturnType<typeof makeFakeTransport>;
  let stdinOnSpy: ReturnType<typeof vi.spyOn>;
  let stdinOffSpy: ReturnType<typeof vi.spyOn>;
  let stdinListeners: Map<string, (...args: unknown[]) => void>;

  beforeEach(() => {
    fakeTransport = makeFakeTransport();
    stdioTransport = fakeTransport;
    stdinListeners = new Map();

    stdinOnSpy = vi.spyOn(process.stdin, "on").mockImplementation(function (
      event: string,
      listener: (...args: unknown[]) => void,
    ) {
      stdinListeners.set(event, listener);
      return process.stdin;
    });

    stdinOffSpy = vi
      .spyOn(process.stdin, "off")
      .mockImplementation(function () {
        return process.stdin;
      });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("registers 'close' and 'end' listeners after start({ transportType: 'stdio' })", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    server.start({ transportType: "stdio" }).catch(() => {});

    await vi.waitFor(
      () => {
        expect(stdinOnSpy).toHaveBeenCalledWith("close", expect.any(Function));
        expect(stdinOnSpy).toHaveBeenCalledWith("end", expect.any(Function));
      },
      { timeout: LISTENER_TIMEOUT },
    );
  });

  it("calls transport.close() exactly once when 'close' fires", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    server.start({ transportType: "stdio" }).catch(() => {});

    await vi.waitFor(
      () => {
        expect(stdinListeners.get("close")).toBeDefined();
      },
      { timeout: LISTENER_TIMEOUT },
    );

    stdinListeners.get("close")!();
    expect(fakeTransport.close).toHaveBeenCalledTimes(1);
  });

  it("does NOT call transport.close() a second time when 'end' fires after 'close' (idempotency)", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    server.start({ transportType: "stdio" }).catch(() => {});

    await vi.waitFor(
      () => {
        expect(stdinListeners.get("close")).toBeDefined();
        expect(stdinListeners.get("end")).toBeDefined();
      },
      { timeout: LISTENER_TIMEOUT },
    );

    stdinListeners.get("close")!();
    stdinListeners.get("end")!();

    expect(fakeTransport.close).toHaveBeenCalledTimes(1);
  });

  it("removes both listeners after the handler fires", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    server.start({ transportType: "stdio" }).catch(() => {});

    await vi.waitFor(
      () => {
        expect(stdinListeners.get("close")).toBeDefined();
      },
      { timeout: LISTENER_TIMEOUT },
    );

    const closeListener = stdinListeners.get("close")!;
    closeListener();

    expect(stdinOffSpy).toHaveBeenCalledWith("close", closeListener);
    expect(stdinOffSpy).toHaveBeenCalledWith("end", closeListener);
  });

  it("leaves no session behind when stdin ends while the session is being set up", async () => {
    // Like StdioServerTransport, closing reports the close.
    fakeTransport.close.mockImplementation(async () => {
      fakeTransport.onclose?.();
    });

    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    const onConnect = vi.fn();
    server.on("connect", onConnect);

    const starting = server.start({ transportType: "stdio" });

    // No client ever initializes, so setup is still waiting for one (~1s)
    // when stdin ends.
    stdinListeners.get("end")!();
    await starting;

    expect(fakeTransport.close).toHaveBeenCalledTimes(1);
    expect(server.sessions).toEqual([]);
    expect(onConnect).not.toHaveBeenCalled();
  });
});

describe("stdio diagnostics", () => {
  beforeEach(() => {
    vi.spyOn(process.stdin, "on").mockReturnValue(process.stdin);
    vi.spyOn(process.stdin, "off").mockReturnValue(process.stdin);
    vi.spyOn(process.stdin, "isPaused").mockReturnValue(false);
    for (const method of ["debug", "error", "info", "log", "warn"] as const) {
      vi.spyOn(console, method).mockImplementation(() => {});
    }
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  // Substitute a linked in-memory transport for start()'s stdio transport so
  // a real SDK client exercises the session without using the worker's stdin.
  async function withStdioSession(
    options: Partial<ConstructorParameters<typeof FastMCP>[0]>,
    clientRoots: boolean,
    run: (client: Client) => Promise<void>,
  ) {
    const server = new FastMCP({ name: "Test", version: "1.0.0", ...options });
    server.addTool({ execute: async () => "hello", name: "hello" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    stdioTransport = serverTransport;
    const client = new Client(
      { name: "client", version: "1.0.0" },
      { capabilities: clientRoots ? { roots: { listChanged: true } } : {} },
    );

    try {
      await Promise.all([
        server.start({ transportType: "stdio" }),
        client.connect(clientTransport),
      ]);
      await run(client);
      expect((await client.listTools()).tools.map((tool) => tool.name)).toEqual(
        ["hello"],
      );
    } finally {
      try {
        await client.close();
      } finally {
        await server.stop();
      }
    }
  }

  const rootsCases = [
    {
      clientRoots: false,
      disabled: false,
      messages: [],
      name: "default options",
    },
    {
      clientRoots: false,
      disabled: true,
      messages: [
        ["[FastMCP debug] roots capability explicitly disabled via config"],
      ],
      name: "roots disabled",
    },
    {
      clientRoots: true,
      disabled: false,
      messages: [["[FastMCP debug] listRoots method not supported by client"]],
      name: "roots declared without a roots/list handler",
    },
  ];

  const stdoutCalls = () =>
    (["debug", "info", "log"] as const).flatMap(
      (method) => vi.mocked(console[method]).mock.calls,
    );

  it.each(rootsCases)(
    "sends default diagnostics to stderr: $name",
    async ({ clientRoots, disabled, messages }) => {
      await withStdioSession(
        disabled ? { roots: { enabled: false } } : {},
        clientRoots,
        async (client) => {
          if (clientRoots) {
            await client.sendRootsListChanged();
            await vi.waitFor(() => {
              expect([
                ...stdoutCalls(),
                ...vi.mocked(console.error).mock.calls,
              ]).toHaveLength(2);
            });
          }
        },
      );
      expect(stdoutCalls()).toEqual([]);
      expect(vi.mocked(console.error).mock.calls).toEqual(
        clientRoots ? [...messages, ...messages] : messages,
      );
    },
  );

  it.each(rootsCases.slice(1))(
    "preserves a user-supplied logger: $name",
    async ({ clientRoots, disabled, messages }) => {
      const logger = {
        debug: vi.fn(),
        error: vi.fn(),
        info: vi.fn(),
        log: vi.fn(),
        warn: vi.fn(),
      };
      await withStdioSession(
        { logger, roots: disabled ? { enabled: false } : undefined },
        clientRoots,
        async (client) => {
          expect(logger.debug.mock.calls).toEqual(messages);
          if (clientRoots) {
            await client.sendRootsListChanged();
            await vi.waitFor(() => {
              expect(logger.debug.mock.calls).toEqual([
                ...messages,
                ...messages,
              ]);
            });
          }
          expect(console.error).not.toHaveBeenCalled();
        },
      );
      expect(stdoutCalls()).toEqual([]);
    },
  );

  it("preserves console when explicitly supplied as the logger", async () => {
    const debug = console.debug;
    await withStdioSession(
      { logger: console, roots: { enabled: false } },
      false,
      async () => {
        expect(console.debug).toBe(debug);
        expect(console.debug).toHaveBeenCalledExactlyOnceWith(
          "[FastMCP debug] roots capability explicitly disabled via config",
        );
        expect(console.error).not.toHaveBeenCalled();
      },
    );
  });

  it.each(["debug", "info"] as const)(
    "sends later ping failures at %s level to stderr",
    async (logLevel) => {
      vi.useFakeTimers({ toFake: ["clearInterval", "setInterval"] });
      await withStdioSession(
        { ping: { enabled: true, intervalMs: 10, logLevel } },
        false,
        async (client) => {
          client.setRequestHandler(PingRequestSchema, () => {
            throw new Error("ping failed");
          });
          await vi.advanceTimersByTimeAsync(10);
        },
      );
      expect(stdoutCalls()).toEqual([]);
      expect(console.error).toHaveBeenCalledExactlyOnceWith(
        `[FastMCP ${logLevel}] server ping failed`,
      );
    },
  );
});
