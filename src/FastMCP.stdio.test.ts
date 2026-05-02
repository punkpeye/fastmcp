import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FastMCP } from "./FastMCP.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal fake transport that satisfies what FastMCP needs for stdio. */
function makeFakeTransport() {
  const transport = {
    close: vi.fn().mockResolvedValue(undefined),
    onclose: undefined as (() => void) | undefined,
    onerror: undefined as ((e: Error) => void) | undefined,
    onmessage: undefined as ((msg: unknown) => void) | undefined,
    // The SDK Server calls these
    send: vi.fn().mockResolvedValue(undefined),
    // FastMCPSession.connect() calls start() on the transport
    start: vi.fn().mockResolvedValue(undefined),
  };
  return transport;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("stdio stdin listener lifecycle", () => {
  let stdinOnSpy: ReturnType<typeof vi.spyOn>;
  let stdinOffSpy: ReturnType<typeof vi.spyOn>;
  let stdinListeners: Map<string, (...args: unknown[]) => void>;

  beforeEach(() => {
    stdinListeners = new Map();

    stdinOnSpy = vi
      .spyOn(process.stdin, "on")
      .mockImplementation(
        (event: string, listener: (...args: unknown[]) => void) => {
          stdinListeners.set(event, listener);
          return process.stdin;
        },
      );

    stdinOffSpy = vi
      .spyOn(process.stdin, "off")
      .mockImplementation((_: string, __: (...args: unknown[]) => void) => {
        return process.stdin;
      });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("registers 'close' and 'end' listeners after start({ transportType: 'stdio' })", async () => {
    const fakeTransport = makeFakeTransport();

    vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
      StdioServerTransport: vi.fn(() => fakeTransport),
    }));

    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    // We don't await start() because stdio transport normally runs forever;
    // we just need to verify the listeners were registered.
    const startPromise = server
      .start({ transportType: "stdio" })
      .catch(() => {});

    // Give the microtask queue a turn so the synchronous listener registration runs
    await Promise.resolve();

    expect(stdinOnSpy).toHaveBeenCalledWith("close", expect.any(Function));
    expect(stdinOnSpy).toHaveBeenCalledWith("end", expect.any(Function));

    await startPromise;
  });

  it("calls transport.close() exactly once when 'close' fires", async () => {
    const fakeTransport = makeFakeTransport();

    vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
      StdioServerTransport: vi.fn(() => fakeTransport),
    }));

    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    const startPromise = server
      .start({ transportType: "stdio" })
      .catch(() => {});
    await Promise.resolve();

    const closeListener = stdinListeners.get("close");
    expect(closeListener).toBeDefined();
    closeListener!();

    expect(fakeTransport.close).toHaveBeenCalledTimes(1);

    await startPromise;
  });

  it("does NOT call transport.close() a second time when 'end' fires after 'close' (idempotency)", async () => {
    const fakeTransport = makeFakeTransport();

    vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
      StdioServerTransport: vi.fn(() => fakeTransport),
    }));

    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    const startPromise = server
      .start({ transportType: "stdio" })
      .catch(() => {});
    await Promise.resolve();

    const closeListener = stdinListeners.get("close");
    const endListener = stdinListeners.get("end");
    expect(closeListener).toBeDefined();
    expect(endListener).toBeDefined();

    // Fire 'close' first, then 'end' — transport.close should only be called once
    closeListener!();
    endListener!();

    expect(fakeTransport.close).toHaveBeenCalledTimes(1);

    await startPromise;
  });

  it("removes both listeners after the handler fires", async () => {
    const fakeTransport = makeFakeTransport();

    vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
      StdioServerTransport: vi.fn(() => fakeTransport),
    }));

    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    const startPromise = server
      .start({ transportType: "stdio" })
      .catch(() => {});
    await Promise.resolve();

    const closeListener = stdinListeners.get("close");
    expect(closeListener).toBeDefined();
    closeListener!();

    expect(stdinOffSpy).toHaveBeenCalledWith("close", closeListener);
    expect(stdinOffSpy).toHaveBeenCalledWith("end", closeListener);

    await startPromise;
  });
});
