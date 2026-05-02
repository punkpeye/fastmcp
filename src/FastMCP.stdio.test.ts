import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FastMCP } from "./FastMCP.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal fake transport that satisfies what FastMCP needs for stdio. */
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

// Module-level so the vi.mock factory (which is hoisted) can close over it.
// Each test reassigns this in beforeEach before calling start().
let fakeTransport: ReturnType<typeof makeFakeTransport>;

// vi.mock is hoisted to module scope by Vitest — the factory must only
// reference module-level variables, not test-body locals.
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
  StdioServerTransport: vi.fn(() => fakeTransport),
}));

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("stdio stdin listener lifecycle", () => {
  let stdinOnSpy: ReturnType<typeof vi.spyOn>;
  let stdinOffSpy: ReturnType<typeof vi.spyOn>;
  let stdinListeners: Map<string, (...args: unknown[]) => void>;

  beforeEach(() => {
    // FastMCPSession.connect() retries getClientCapabilities() up to 10×100ms.
    // Use fake timers so tests don't actually wait ~1 s.
    vi.useFakeTimers();

    fakeTransport = makeFakeTransport();
    stdinListeners = new Map();

    stdinOnSpy = vi
      .spyOn(process.stdin, "on")
      .mockImplementation(
        (event: string, listener: (...args: unknown[]) => void) => {
          stdinListeners.set(event, listener);
          return process.stdin;
        },
      );

    stdinOffSpy = vi.spyOn(process.stdin, "off").mockImplementation(() => {
      return process.stdin;
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("registers 'close' and 'end' listeners after start({ transportType: 'stdio' })", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });

    // We don't await start() because stdio transport normally runs forever.
    const startPromise = server
      .start({ transportType: "stdio" })
      .catch(() => {});

    // Advance through the 10×100ms capability-retry loop so session.connect()
    // resolves and the stdin listeners are registered.
    await vi.advanceTimersByTimeAsync(1100);

    expect(stdinOnSpy).toHaveBeenCalledWith("close", expect.any(Function));
    expect(stdinOnSpy).toHaveBeenCalledWith("end", expect.any(Function));

    await startPromise;
  });

  it("calls transport.close() exactly once when 'close' fires", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    const startPromise = server
      .start({ transportType: "stdio" })
      .catch(() => {});
    await vi.advanceTimersByTimeAsync(1100);

    const closeListener = stdinListeners.get("close");
    expect(closeListener).toBeDefined();
    closeListener!();

    expect(fakeTransport.close).toHaveBeenCalledTimes(1);

    await startPromise;
  });

  it("does NOT call transport.close() a second time when 'end' fires after 'close' (idempotency)", async () => {
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    const startPromise = server
      .start({ transportType: "stdio" })
      .catch(() => {});
    await vi.advanceTimersByTimeAsync(1100);

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
    const server = new FastMCP({ name: "Test", version: "1.0.0" });
    const startPromise = server
      .start({ transportType: "stdio" })
      .catch(() => {});
    await vi.advanceTimersByTimeAsync(1100);

    const closeListener = stdinListeners.get("close");
    expect(closeListener).toBeDefined();
    closeListener!();

    expect(stdinOffSpy).toHaveBeenCalledWith("close", closeListener);
    expect(stdinOffSpy).toHaveBeenCalledWith("end", closeListener);

    await startPromise;
  });
});
