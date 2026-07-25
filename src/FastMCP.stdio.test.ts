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
let fakeTransport: ReturnType<typeof makeFakeTransport>;

// Must use a regular function (not arrow) so `new StdioServerTransport()` works.
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
  StdioServerTransport: vi.fn(function () {
    return fakeTransport;
  }),
}));

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// session.connect() retries getClientCapabilities() 10×100ms (~1s real time).
// Give waitFor enough headroom beyond that.
const LISTENER_TIMEOUT = 3000;

describe("stdio stdin listener lifecycle", () => {
  let stdinOnSpy: ReturnType<typeof vi.spyOn>;
  let stdinOffSpy: ReturnType<typeof vi.spyOn>;
  let stdinListeners: Map<string, (...args: unknown[]) => void>;

  beforeEach(() => {
    fakeTransport = makeFakeTransport();
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
});
