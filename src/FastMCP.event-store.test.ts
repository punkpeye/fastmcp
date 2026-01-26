import type { EventStore } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { expect, test, vi } from "vitest";

test("passes eventStore through to mcp-proxy", async () => {
  vi.resetModules();

  const startHTTPServerMock = vi.fn(async () => ({
    close: async () => {},
  }));

  vi.doMock("mcp-proxy", () => ({
    startHTTPServer: startHTTPServerMock,
  }));

  const { FastMCP } = await import("./FastMCP.js");

  const server = new FastMCP({
    name: "Test",
    version: "1.0.0",
  });

  const eventStore = { id: "test-store" } as unknown as EventStore;

  try {
    await server.start({
      httpStream: {
        eventStore,
        port: 0,
      },
      transportType: "httpStream",
    });

    expect(startHTTPServerMock).toHaveBeenCalledTimes(1);
    expect(startHTTPServerMock).toHaveBeenCalledWith(
      expect.objectContaining({ eventStore }),
    );
  } finally {
    await server.stop();
    vi.unmock("mcp-proxy");
    vi.resetModules();
  }
});
