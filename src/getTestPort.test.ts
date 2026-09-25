import type { AddressInfo } from "node:net";

import { createServer } from "node:net";
import { expect, it, vi } from "vitest";

import { getTestPort } from "./getTestPort.js";

const getRandomPort = vi.hoisted(() =>
  vi.fn<(host?: string) => Promise<number>>(),
);

vi.mock("get-port-please", async (importOriginal) => ({
  ...(await importOriginal<typeof import("get-port-please")>()),
  getRandomPort,
}));

it("skips a port that another server holds on the IPv6 loopback", async (context) => {
  const server = createServer();
  const listening = await new Promise<boolean>((resolve) => {
    server.once("error", () => resolve(false));
    server.listen(0, "::1", () => resolve(true));
  });

  if (!listening) {
    context.skip("this host has no IPv6 loopback");
  }

  try {
    const { getRandomPort: realGetRandomPort } =
      await vi.importActual<typeof import("get-port-please")>(
        "get-port-please",
      );
    const taken = (server.address() as AddressInfo).port;
    const free = await realGetRandomPort("127.0.0.1");

    // What a worker sees when another worker's "localhost" server holds a port
    // on ::1: the IPv4 allocation still offers it.
    getRandomPort.mockResolvedValueOnce(taken).mockResolvedValueOnce(free);

    await expect(getTestPort()).resolves.toBe(free);
    expect(getRandomPort).toHaveBeenCalledTimes(2);
  } finally {
    server.close();
  }
});
