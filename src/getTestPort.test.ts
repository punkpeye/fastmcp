import type { AddressInfo } from "node:net";

import { createServer } from "node:net";
import { beforeEach, expect, it, vi } from "vitest";

import { getTestPort } from "./getTestPort.js";

const getRandomPort = vi.hoisted(() =>
  vi.fn<(host?: string) => Promise<number>>(),
);

vi.mock("get-port-please", async (importOriginal) => ({
  ...(await importOriginal<typeof import("get-port-please")>()),
  getRandomPort,
}));

beforeEach(() => {
  getRandomPort.mockReset();
});

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

it("skips a port the OS refuses to bind on the IPv6 loopback", async (context) => {
  // An unprivileged process gets EACCES for a port below 1024: the same error
  // Windows reports for a port inside an excluded range.
  const refused = 1;
  const code = await new Promise<string | undefined>((resolve) => {
    const server = createServer();
    server.once("error", (error: NodeJS.ErrnoException) => resolve(error.code));
    server.listen(refused, "::1", () => server.close(() => resolve(undefined)));
  });

  if (code !== "EACCES") {
    context.skip("this host does not refuse to bind a privileged port on ::1");
  }

  const { getRandomPort: realGetRandomPort } =
    await vi.importActual<typeof import("get-port-please")>("get-port-please");
  const free = await realGetRandomPort("127.0.0.1");

  getRandomPort.mockResolvedValueOnce(refused).mockResolvedValueOnce(free);

  await expect(getTestPort()).resolves.toBe(free);
  expect(getRandomPort).toHaveBeenCalledTimes(2);
});
