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

/** The bind error code for `port` at `host`, or null when the bind succeeded. */
const bindCode = (port: number, host: string): Promise<null | string> =>
  new Promise((resolve) => {
    const server = createServer();
    server.unref();
    server.once("error", (error: NodeJS.ErrnoException) =>
      resolve(error.code ?? "?"),
    );
    server.listen({ host, port }, () => server.close(() => resolve(null)));
  });

/** A port nothing holds, read back from the OS. */
const anyFreePort = async (): Promise<number> => {
  const probe = createServer();
  return new Promise((resolve) => {
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address() as AddressInfo;
      probe.close(() => resolve(port));
    });
  });
};

/**
 * A port the OS refuses to bind for a reason other than EADDRINUSE. On Windows
 * this is a port an `netsh {interface ipv4|ipv6} show excludedportrange` range
 * covers, where `listen()` fails with EACCES. Probing the bind is the only
 * reliable test: a range can be listed and still bind.
 */
const findUnbindablePort = async (): Promise<null | number> => {
  const candidates: number[] = [5357]; // the WSDAPI reservation
  for (let port = 50000; port < 60000; port++) candidates.push(port);

  for (const port of candidates) {
    if ((await bindCode(port, "127.0.0.1")) === "EACCES") return port;
  }
  return null;
};

it("skips a port the OS refuses to bind", async (context) => {
  const reserved = await findUnbindablePort();
  if (reserved === null) {
    context.skip("this host refuses to bind no TCP port");
    return;
  }

  // Refused on both loopbacks, so it can never host a test server
  expect(await bindCode(reserved, "127.0.0.1")).toBe("EACCES");
  expect(await bindCode(reserved, "::1")).toBe("EACCES");

  // The allocator offers the reserved port first, as it would if the OS had just
  // released it, then a port that does work
  const usable = await anyFreePort();
  getRandomPort.mockResolvedValueOnce(reserved).mockResolvedValueOnce(usable);

  const handed = await getTestPort();
  expect(handed).toBe(usable);
  expect(await bindCode(handed, "127.0.0.1")).toBeNull();
  expect(await bindCode(handed, "::1")).toBeNull();
});

it("control: still returns a port that binds", async () => {
  const free = await anyFreePort();
  getRandomPort.mockResolvedValueOnce(free);
  await expect(getTestPort()).resolves.toBe(free);
});
