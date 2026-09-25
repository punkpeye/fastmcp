import { getRandomPort } from "get-port-please";
import { createServer } from "node:net";

/**
 * Whether nothing is listening on `port` at `host`. Only EADDRINUSE counts as
 * taken: an address this machine does not have — the IPv6 loopback on a host
 * without IPv6 — cannot hold the port for anyone.
 */
const isFreeOn = (port: number, host: string): Promise<boolean> =>
  new Promise((resolve) => {
    const server = createServer();
    server.unref();
    server.once("error", (error: NodeJS.ErrnoException) => {
      resolve(error.code !== "EADDRINUSE");
    });
    server.listen({ host, port }, () => {
      server.close(() => resolve(true));
    });
  });

/**
 * Allocates a free port for a test server.
 *
 * `getRandomPort()` with no host resolves to every local host and walks them:
 * it binds port 0 on the first, keeps the port the OS assigned, then tries to
 * bind that same port on the rest. A test running in a parallel worker can
 * claim the port inside that window, and the whole call then throws
 * `GetPortError: Unable to find a random port` — surfacing as an unrelated
 * test failing at `getTestPort()` rather than anything to do with its subject.
 *
 * Pinning the check to a single host reduces it to one bind of port 0, which
 * the OS only hands out if it is free. The retry covers the transient bind
 * failures that remain when many workers start servers at once.
 *
 * Free on 127.0.0.1 alone is not enough, though. Most test servers listen on
 * "localhost", which resolves to ::1 first on many hosts (CI's included), and
 * the OS keeps the two loopbacks' ports apart: a port a parallel worker's
 * server holds on ::1 is still handed out for 127.0.0.1, and this test's server
 * then fails with EADDRINUSE. So the port must be free on ::1 too.
 */
export const getTestPort = async (): Promise<number> => {
  let lastError: unknown = new Error(
    "No port was free on both loopback addresses",
  );

  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const port = await getRandomPort("127.0.0.1");

      if (await isFreeOn(port, "::1")) {
        return port;
      }
    } catch (error) {
      lastError = error;
    }

    await new Promise((resolve) => setTimeout(resolve, 10 * (attempt + 1)));
  }

  throw lastError;
};
