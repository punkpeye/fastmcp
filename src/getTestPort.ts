import { getRandomPort } from "get-port-please";

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
 */
export const getTestPort = async (): Promise<number> => {
  let lastError: unknown;

  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      return await getRandomPort("127.0.0.1");
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 10 * (attempt + 1)));
    }
  }

  throw lastError;
};
