/**
 * OAuth Proxy body-reader robustness tests
 * Exercises the /oauth/* POST endpoints over raw sockets to cover request
 * bodies that are aborted mid-stream or exceed the accepted size limit.
 */

import { getRandomPort } from "get-port-please";
import { OutgoingMessage } from "node:http";
import { connect, type Socket } from "node:net";
import { describe, expect, it, vi } from "vitest";

import { OAuthProxy } from "./auth/OAuthProxy.js";
import { FastMCP } from "./FastMCP.js";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function openSocket(port: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, "127.0.0.1");
    socket.once("connect", () => resolve(socket));
    socket.once("error", reject);
  });
}

function requestHead(
  contentLength: number,
  contentType: string,
  path: string,
  port: number,
  connection = "close",
): string {
  return [
    `POST ${path} HTTP/1.1`,
    `Host: localhost:${port}`,
    `Content-Type: ${contentType}`,
    `Content-Length: ${contentLength}`,
    `Connection: ${connection}`,
    "",
    "",
  ].join("\r\n");
}

async function startOAuthProxyServer(port: number) {
  const authProxy = new OAuthProxy({
    allowedRedirectUriPatterns: ["https://client.example.com/*"],
    baseUrl: `http://localhost:${port}`,
    scopes: ["openid", "profile"],
    upstreamAuthorizationEndpoint: "https://example.com/oauth/authorize",
    upstreamClientId: "test-client-id",
    upstreamClientSecret: "test-client-secret",
    upstreamTokenEndpoint: "https://example.com/oauth/token",
  });

  const server = new FastMCP({
    name: "Test Server",
    oauth: {
      authorizationServer: authProxy.getAuthorizationServerMetadata(),
      enabled: true,
      proxy: authProxy,
    },
    version: "1.0.0",
  });

  await server.start({
    // Raw-socket clients need a concrete address family
    httpStream: { host: "127.0.0.1", port },
    transportType: "httpStream",
  });

  return server;
}

// Every case here starts a real server, drives it over a raw socket and stops
// it again, around a vi.waitFor that is itself allowed 3-5 s. Under vitest's
// default 5 s per-test budget that leaves no headroom — the 5 s waitFor below
// cannot even reach its own limit without failing the test first — so these
// went red under parallel load with "Test timed out", not an assertion.
describe("OAuth proxy body readers", { timeout: 15000 }, () => {
  it.each(["/oauth/register", "/oauth/consent", "/oauth/token"])(
    "settles with 400 invalid_request when the client aborts mid-body (%s)",
    async (path) => {
      const port = await getRandomPort();
      const server = await startOAuthProxyServer(port);
      const endSpy = vi.spyOn(OutgoingMessage.prototype, "end");

      try {
        const body = JSON.stringify({
          redirect_uris: ["https://client.example.com/callback"],
        });
        const socket = await openSocket(port);
        socket.write(requestHead(body.length, "application/json", path, port));
        socket.end(body.slice(0, 10)); // incomplete body, then FIN

        // The aborted socket is torn down by Node's own parse-error handling,
        // so the 400 is observed server-side: the body reader must settle and
        // attempt a 400 invalid_request response instead of hanging forever.
        await vi.waitFor(
          () => {
            expect(
              endSpy.mock.calls.some((call) =>
                String(call[0]).includes("invalid_request"),
              ),
            ).toBe(true);
          },
          { interval: 50, timeout: 3000 },
        );

        // The server stays responsive for subsequent requests.
        const response = await fetch(
          `http://localhost:${port}/oauth/register`,
          {
            body,
            headers: { "Content-Type": "application/json" },
            method: "POST",
          },
        );
        expect(response.status).toBe(201);
      } finally {
        endSpy.mockRestore();
        await server.stop();
      }
    },
  );

  it("rejects an over-limit body before it is fully received", async () => {
    const port = await getRandomPort();
    const server = await startOAuthProxyServer(port);

    try {
      const socket = await openSocket(port);
      // The server may close the connection while we are still writing.
      socket.on("error", () => {});

      const declaredLength = 4 * 1024 * 1024;
      socket.write(
        requestHead(
          declaredLength,
          "application/x-www-form-urlencoded",
          "/oauth/token",
          port,
        ),
      );

      let response = "";
      socket.on("data", (chunk) => (response += chunk));

      // Trickle 6 × 256 KiB = 1.5 MiB, crossing the 1 MiB limit.
      const chunk = "x".repeat(256 * 1024);
      for (let i = 0; i < 6 && response.length === 0; i++) {
        if (!socket.writable) break;
        socket.write(chunk);
        await sleep(50);
      }

      await vi.waitFor(
        () => {
          expect(response).toContain("400");
          expect(response).toContain("invalid_request");
          expect(response).toContain("Request body exceeds 1 MiB");
        },
        { interval: 50, timeout: 3000 },
      );

      // The rejection happened before the declared body was fully sent.
      expect(socket.bytesWritten).toBeLessThan(declaredLength);
      socket.destroy();
    } finally {
      await server.stop();
    }
  });

  it("closes a keep-alive request after rejecting an over-limit body", async () => {
    const port = await getRandomPort();
    const server = await startOAuthProxyServer(port);

    try {
      const socket = await openSocket(port);
      socket.on("error", () => {});

      let response = "";
      let serverClosedSocket = false;
      socket.on("data", (chunk) => (response += chunk));
      // "close", not "end": the server answers 400 and tears the connection
      // down while the client is still writing the oversized body, so the
      // client sees an RST roughly as often as a clean FIN and "end" never
      // fires on that path. Both outcomes mean the server closed the
      // connection, and "close" is emitted either way — matching the
      // aborted-body test below.
      socket.once("close", () => {
        serverClosedSocket = true;
      });

      socket.write(
        requestHead(
          4 * 1024 * 1024,
          "application/x-www-form-urlencoded",
          "/oauth/token",
          port,
          "keep-alive",
        ),
      );
      socket.write("x".repeat(1280 * 1024));

      await vi.waitFor(
        () => {
          expect(response).toContain("400");
          expect(response).toContain("invalid_request");
          expect(response).toContain("Request body exceeds 1 MiB");
          expect(serverClosedSocket).toBe(true);
        },
        { interval: 50, timeout: 3000 },
      );
    } finally {
      await server.stop();
    }
  });

  it("still accepts a valid body delivered in slow chunks", async () => {
    const port = await getRandomPort();
    const server = await startOAuthProxyServer(port);

    try {
      const body = JSON.stringify({
        redirect_uris: ["https://client.example.com/callback"],
      });
      const socket = await openSocket(port);
      socket.write(
        requestHead(body.length, "application/json", "/oauth/register", port),
      );
      socket.write(body.slice(0, 10));
      await sleep(100);
      socket.end(body.slice(10)); // final chunk completes the body

      let response = "";
      socket.on("data", (chunk) => (response += chunk));

      await vi.waitFor(
        () => {
          expect(response).toContain("201");
          expect(response).toContain("client_id");
        },
        { interval: 50, timeout: 3000 },
      );
    } finally {
      await server.stop();
    }
  });

  it("preserves a UTF-8 character split across request chunks", async () => {
    const port = await getRandomPort();
    const server = await startOAuthProxyServer(port);

    try {
      const clientName = "Café 日本語 клиент";
      const body = Buffer.from(
        JSON.stringify({
          client_name: clientName,
          redirect_uris: ["https://client.example.com/callback"],
        }),
        "utf8",
      );
      const accentStart = body.indexOf(Buffer.from("é", "utf8"));
      expect(accentStart).toBeGreaterThanOrEqual(0);

      const socket = await openSocket(port);
      socket.write(
        requestHead(
          body.byteLength,
          "application/json",
          "/oauth/register",
          port,
        ),
      );
      socket.write(body.subarray(0, accentStart + 1));
      await sleep(100);
      socket.end(body.subarray(accentStart + 1));

      let response = "";
      socket.on("data", (chunk) => (response += chunk));

      await vi.waitFor(
        () => {
          expect(response).toContain("201");
          expect(response).toContain(clientName);
        },
        { interval: 50, timeout: 3000 },
      );
    } finally {
      await server.stop();
    }
  });

  // ============================================================================
  // CHUNKED ENCODING TESTS — validates the streaming counter design rationale
  // ============================================================================
  // These three tests lock in the guarantee that the streaming counter protects
  // chunked and dishonest bodies. Without them, a future "optimization" that
  // trusts only Content-Length would pass the existing suite and silently break
  // the chunked path (Transfer-Encoding: chunked uses no Content-Length header).

  it("rejects an oversize chunked body (no Content-Length)", async () => {
    const port = await getRandomPort();
    const server = await startOAuthProxyServer(port);

    try {
      const socket = await openSocket(port);
      let response = "";
      let serverClosedSocket = false;

      socket.on("data", (chunk) => (response += chunk));
      socket.on("close", () => (serverClosedSocket = true));

      // Send chunked request (no Content-Length header)
      const headers = [
        `POST /oauth/register HTTP/1.1`,
        `Host: localhost:${port}`,
        `Transfer-Encoding: chunked`,
        `Content-Type: application/json`,
        ``,
        ``,
      ].join("\r\n");

      socket.write(headers);

      // Send chunks until we exceed 1 MiB limit
      const chunkSize = 256 * 1024; // 256 KiB per chunk
      const chunkData = Buffer.alloc(chunkSize, "a");

      for (let sent = 0; sent < 1.5 * 1024 * 1024; sent += chunkSize) {
        if (socket.destroyed) break;
        // Write chunk in HTTP chunked format: size-in-hex CRLF data CRLF
        socket.write(`${chunkSize.toString(16)}\r\n`);
        socket.write(chunkData);
        socket.write("\r\n");
        await sleep(10);
      }

      await vi.waitFor(
        () => {
          expect(response).toContain("400");
          expect(response).toContain("invalid_request");
          expect(response).toContain("Request body exceeds 1 MiB");
          expect(serverClosedSocket).toBe(true);
        },
        { interval: 50, timeout: 5000 },
      );
    } finally {
      await server.stop();
    }
  });

  it("preserves UTF-8 characters split across chunked wire boundaries", async () => {
    const port = await getRandomPort();
    const server = await startOAuthProxyServer(port);

    try {
      const socket = await openSocket(port);
      let response = "";

      socket.on("data", (chunk) => (response += chunk));

      // Send chunked request with UTF-8 character split across chunks
      const headers = [
        `POST /oauth/register HTTP/1.1`,
        `Host: localhost:${port}`,
        `Transfer-Encoding: chunked`,
        `Content-Type: application/json`,
        ``,
        ``,
      ].join("\r\n");

      socket.write(headers);

      // Split "Café 日本語 клиент" across two chunks
      const part1 = '{"client_name":"Caf';
      const part2 =
        'é 日本語 клиент","redirect_uris":["https://client.example.com/callback"]}';

      // First chunk
      socket.write(`${Buffer.byteLength(part1).toString(16)}\r\n`);
      socket.write(part1);
      socket.write("\r\n");

      await sleep(50);

      // Second chunk
      socket.write(`${Buffer.byteLength(part2).toString(16)}\r\n`);
      socket.write(part2);
      socket.write("\r\n");

      // Terminating chunk
      socket.write("0\r\n\r\n");

      await vi.waitFor(
        () => {
          expect(response).toContain("201");
          expect(response).toContain("Café 日本語 клиент");
        },
        { interval: 50, timeout: 3000 },
      );
    } finally {
      await server.stop();
    }
  });

  it("handles chunked request aborted before terminating chunk", async () => {
    const port = await getRandomPort();
    const server = await startOAuthProxyServer(port);

    try {
      const socket = await openSocket(port);
      let socketClosed = false;

      socket.on("close", () => (socketClosed = true));

      // Send chunked request headers
      const headers = [
        `POST /oauth/token HTTP/1.1`,
        `Host: localhost:${port}`,
        `Transfer-Encoding: chunked`,
        `Content-Type: application/x-www-form-urlencoded`,
        ``,
        ``,
      ].join("\r\n");

      socket.write(headers);

      // Send one chunk
      const chunk1 = "grant_type=authorization_code&code=abc";
      socket.write(`${Buffer.byteLength(chunk1).toString(16)}\r\n`);
      socket.write(chunk1);
      socket.write("\r\n");

      await sleep(50);

      // Abort before sending terminating chunk
      socket.destroy();

      await vi.waitFor(() => expect(socketClosed).toBe(true), {
        interval: 50,
        timeout: 2000,
      });

      // Verify server is still responsive after abort
      const healthSocket = await openSocket(port);
      let healthResponse = "";

      healthSocket.on("data", (chunk) => (healthResponse += chunk));
      healthSocket.write(`GET / HTTP/1.1\r\nHost: localhost\r\n\r\n`);

      await vi.waitFor(() => expect(healthResponse.length).toBeGreaterThan(0), {
        interval: 50,
        timeout: 2000,
      });

      healthSocket.end();
    } finally {
      await server.stop();
    }
  });
});
