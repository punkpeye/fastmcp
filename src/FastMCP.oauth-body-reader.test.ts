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
): string {
  return [
    `POST ${path} HTTP/1.1`,
    `Host: localhost:${port}`,
    `Content-Type: ${contentType}`,
    `Content-Length: ${contentLength}`,
    "Connection: close",
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

describe("OAuth proxy body readers", () => {
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
});
