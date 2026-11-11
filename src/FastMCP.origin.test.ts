/**
 * A server bound to a loopback address is out of the network's reach, but any
 * page open in the user's browser can still send it requests. It answers
 * pages served from loopback only, unless `cors` says otherwise.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { type CorsOptions } from "mcp-proxy";
import http from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";

import { FastMCP, type Logger } from "./FastMCP.js";
import { getTestPort } from "./getTestPort.js";

const FOREIGN = "https://elsewhere.example";

const createLogger = () =>
  ({
    debug: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    log: vi.fn(),
    warn: vi.fn(),
  }) satisfies Logger;

/** An HTTP request with headers a browser decides, such as `Host`. */
const send = (
  port: number,
  {
    body,
    headers = {},
    method = "POST",
    path = "/mcp",
  }: {
    body?: unknown;
    headers?: Record<string, string>;
    method?: string;
    path?: string;
  },
) =>
  new Promise<{
    body: string;
    headers: http.IncomingHttpHeaders;
    status: number;
  }>((resolve, reject) => {
    const request = http.request(
      {
        headers: {
          Accept: "application/json, text/event-stream",
          "Content-Type": "application/json",
          ...headers,
        },
        host: "127.0.0.1",
        method,
        path,
        port,
      },
      (response) => {
        let text = "";

        response.on("data", (chunk) => (text += chunk));
        response.on("end", () =>
          resolve({
            body: text,
            headers: response.headers,
            status: response.statusCode!,
          }),
        );
      },
    );

    request.on("error", reject);
    request.end(body === undefined ? undefined : JSON.stringify(body));
  });

const initialize = {
  id: 1,
  jsonrpc: "2.0",
  method: "initialize",
  params: {
    capabilities: {},
    clientInfo: { name: "page", version: "1.0.0" },
    protocolVersion: "2025-06-18",
  },
};

describe("httpStream answers only the origins it means to", () => {
  const servers: FastMCP[] = [];

  afterEach(async () => {
    for (const server of servers.splice(0)) await server.stop();
  });

  const start = async (
    httpStream: {
      cors?: boolean | CorsOptions;
      host?: string;
      stateless?: boolean;
    } = {},
  ) => {
    const port = await getTestPort();
    const logger = createLogger();
    const server = new FastMCP({ logger, name: "Test", version: "1.0.0" });
    const executions: string[] = [];
    const connections: string[] = [];

    server.on("connect", () => connections.push("connect"));

    server.addTool({
      description: "Echoes a message",
      execute: async () => {
        executions.push("ran");
        return "TOOL RAN";
      },
      name: "echo",
    });

    // Bound to an IPv4 loopback address, so that the requests below reach it.
    await server.start({
      httpStream: { host: "127.0.0.1", ...httpStream, port },
      transportType: "httpStream",
    });
    servers.push(server);

    return { connections, executions, logger, port, server };
  };

  const preflight = (port: number, origin: string) =>
    send(port, {
      headers: {
        "Access-Control-Request-Headers": "content-type,mcp-session-id",
        "Access-Control-Request-Method": "POST",
        Origin: origin,
      },
      method: "OPTIONS",
    });

  const refusal = (origin: string) => ({
    error: {
      code: -32000,
      message: `Forbidden: the origin ${origin} is not allowed`,
    },
    id: null,
    jsonrpc: "2.0",
  });

  it("refuses a page served from elsewhere", async () => {
    const { executions, logger, port } = await start();

    expect(
      (await preflight(port, FOREIGN)).headers["access-control-allow-origin"],
    ).toBeUndefined();

    const response = await send(port, {
      body: initialize,
      headers: { Origin: FOREIGN },
    });

    expect(response.status).toBe(403);
    expect(JSON.parse(response.body)).toEqual(refusal(FOREIGN));
    expect(response.headers["mcp-session-id"]).toBeUndefined();
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
    expect(executions).toEqual([]);
    expect(logger.warn).toHaveBeenCalledWith(
      `[FastMCP warning] Refused a request from the origin ${FOREIGN}. A server bound to a loopback address answers pages served from loopback only; name the origins to answer in httpStream.cors.origin.`,
    );
  });

  it("opens no session for a page it refuses", async () => {
    const { connections, port, server } = await start();

    for (let attempt = 0; attempt < 3; attempt++) {
      const refused = await send(port, {
        body: initialize,
        headers: { Origin: FOREIGN },
      });

      expect(refused.status).toBe(403);
    }

    // Nor on the legacy SSE endpoint, which a page opens with a GET.
    const stream = await send(port, {
      headers: { Accept: "text/event-stream", Origin: FOREIGN },
      method: "GET",
      path: "/sse",
    });

    expect(stream.status).toBe(403);
    expect(connections).toEqual([]);
    expect(server.sessions).toEqual([]);
  });

  it("refuses a page whose host name was re-pointed at the server", async () => {
    const { port } = await start();

    // To the browser the page and the server are one origin, so no CORS
    // check applies. It still names the page it is sending for.
    const response = await send(port, {
      body: initialize,
      headers: {
        Host: `rebound.example:${port}`,
        Origin: `http://rebound.example:${port}`,
      },
    });

    expect(response.status).toBe(403);
  });

  it.each(["null", "not an origin", "file:///home/user/page.html"])(
    "refuses a page with no origin of its own (%s)",
    async (origin) => {
      const { port } = await start();
      const response = await send(port, {
        body: initialize,
        headers: { Origin: origin },
      });

      expect(response.status).toBe(403);
    },
  );

  it("refuses a call on a session that a local client opened", async () => {
    const { executions, port } = await start();
    const opened = await send(port, { body: initialize });
    const session = {
      "Mcp-Protocol-Version": "2025-06-18",
      "Mcp-Session-Id": opened.headers["mcp-session-id"] as string,
    };
    const call = {
      id: 2,
      jsonrpc: "2.0",
      method: "tools/call",
      params: { arguments: {}, name: "echo" },
    };

    expect(opened.status).toBe(200);

    const refused = await send(port, {
      body: call,
      headers: { ...session, Origin: FOREIGN },
    });

    expect(refused.status).toBe(403);
    expect(executions).toEqual([]);

    // A batch is refused whole.
    expect(
      (
        await send(port, {
          body: [call],
          headers: { ...session, Origin: FOREIGN },
        })
      ).status,
    ).toBe(403);
    expect(executions).toEqual([]);

    const allowed = await send(port, { body: call, headers: session });

    expect(allowed.status).toBe(200);
    expect(allowed.body).toContain("TOOL RAN");
  });

  it("refuses a message posted to a legacy SSE session", async () => {
    const { port } = await start();
    const client = new Client({ name: "client", version: "1.0.0" });
    const transport = new SSEClientTransport(
      new URL(`http://127.0.0.1:${port}/sse`),
    );

    await client.connect(transport);

    try {
      // The endpoint the server told the client to post to.
      const endpoint = (transport as unknown as { _endpoint: URL })._endpoint;
      const response = await send(port, {
        body: { id: 9, jsonrpc: "2.0", method: "tools/list" },
        headers: { Origin: FOREIGN },
        path: endpoint.pathname + endpoint.search,
      });

      expect(response.status).toBe(403);
    } finally {
      await client.close();
    }
  });

  it.each([
    "http://localhost:6274",
    "http://127.0.0.1:3000",
    "http://127.8.9.10",
    "http://[::1]:3000",
    "https://app.localhost",
  ])("answers a page served from loopback (%s)", async (origin) => {
    const { logger, port } = await start();

    expect(
      (await preflight(port, origin)).headers["access-control-allow-origin"],
    ).toBe(origin);

    const response = await send(port, {
      body: initialize,
      headers: { Origin: origin },
    });

    expect(response.status).toBe(200);
    expect(response.headers["access-control-allow-origin"]).toBe(origin);
    // Cookies stay out of it: another local port is the same site.
    expect(
      response.headers["access-control-allow-credentials"],
    ).toBeUndefined();
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it("says why when it refuses an origin cors does not name", async () => {
    const { logger, port } = await start({
      cors: { origin: "https://app.example" },
    });

    await send(port, {
      body: initialize,
      headers: { Origin: "http://localhost:6274" },
    });

    expect(logger.warn).toHaveBeenCalledWith(
      "[FastMCP warning] Refused a request from the origin http://localhost:6274. It is not one of the origins httpStream.cors.origin allows.",
    );
  });

  it("writes a refused origin to the log as printable text", async () => {
    const { logger, port } = await start();

    await send(port, {
      body: initialize,
      headers: { Origin: "x \u009b31mred\tend" },
    });

    const [[message]] = logger.warn.mock.calls;

    expect(message).toMatch(/^[\x20-\x7e]+$/);
    expect(message).toContain("\\u009b31mred\\u0009end.");
  });

  it.each(["127.1", "0x7f.0.0.1"])(
    "applies to a loopback address however it is written (%s)",
    async (host) => {
      const { port } = await start({ host });

      expect(
        (await send(port, { body: initialize, headers: { Origin: FOREIGN } }))
          .status,
      ).toBe(403);
    },
  );

  it.each<[string, string, CorsOptions["origin"]]>([
    ["an extension", "chrome-extension://abcdefghijklmnop", undefined],
    ["an app", "tauri://localhost", undefined],
  ])(
    "answers %s it names, whose pages have no origin of their own",
    async (_, origin) => {
      for (const named of [
        origin,
        [origin],
        (candidate: string) => candidate === origin,
      ]) {
        const { executions, port } = await start({ cors: { origin: named } });
        const opened = await send(port, {
          body: initialize,
          headers: { Origin: origin },
        });

        expect(opened.status).toBe(200);

        const called = await send(port, {
          body: {
            id: 2,
            jsonrpc: "2.0",
            method: "tools/call",
            params: { arguments: {}, name: "echo" },
          },
          headers: {
            "Mcp-Protocol-Version": "2025-06-18",
            "Mcp-Session-Id": opened.headers["mcp-session-id"] as string,
            Origin: origin,
          },
        });

        expect(called.status).toBe(200);
        expect(executions).toEqual(["ran"]);
      }
    },
  );

  it("refuses an extension it does not name", async () => {
    const { port } = await start();

    expect(
      (
        await send(port, {
          body: initialize,
          headers: { Origin: "chrome-extension://abcdefghijklmnop" },
        })
      ).status,
    ).toBe(403);
  });

  it("reads an empty Origin header as no origin, as CORS does", async () => {
    const { port } = await start();

    expect(
      (await send(port, { body: initialize, headers: { Origin: "" } })).status,
    ).toBe(200);
  });

  it("answers a client that is not a page", async () => {
    const { port } = await start();

    expect((await send(port, { body: initialize })).status).toBe(200);
  });

  it("applies in stateless mode", async () => {
    const { port } = await start({ stateless: true });

    expect(
      (await send(port, { body: initialize, headers: { Origin: FOREIGN } }))
        .status,
    ).toBe(403);
    expect((await send(port, { body: initialize })).status).toBe(200);
  });

  it("reports an origin it refuses once", async () => {
    const { logger, port } = await start();

    for (let attempt = 0; attempt < 3; attempt++) {
      await send(port, { body: initialize, headers: { Origin: FOREIGN } });
    }

    await send(port, {
      body: initialize,
      headers: { Origin: "https://another.example" },
    });

    expect(logger.warn).toHaveBeenCalledTimes(2);
  });

  it.each<[string, boolean | CorsOptions]>([
    ["cors: true", true],
    ["every origin", { origin: "*" }],
    ["that origin", { origin: FOREIGN }],
    ["a list with that origin", { origin: ["https://app.example", FOREIGN] }],
    ["a function that takes it", { origin: (origin) => origin === FOREIGN }],
  ])("answers another origin when cors allows %s", async (_, cors) => {
    const { port } = await start({ cors });

    expect(
      (await preflight(port, FOREIGN)).headers["access-control-allow-origin"],
    ).toBe(cors === true || Object(cors).origin === "*" ? "*" : FOREIGN);
    expect(
      (await send(port, { body: initialize, headers: { Origin: FOREIGN } }))
        .status,
    ).toBe(200);
  });

  it.each<[string, CorsOptions]>([
    ["another origin", { origin: "https://app.example" }],
    ["a list without it", { origin: ["https://app.example"] }],
    ["a function that refuses it", { origin: () => false }],
  ])("refuses an origin when cors allows %s", async (_, cors) => {
    const { port } = await start({ cors });

    expect(
      (await send(port, { body: initialize, headers: { Origin: FOREIGN } }))
        .status,
    ).toBe(403);
  });

  it("keeps to loopback when cors sets something other than the origin", async () => {
    const { port } = await start({
      cors: { allowedHeaders: ["Content-Type", "X-Custom-Header"] },
    });
    const allowed = await preflight(port, "http://localhost:6274");

    expect(allowed.headers["access-control-allow-origin"]).toBe(
      "http://localhost:6274",
    );
    expect(allowed.headers["access-control-allow-headers"]).toContain(
      "X-Custom-Header",
    );
    expect(
      (await send(port, { body: initialize, headers: { Origin: FOREIGN } }))
        .status,
    ).toBe(403);
  });

  it("grants credentials to origins cors names only", async () => {
    const loopback = await start({ cors: { credentials: true } });
    const unnamed = await preflight(loopback.port, "http://localhost:6274");

    expect(unnamed.headers["access-control-allow-origin"]).toBe(
      "http://localhost:6274",
    );
    expect(unnamed.headers["access-control-allow-credentials"]).toBeUndefined();

    const named = await start({
      cors: { credentials: true, origin: ["http://localhost:6274"] },
    });

    expect(
      (await preflight(named.port, "http://localhost:6274")).headers[
        "access-control-allow-credentials"
      ],
    ).toBe("true");
  });

  it("reads an empty cors.origin as naming no origin", async () => {
    const { port } = await start({ cors: { origin: "" } });

    expect(
      (await preflight(port, "http://localhost:6274")).headers[
        "access-control-allow-origin"
      ],
    ).toBe("http://localhost:6274");
    expect(
      (await preflight(port, FOREIGN)).headers["access-control-allow-origin"],
    ).toBeUndefined();
    expect(
      (await send(port, { body: initialize, headers: { Origin: FOREIGN } }))
        .status,
    ).toBe(403);
  });

  it("keeps to loopback when cors is off", async () => {
    const { port } = await start({ cors: false });
    const local = await send(port, {
      body: initialize,
      headers: { Origin: "http://localhost:6274" },
    });

    expect(local.status).toBe(200);
    expect(local.headers["access-control-allow-origin"]).toBeUndefined();
    expect(
      (await send(port, { body: initialize, headers: { Origin: FOREIGN } }))
        .status,
    ).toBe(403);
  });

  it("answers every origin when it is not bound to loopback", async () => {
    const { logger, port } = await start({ host: "0.0.0.0" });

    expect(
      (await preflight(port, FOREIGN)).headers["access-control-allow-origin"],
    ).toBe("*");
    expect(
      (await send(port, { body: initialize, headers: { Origin: FOREIGN } }))
        .status,
    ).toBe(200);
    expect(logger.warn).not.toHaveBeenCalled();
  });
});
