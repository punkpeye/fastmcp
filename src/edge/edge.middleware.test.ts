import { Hono, type MiddlewareHandler } from "hono";
import { cors } from "hono/cors";
import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { EdgeFastMCP } from "./index.js";

const createServer = (mcpPath?: string, onExecute?: () => void) => {
  const server = new EdgeFastMCP({ mcpPath, name: "test", version: "1.0.0" });

  server.addTool({
    description: "Returns private data",
    execute: async () => {
      onExecute?.();
      return "TOP SECRET";
    },
    name: "secret",
    parameters: z.object({}),
  });

  return server;
};

const auth: MiddlewareHandler = async (c, next) => {
  if (c.req.header("authorization") !== "Bearer secret") {
    return c.json({ error: "Unauthorized" }, 401);
  }

  await next();
};

const callTool = (
  headers: Record<string, string> = {},
  url = "https://worker.example/mcp",
) =>
  new Request(url, {
    body: JSON.stringify({
      id: 1,
      jsonrpc: "2.0",
      method: "tools/call",
      params: { arguments: {}, name: "secret" },
    }),
    headers: {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
      ...headers,
    },
    method: "POST",
  });

const toolResult = {
  id: 1,
  jsonrpc: "2.0",
  result: { content: [{ text: "TOP SECRET", type: "text" }] },
};

/** Whether `app` answers the tool call only for a caller holding the token. */
const expectGuarded = async (app: {
  fetch: (request: Request) => Promise<Response> | Response;
}) => {
  const refused = await app.fetch(callTool());

  expect(refused.status).toBe(401);
  expect(await refused.json()).toEqual({ error: "Unauthorized" });

  const allowed = await app.fetch(callTool({ authorization: "Bearer secret" }));

  expect(allowed.status).toBe(200);
  expect(await allowed.json()).toEqual(toolResult);
};

describe("EdgeFastMCP middleware added through getApp()", () => {
  it.each(["/mcp", "*", "/mcp/*"])(
    "runs in front of the MCP endpoint when added at %s",
    async (path) => {
      const server = createServer();

      server.getApp().use(path, auth);

      for (const method of ["POST", "GET", "DELETE"]) {
        const refused = await server.fetch(
          method === "POST"
            ? callTool()
            : new Request("https://worker.example/mcp", { method }),
        );

        expect(refused.status).toBe(401);
        expect(await refused.json()).toEqual({ error: "Unauthorized" });
      }

      const allowed = await server.fetch(
        callTool({ authorization: "Bearer secret" }),
      );

      expect(allowed.status).toBe(200);
      expect(await allowed.json()).toEqual(toolResult);
    },
  );

  it("runs in front of an MCP endpoint at a custom path", async () => {
    const server = createServer("/api/mcp");

    server.getApp().use("/api/*", auth);

    const url = "https://worker.example/api/mcp";

    expect((await server.fetch(callTool({}, url))).status).toBe(401);
    expect(
      await (
        await server.fetch(callTool({ authorization: "Bearer secret" }, url))
      ).json(),
    ).toEqual(toolResult);
  });

  it("leaves the MCP endpoint alone when no middleware covers it", async () => {
    const server = createServer();

    server.getApp().use("/api/*", auth);

    const response = await server.fetch(callTool());

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(toolResult);
  });

  it("leaves the health endpoint open", async () => {
    const server = createServer();

    server.getApp().use("*", auth);

    const response = await server.fetch(
      new Request("https://worker.example/health"),
    );

    expect(response.status).toBe(200);
  });

  it("runs middleware in the order it was added, around the MCP response", async () => {
    const server = createServer();
    const order: string[] = [];

    server.getApp().use("*", async (c, next) => {
      order.push("first in");
      await next();
      order.push("first out");
      c.res.headers.set("x-first", String(c.res.status));
    });
    server.getApp().use("/mcp", async (_, next) => {
      order.push("second in");
      await next();
      order.push("second out");
    });

    const response = await server.fetch(callTool());

    expect(order).toEqual(["first in", "second in", "second out", "first out"]);
    expect(response.headers.get("x-first")).toBe("200");
    expect(await response.json()).toEqual(toolResult);
  });

  it("applies CORS middleware to the MCP response", async () => {
    const server = createServer();

    server.getApp().use("*", cors({ origin: "https://app.example" }));

    const response = await server.fetch(
      callTool({ origin: "https://app.example" }),
    );

    expect(response.headers.get("access-control-allow-origin")).toBe(
      "https://app.example",
    );
    expect(await response.json()).toEqual(toolResult);
  });

  it("still reads a body that middleware read through c.req", async () => {
    const server = createServer();
    const seen: unknown[] = [];

    server.getApp().use("/mcp", async (c, next) => {
      seen.push((await c.req.json()).method);
      await next();
    });

    const response = await server.fetch(callTool());

    expect(seen).toEqual(["tools/call"]);
    expect(await response.json()).toEqual(toolResult);
  });

  it.each<[string, (app: Hono) => unknown]>([
    ["use() with several handlers", (app) => app.use("/mcp", cors(), auth)],
    ["use() without a path", (app) => app.use(auth)],
    ["all()", (app) => app.all("/mcp", auth)],
    ["on()", (app) => app.on(["POST", "GET", "DELETE"], "/mcp", auth)],
    ["a method", (app) => app.post("/mcp", auth)],
    ["a route group", (app) => app.route("/", new Hono().use("*", auth))],
    [
      "a route group at the MCP path",
      (app) => app.route("/mcp", new Hono().use(auth)),
    ],
    ["basePath()", (app) => app.basePath("/").use("/mcp", auth)],
  ])("runs however it was registered: %s", async (_, register) => {
    const server = createServer();

    register(server.getApp());

    await expectGuarded(server);
  });

  it("does not let a route added afterwards take the MCP endpoint over", async () => {
    const server = createServer();

    // Each answers every request it is given and takes no `next`: a custom
    // 404, however it was registered.
    server.getApp().use("*", async (c) => c.text("Custom 404", 404));
    server.getApp().all("*", (c) => c.text("fallback", 404));
    server.getApp().post("/mcp", (c) => c.text("shadow"));

    const response = await server.fetch(callTool());

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(toolResult);
  });

  it("answers with the app's error handler when middleware throws", async () => {
    const server = createServer();

    server.getApp().onError((error, c) => c.text(error.message, 418));
    server.getApp().use("/mcp", () => {
      throw new Error("middleware failed");
    });

    const response = await server.fetch(callTool());

    expect(response.status).toBe(418);
    expect(await response.text()).toBe("middleware failed");
  });

  it("does not answer for middleware that neither responds nor calls next", async () => {
    const server = createServer();

    server.getApp().use("/mcp", (async () => {}) as MiddlewareHandler);

    const response = await server.fetch(callTool());

    expect(response.status).toBe(500);
    expect(await response.text()).not.toContain("TOP SECRET");
  });

  it("keeps the answer of middleware that answers and still calls next", async () => {
    let executions = 0;
    const server = createServer(undefined, () => executions++);

    server.getApp().use("/mcp", async (c, next) => {
      c.res = c.text("denied", 401);
      await next();
    });

    const response = await server.fetch(callTool());

    expect(response.status).toBe(401);
    expect(await response.text()).toBe("denied");
    // The request it turned away was not run.
    expect(executions).toBe(0);
  });

  it("passes the runtime's bindings on to middleware", async () => {
    const server = createServer();

    server.getApp().use("/mcp", async (c, next) => {
      const { TOKEN } = c.env as { TOKEN: string };

      if (c.req.header("authorization") !== `Bearer ${TOKEN}`) {
        return c.json({ error: "Unauthorized" }, 401);
      }

      await next();
    });

    // As a runtime calls a default export: fetch(request, env, context).
    await expectGuarded({
      fetch: (request) => server.fetch(request, { TOKEN: "secret" }),
    });
  });

  it("runs when the app is mounted under several, each with an error handler", async () => {
    const server = createServer();

    server.getApp().onError((error, c) => c.text(error.message, 500));
    server.getApp().use("/mcp", auth);

    // Every mount wraps the handlers again.
    const api = new Hono().onError((error, c) => c.text(error.message, 500));

    api.route("/", server.getApp());

    await expectGuarded(new Hono().route("/", api));
  });

  it("runs middleware of the app it is mounted in, even when added after it", async () => {
    const tenant = createServer();
    const server = createServer();

    server.getApp().route("/tenant", tenant.getApp());
    server.getApp().use("*", auth);

    await expectGuarded(server);
    await expectGuarded({
      fetch: (request) =>
        server.fetch(new Request("https://worker.example/tenant/mcp", request)),
    });
  });

  describe("mounted in an app built from another copy of hono", () => {
    // The CommonJS build is a second copy: its requests are not ones this
    // copy's helpers can read.
    const other = createRequire(import.meta.url)(
      "hono",
    ) as typeof import("hono");

    it("is another copy", () => {
      expect(other.Hono).not.toBe(Hono);
    });

    it("still answers", async () => {
      const outer = new other.Hono().route(
        "/",
        createServer().getApp() as never,
      );
      const response = await outer.fetch(callTool());

      expect(response.status).toBe(200);
      expect(await response.json()).toEqual(toolResult);
    });

    it("still runs middleware", async () => {
      const server = createServer();

      server.getApp().use("/mcp", auth);

      await expectGuarded(
        new other.Hono().route("/", server.getApp() as never),
      );
    });
  });

  it.each([false, true])(
    "runs when the app is mounted in another one (own error handler: %s)",
    async (ownErrorHandler) => {
      const server = createServer();

      if (ownErrorHandler) {
        server.getApp().onError((error, c) => c.text(error.message, 500));
      }

      server.getApp().use("/mcp", auth);

      const outer = new Hono().route("/", server.getApp());

      expect((await outer.fetch(callTool())).status).toBe(401);
      expect(
        await (
          await outer.fetch(callTool({ authorization: "Bearer secret" }))
        ).json(),
      ).toEqual(toolResult);
    },
  );
});
