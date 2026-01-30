import type { Context } from "hono";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { getRandomPort } from "get-port-please";
import { fetch } from "undici";
import { expect, test } from "vitest";
import { z } from "zod";

import { FastMCP, FastMCPSession } from "./FastMCP.js";

const runWithTestServer = async ({
  run,
  server: createServer,
}: {
  run: ({
    client,
    port,
    server,
    session,
  }: {
    client: Client;
    port: number;
    server: FastMCP;
    session: FastMCPSession;
  }) => Promise<void>;
  server?: () => Promise<FastMCP>;
}) => {
  const port = await getRandomPort();

  const server = createServer
    ? await createServer()
    : new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

  await server.start({
    httpStream: {
      port,
    },
    transportType: "httpStream",
  });

  try {
    const client = new Client(
      {
        name: "test-client",
        version: "1.0.0",
      },
      {
        capabilities: {},
      },
    );

    const transport = new SSEClientTransport(
      new URL(`http://localhost:${port}/sse`),
    );

    const session = await new Promise<FastMCPSession>((resolve) => {
      server.on("connect", async (event) => {
        await event.session.waitForReady();
        resolve(event.session);
      });

      client.connect(transport);
    });

    await run({ client, port, server, session });
  } finally {
    await server.stop();
  }
};

test("custom routes handle GET requests", async () => {
  await runWithTestServer({
    run: async ({ port }) => {
      const response = await fetch(`http://localhost:${port}/custom`);
      expect(response.status).toBe(200);

      const data = (await response.json()) as { message: string };
      expect(data).toEqual({ message: "Hello from custom route" });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      const app = server.getApp();
      app.get("/custom", async (c) => {
        return c.json({ message: "Hello from custom route" });
      });

      return server;
    },
  });
});

test("custom routes handle POST requests with JSON body", async () => {
  await runWithTestServer({
    run: async ({ port }) => {
      const payload = { number: 42, test: "data" };
      const response = await fetch(`http://localhost:${port}/echo`, {
        body: JSON.stringify(payload),
        headers: {
          "Content-Type": "application/json",
        },
        method: "POST",
      });

      expect(response.status).toBe(200);
      const data = (await response.json()) as { received: unknown };
      expect(data.received).toEqual(payload);
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      const app = server.getApp();
      app.post("/echo", async (c) => {
        const body = await c.req.json();
        return c.json({ received: body });
      });

      return server;
    },
  });
});

test("custom routes handle path parameters", async () => {
  await runWithTestServer({
    run: async ({ port }) => {
      // Test single parameter
      const response1 = await fetch(`http://localhost:${port}/users/123`);
      expect(response1.status).toBe(200);
      const data1 = (await response1.json()) as { userId: string };
      expect(data1).toEqual({ userId: "123" });

      // Test multiple parameters
      const response2 = await fetch(
        `http://localhost:${port}/users/456/posts/789`,
      );
      expect(response2.status).toBe(200);
      const data2 = (await response2.json()) as {
        postId: string;
        userId: string;
      };
      expect(data2).toEqual({ postId: "789", userId: "456" });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      const app = server.getApp();
      app.get("/users/:id", async (c) => {
        const id = c.req.param("id");
        return c.json({ userId: id });
      });

      app.get("/users/:userId/posts/:postId", async (c) => {
        const userId = c.req.param("userId");
        const postId = c.req.param("postId");
        return c.json({ postId, userId });
      });

      return server;
    },
  });
});

test("custom routes handle query parameters", async () => {
  await runWithTestServer({
    run: async ({ port }) => {
      const response = await fetch(
        `http://localhost:${port}/search?q=test&limit=10&tags=a&tags=b`,
      );
      expect(response.status).toBe(200);

      const data = (await response.json()) as {
        query: Record<string, string | string[]>;
      };
      expect(data.query.q).toBe("test");
      expect(data.query.limit).toBe("10");
      expect(data.query.tags).toEqual(["a", "b"]);
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      const app = server.getApp();
      app.get("/search", async (c) => {
        const query = c.req.query();
        // Convert single values to match old API behavior
        const processedQuery: Record<string, string | string[]> = {};
        for (const [key, value] of Object.entries(query)) {
          if (key === "tags") {
            // tags can be an array
            const allTags = c.req.queries("tags");
            processedQuery[key] = allTags || [];
          } else {
            processedQuery[key] = value;
          }
        }
        return c.json({ query: processedQuery });
      });

      return server;
    },
  });
});

test("custom routes handle different HTTP methods", async () => {
  await runWithTestServer({
    run: async ({ port }) => {
      // Note: OPTIONS is intercepted by mcp-proxy for CORS handling and returns 204
      const methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];

      for (const method of methods) {
        const response = await fetch(`http://localhost:${port}/resource`, {
          method,
        });
        expect(response.status).toBe(200);

        const data = (await response.json()) as { method: string };
        expect(data.method).toBe(method);
      }

      // Test that OPTIONS returns 204 (handled by mcp-proxy for CORS)
      const optionsResponse = await fetch(`http://localhost:${port}/resource`, {
        method: "OPTIONS",
      });
      expect(optionsResponse.status).toBe(204);
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      const app = server.getApp();

      app.get("/resource", async (c) => {
        return c.json({ method: "GET" });
      });

      app.post("/resource", async (c) => {
        return c.json({ method: "POST" });
      });

      app.put("/resource", async (c) => {
        return c.json({ method: "PUT" });
      });

      app.delete("/resource", async (c) => {
        return c.json({ method: "DELETE" });
      });

      app.patch("/resource", async (c) => {
        return c.json({ method: "PATCH" });
      });

      // Note: OPTIONS handler won't be called due to mcp-proxy CORS handling
      app.options("/resource", async (c) => {
        return c.json({ method: "OPTIONS" });
      });

      return server;
    },
  });
});

test("custom routes return proper status codes", async () => {
  await runWithTestServer({
    run: async ({ port }) => {
      const response1 = await fetch(`http://localhost:${port}/created`);
      expect(response1.status).toBe(201);

      const response2 = await fetch(`http://localhost:${port}/not-found`);
      expect(response2.status).toBe(404);

      const response3 = await fetch(`http://localhost:${port}/deleted`, {
        method: "DELETE",
      });
      expect(response3.status).toBe(204);
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      const app = server.getApp();

      app.get("/created", async (c) => {
        return c.json({ created: true }, 201);
      });

      app.get("/not-found", async (c) => {
        return c.json({ error: "Not found" }, 404);
      });

      app.delete("/deleted", async (c) => {
        return c.body(null, 204);
      });

      return server;
    },
  });
});

test("custom routes handle HTML responses", async () => {
  await runWithTestServer({
    run: async ({ port }) => {
      const response = await fetch(`http://localhost:${port}/page`);
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toContain("text/html");

      const html = await response.text();
      expect(html).toContain("<h1>Hello</h1>");
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      const app = server.getApp();
      app.get("/page", async (c) => {
        return c.html("<html><body><h1>Hello</h1></body></html>");
      });

      return server;
    },
  });
});

test("custom routes handle errors gracefully", async () => {
  await runWithTestServer({
    run: async ({ port }) => {
      const response = await fetch(`http://localhost:${port}/error`);
      expect(response.status).toBe(500);

      const data = (await response.json()) as { error: string };
      expect(data.error).toBe("Something went wrong");
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      const app = server.getApp();
      app.get("/error", async () => {
        throw new Error("Something went wrong");
      });

      // Add error handler to return JSON instead of HTML
      app.onError((err, c) => {
        return c.json({ error: err.message }, 500);
      });

      return server;
    },
  });
});

test("custom routes work alongside MCP endpoints", async () => {
  await runWithTestServer({
    run: async ({ client, port }) => {
      // Test custom route
      const response = await fetch(`http://localhost:${port}/api/status`);
      expect(response.status).toBe(200);
      const data = (await response.json()) as { status: string };
      expect(data.status).toBe("ok");

      // Test MCP functionality still works
      const tools = await client.listTools();
      expect(tools.tools).toHaveLength(1);
      expect(tools.tools[0].name).toBe("test_tool");

      // Health endpoint still works
      const healthResponse = await fetch(`http://localhost:${port}/health`);
      expect(healthResponse.status).toBe(200);
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      // Add a custom route using Hono
      const app = server.getApp();
      app.get("/api/status", async (c) => {
        return c.json({ status: "ok" });
      });

      // Add an MCP tool
      server.addTool({
        description: "Test tool",
        execute: async () => ({
          content: [{ text: "Tool result", type: "text" }],
        }),
        name: "test_tool",
        parameters: z.object({}),
      });

      return server;
    },
  });
});

test("custom routes with wildcard patterns", async () => {
  await runWithTestServer({
    run: async ({ port }) => {
      const response = await fetch(
        `http://localhost:${port}/static/css/style.css`,
      );
      expect(response.status).toBe(200);

      const data = (await response.json()) as { path: string };
      expect(data.path).toBe("/static/css/style.css");
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      const app = server.getApp();
      app.get("/static/*", async (c) => {
        return c.json({ path: c.req.path });
      });

      return server;
    },
  });
});

test("custom routes respect route order", async () => {
  await runWithTestServer({
    run: async ({ port }) => {
      // Should match specific route
      const response1 = await fetch(`http://localhost:${port}/api/special`);
      const data1 = (await response1.json()) as { route: string };
      expect(data1.route).toBe("special");

      // Should match wildcard route
      const response2 = await fetch(`http://localhost:${port}/api/other`);
      const data2 = (await response2.json()) as { route: string };
      expect(data2.route).toBe("wildcard");
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      const app = server.getApp();

      // More specific route first
      app.get("/api/special", async (c) => {
        return c.json({ route: "special" });
      });

      // Wildcard route second
      app.get("/api/*", async (c) => {
        return c.json({ route: "wildcard" });
      });

      return server;
    },
  });
});

test("custom routes with authentication", { timeout: 10000 }, async () => {
  interface TestAuth {
    [key: string]: unknown;
    userId: string;
  }

  const port = await getRandomPort();
  const server = new FastMCP<TestAuth>({
    authenticate: async (req) => {
      const authHeader = req.headers.authorization;
      if (authHeader === "Bearer valid-token") {
        return { userId: "123" };
      }
      throw new Error("Unauthorized");
    },
    name: "Test",
    version: "1.0.0",
  });

  // Helper to get auth from context
  const getAuth = async (c: Context): Promise<null | TestAuth> => {
    const req = c.env.incoming;
    const authHeader = req.headers.authorization;
    if (authHeader === "Bearer valid-token") {
      return { userId: "123" };
    }
    return null;
  };

  const app = server.getApp();
  app.get("/protected", async (c) => {
    const auth = await getAuth(c);
    if (!auth) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    return c.json({
      authenticated: true,
      userId: auth.userId,
    });
  });

  await server.start({
    httpStream: { port },
    transportType: "httpStream",
  });

  try {
    // Test without auth
    const response1 = await fetch(`http://localhost:${port}/protected`);
    expect(response1.status).toBe(401);

    // Test with valid auth
    const response2 = await fetch(`http://localhost:${port}/protected`, {
      headers: {
        Authorization: "Bearer valid-token",
      },
    });
    expect(response2.status).toBe(200);
    const data = (await response2.json()) as {
      authenticated: boolean;
      userId: string;
    };
    expect(data).toEqual({ authenticated: true, userId: "123" });
  } finally {
    await server.stop();
  }
});

test("routes return 404 for non-existent paths", async () => {
  await runWithTestServer({
    run: async ({ port }) => {
      const response = await fetch(`http://localhost:${port}/does-not-exist`);
      expect(response.status).toBe(404);
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      const app = server.getApp();
      app.get("/exists", async (c) => {
        return c.json({ exists: true });
      });

      return server;
    },
  });
});

test("custom routes handle text body parsing", async () => {
  await runWithTestServer({
    run: async ({ port }) => {
      const response = await fetch(`http://localhost:${port}/text`, {
        body: "Hello, World!",
        headers: {
          "Content-Type": "text/plain",
        },
        method: "POST",
      });

      expect(response.status).toBe(200);
      const data = (await response.json()) as {
        length: number;
        received: string;
      };
      expect(data).toEqual({ length: 13, received: "Hello, World!" });
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      const app = server.getApp();
      app.post("/text", async (c) => {
        const text = await c.req.text();
        return c.json({ length: text.length, received: text });
      });

      return server;
    },
  });
});

test("custom routes handle concurrent requests", async () => {
  await runWithTestServer({
    run: async ({ port }) => {
      // Send multiple concurrent requests
      const promises = Array.from({ length: 5 }, () =>
        fetch(`http://localhost:${port}/counter`),
      );

      const responses = await Promise.all(promises);
      const results = await Promise.all(
        responses.map((r) => r.json() as Promise<{ count: number }>),
      );

      // Results should contain counts from 1 to 5 (not necessarily in order)
      const counts = results.map((r) => r.count).sort((a, b) => a - b);
      expect(counts).toEqual([1, 2, 3, 4, 5]);
    },
    server: async () => {
      const server = new FastMCP({
        name: "Test",
        version: "1.0.0",
      });

      // Use a closure to capture the counter
      const state = { requestCount: 0 };

      const app = server.getApp();
      app.get("/counter", async (c) => {
        state.requestCount++;
        const currentCount = state.requestCount;
        // Simulate some async work
        await new Promise((resolve) => setTimeout(resolve, 10));
        return c.json({ count: currentCount });
      });

      return server;
    },
  });
});

test("public routes bypass authentication", async () => {
  interface TestAuth {
    [key: string]: unknown;
    userId: string;
  }

  const port = await getRandomPort();
  const server = new FastMCP<TestAuth>({
    authenticate: async (req) => {
      const authHeader = req.headers.authorization;
      if (authHeader === "Bearer valid-token") {
        return { userId: "123" };
      }
      throw new Error("Unauthorized");
    },
    name: "Test",
    version: "1.0.0",
  });

  // Helper to get auth from context (returns null if not authenticated)
  const getAuth = async (c: Context): Promise<null | TestAuth> => {
    const req = c.env.incoming;
    const authHeader = req.headers.authorization;
    if (authHeader === "Bearer valid-token") {
      return { userId: "123" };
    }
    return null;
  };

  const app = server.getApp();

  // Add a public route - no auth check
  app.get("/public", async (c) => {
    const auth = await getAuth(c);
    return c.json({
      auth: auth || undefined,
      message: "This is public",
      public: true,
    });
  });

  // Add a private route for comparison
  app.get("/private", async (c) => {
    const auth = await getAuth(c);
    if (!auth) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    return c.json({
      auth,
      message: "This is private",
      public: false,
    });
  });

  await server.start({
    httpStream: { port },
    transportType: "httpStream",
  });

  try {
    // Test public route without auth - should work
    const publicResponse = await fetch(`http://localhost:${port}/public`);
    expect(publicResponse.status).toBe(200);
    const publicData = (await publicResponse.json()) as {
      auth: unknown;
      message: string;
      public: boolean;
    };
    expect(publicData).toEqual({
      auth: undefined, // No auth for public routes
      message: "This is public",
      public: true,
    });

    // Test private route without auth - should fail
    const privateResponse = await fetch(`http://localhost:${port}/private`);
    expect(privateResponse.status).toBe(401);

    // Test private route with valid auth - should work
    const privateAuthResponse = await fetch(
      `http://localhost:${port}/private`,
      {
        headers: {
          Authorization: "Bearer valid-token",
        },
      },
    );
    expect(privateAuthResponse.status).toBe(200);
    const privateAuthData = (await privateAuthResponse.json()) as {
      auth: { userId: string };
      message: string;
      public: boolean;
    };
    expect(privateAuthData).toEqual({
      auth: { userId: "123" },
      message: "This is private",
      public: false,
    });
  } finally {
    await server.stop();
  }
});

test("public routes work with OAuth discovery endpoints", async () => {
  const port = await getRandomPort();
  const server = new FastMCP({
    authenticate: async () => {
      // Always reject auth to verify public routes bypass this
      throw new Error("Auth should be bypassed for public routes");
    },
    name: "Test",
    version: "1.0.0",
  });

  const app = server.getApp();

  // Add OAuth discovery endpoint as public route (no auth check)
  app.get("/.well-known/openid-configuration", async (c) => {
    return c.json({
      authorization_endpoint: "https://example.com/auth",
      issuer: "https://example.com",
      token_endpoint: "https://example.com/token",
    });
  });

  // Add protected resource metadata as public route (no auth check)
  app.get("/.well-known/oauth-protected-resource", async (c) => {
    return c.json({
      authorizationServers: ["https://example.com"],
      resource: "https://example.com/api",
    });
  });

  await server.start({
    httpStream: { port },
    transportType: "httpStream",
  });

  try {
    // Test OpenID configuration endpoint
    const oidcResponse = await fetch(
      `http://localhost:${port}/.well-known/openid-configuration`,
    );
    expect(oidcResponse.status).toBe(200);
    const oidcData = (await oidcResponse.json()) as {
      authorization_endpoint: string;
      issuer: string;
      token_endpoint: string;
    };
    expect(oidcData.issuer).toBe("https://example.com");

    // Test protected resource metadata endpoint
    const resourceResponse = await fetch(
      `http://localhost:${port}/.well-known/oauth-protected-resource`,
    );
    expect(resourceResponse.status).toBe(200);
    const resourceData = (await resourceResponse.json()) as {
      authorizationServers: string[];
      resource: string;
    };
    expect(resourceData.resource).toBe("https://example.com/api");
  } finally {
    await server.stop();
  }
});

test("public routes work with wildcards", async () => {
  const port = await getRandomPort();
  const server = new FastMCP({
    authenticate: async () => {
      throw new Error("Auth should be bypassed");
    },
    name: "Test",
    version: "1.0.0",
  });

  const app = server.getApp();

  // Add public wildcard route for static files (no auth check)
  app.get("/public/*", async (c) => {
    return c.json({
      file: c.req.path,
      message: "Public static file",
    });
  });

  await server.start({
    httpStream: { port },
    transportType: "httpStream",
  });

  try {
    const response = await fetch(
      `http://localhost:${port}/public/css/style.css`,
    );
    expect(response.status).toBe(200);
    const data = (await response.json()) as {
      file: string;
      message: string;
    };
    expect(data.file).toBe("/public/css/style.css");
    expect(data.message).toBe("Public static file");
  } finally {
    await server.stop();
  }
});

test("mixed public and private routes with same path pattern", async () => {
  interface TestAuth {
    [key: string]: unknown;
    role: string;
  }

  const port = await getRandomPort();
  const server = new FastMCP<TestAuth>({
    authenticate: async (req) => {
      const authHeader = req.headers.authorization;
      if (authHeader === "Bearer admin-token") {
        return { role: "admin" };
      }
      throw new Error("Unauthorized");
    },
    name: "Test",
    version: "1.0.0",
  });

  // Helper to get auth from context
  const getAuth = async (c: Context): Promise<null | TestAuth> => {
    const req = c.env.incoming;
    const authHeader = req.headers.authorization;
    if (authHeader === "Bearer admin-token") {
      return { role: "admin" };
    }
    return null;
  };

  const app = server.getApp();

  // Public GET endpoint (no auth check)
  app.get("/api/status", async (c) => {
    return c.json({ public: true, status: "ok" });
  });

  // Private POST endpoint with same path
  app.post("/api/status", async (c) => {
    const auth = await getAuth(c);
    if (!auth) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    return c.json({
      message: "Status updated",
      public: false,
      user: auth.role,
    });
  });

  await server.start({
    httpStream: { port },
    transportType: "httpStream",
  });

  try {
    // Test public GET - should work without auth
    const getResponse = await fetch(`http://localhost:${port}/api/status`);
    expect(getResponse.status).toBe(200);
    const getData = (await getResponse.json()) as {
      public: boolean;
      status: string;
    };
    expect(getData).toEqual({ public: true, status: "ok" });

    // Test private POST without auth - should fail
    const postResponse = await fetch(`http://localhost:${port}/api/status`, {
      method: "POST",
    });
    expect(postResponse.status).toBe(401);

    // Test private POST with auth - should work
    const postAuthResponse = await fetch(
      `http://localhost:${port}/api/status`,
      {
        headers: {
          Authorization: "Bearer admin-token",
        },
        method: "POST",
      },
    );
    expect(postAuthResponse.status).toBe(200);
    const postAuthData = (await postAuthResponse.json()) as {
      message: string;
      public: boolean;
      user: string;
    };
    expect(postAuthData).toEqual({
      message: "Status updated",
      public: false,
      user: "admin",
    });
  } finally {
    await server.stop();
  }
});

test("route options validation", async () => {
  const server = new FastMCP({
    name: "Test",
    version: "1.0.0",
  });

  const app = server.getApp();

  // Test that routes can be added without throwing
  expect(() => {
    app.get("/test1", async (c) => {
      return c.json({ test: 1 });
    });
  }).not.toThrow();

  expect(() => {
    app.get("/test2", async (c) => {
      return c.json({ test: 2 });
    });
  }).not.toThrow();

  expect(() => {
    app.get("/test3", async (c) => {
      return c.json({ test: 3 });
    });
  }).not.toThrow();

  expect(() => {
    app.get("/test4", async (c) => {
      return c.json({ test: 4 });
    });
  }).not.toThrow();
});
