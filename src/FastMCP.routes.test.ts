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

      server.addRoute("GET", "/custom", async (_req, res) => {
        res.json({ message: "Hello from custom route" });
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

      server.addRoute("POST", "/echo", async (req, res) => {
        const body = await req.json();
        res.json({ received: body });
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

      server.addRoute("GET", "/users/:id", async (req, res) => {
        res.json({ userId: req.params.id });
      });

      server.addRoute(
        "GET",
        "/users/:userId/posts/:postId",
        async (req, res) => {
          res.json({
            postId: req.params.postId,
            userId: req.params.userId,
          });
        },
      );

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

      server.addRoute("GET", "/search", async (req, res) => {
        res.json({ query: req.query });
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

      const methods = ["GET", "POST", "PUT", "DELETE", "PATCH"] as const;
      methods.forEach((method) => {
        server.addRoute(method, "/resource", async (req, res) => {
          res.json({ method: req.method });
        });
      });

      // Note: OPTIONS handler won't be called due to mcp-proxy CORS handling
      server.addRoute("OPTIONS", "/resource", async (req, res) => {
        res.json({ method: req.method });
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

      server.addRoute("GET", "/created", async (_req, res) => {
        res.status(201).json({ created: true });
      });

      server.addRoute("GET", "/not-found", async (_req, res) => {
        res.status(404).json({ error: "Not found" });
      });

      server.addRoute("DELETE", "/deleted", async (_req, res) => {
        res.status(204).end();
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

      server.addRoute("GET", "/page", async (_req, res) => {
        res.send("<html><body><h1>Hello</h1></body></html>");
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

      server.addRoute("GET", "/error", async () => {
        throw new Error("Something went wrong");
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

      // Add a custom route
      server.addRoute("GET", "/api/status", async (_req, res) => {
        res.json({ status: "ok" });
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

      server.addRoute("GET", "/static/*", async (req, res) => {
        res.json({ path: req.url });
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

      // More specific route first
      server.addRoute("GET", "/api/special", async (_req, res) => {
        res.json({ route: "special" });
      });

      // Wildcard route second
      server.addRoute("GET", "/api/*", async (_req, res) => {
        res.json({ route: "wildcard" });
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

  server.addRoute("GET", "/protected", async (req, res) => {
    res.json({
      authenticated: true,
      userId: req.auth?.userId,
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

      server.addRoute("GET", "/exists", async (_req, res) => {
        res.json({ exists: true });
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

      server.addRoute("POST", "/text", async (req, res) => {
        const text = await req.text();
        res.json({ length: text.length, received: text });
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

      server.addRoute("GET", "/counter", async (_req, res) => {
        state.requestCount++;
        const currentCount = state.requestCount;
        // Simulate some async work
        await new Promise((resolve) => setTimeout(resolve, 10));
        res.json({ count: currentCount });
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

  // Add a public route
  server.addRoute(
    "GET",
    "/public",
    async (req, res) => {
      res.json({
        auth: req.auth,
        message: "This is public",
        public: true,
      });
    },
    { public: true },
  );

  // Add a private route for comparison
  server.addRoute("GET", "/private", async (req, res) => {
    res.json({
      auth: req.auth,
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

  // Add OAuth discovery endpoint as public route
  server.addRoute(
    "GET",
    "/.well-known/openid-configuration",
    async (_req, res) => {
      res.json({
        authorization_endpoint: "https://example.com/auth",
        issuer: "https://example.com",
        token_endpoint: "https://example.com/token",
      });
    },
    { public: true },
  );

  // Add protected resource metadata as public route
  server.addRoute(
    "GET",
    "/.well-known/oauth-protected-resource",
    async (_req, res) => {
      res.json({
        authorizationServers: ["https://example.com"],
        resource: "https://example.com/api",
      });
    },
    { public: true },
  );

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

  // Add public wildcard route for static files
  server.addRoute(
    "GET",
    "/public/*",
    async (req, res) => {
      res.json({
        file: req.url,
        message: "Public static file",
      });
    },
    { public: true },
  );

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

  // Public GET endpoint
  server.addRoute(
    "GET",
    "/api/status",
    async (_req, res) => {
      res.json({ public: true, status: "ok" });
    },
    { public: true },
  );

  // Private POST endpoint with same path
  server.addRoute("POST", "/api/status", async (req, res) => {
    res.json({
      message: "Status updated",
      public: false,
      user: req.auth?.role,
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

  // Test that undefined options work (default behavior)
  expect(() => {
    server.addRoute("GET", "/test1", async (_req, res) => {
      res.json({ test: 1 });
    });
  }).not.toThrow();

  // Test that empty options work
  expect(() => {
    server.addRoute(
      "GET",
      "/test2",
      async (_req, res) => {
        res.json({ test: 2 });
      },
      {},
    );
  }).not.toThrow();

  // Test that public: false works (explicit private)
  expect(() => {
    server.addRoute(
      "GET",
      "/test3",
      async (_req, res) => {
        res.json({ test: 3 });
      },
      { public: false },
    );
  }).not.toThrow();

  // Test that public: true works
  expect(() => {
    server.addRoute(
      "GET",
      "/test4",
      async (_req, res) => {
        res.json({ test: 4 });
      },
      { public: true },
    );
  }).not.toThrow();
});
