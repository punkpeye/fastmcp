#!/usr/bin/env node

/**
 * Example FastMCP server demonstrating custom HTTP routes using Hono's native API.
 *
 * This example shows how to:
 * - Use getApp() to access Hono's native API
 * - Add REST API endpoints with Hono's standard methods (app.get(), app.post(), etc.)
 * - Implement authentication with a custom helper function
 * - Handle file uploads
 * - Serve admin interfaces
 * - Create webhooks
 * - OAuth discovery endpoints
 * - Integrate custom routes with MCP tools
 *
 * Run with:
 *   npx fastmcp dev src/examples/custom-routes.ts
 *   npx fastmcp inspect src/examples/custom-routes.ts
 *
 * Or directly:
 *   node dist/examples/custom-routes.js --transport=http-stream --port=8080
 */

import type { Context } from "hono";

import { z } from "zod";

import { FastMCP } from "../FastMCP.js";

// Example in-memory data store
interface User {
  email: string;
  id: string;
  name: string;
}

const users = new Map<string, User>([
  ["1", { email: "alice@example.com", id: "1", name: "Alice" }],
  ["2", { email: "bob@example.com", id: "2", name: "Bob" }],
]);

let requestCount = 0;

// Simple authentication for demonstration
interface UserAuth {
  [key: string]: unknown;
  role: string;
  userId: string;
}

// Create the FastMCP server with authentication
const server = new FastMCP<UserAuth>({
  // Simple authentication - in production, use proper tokens/JWTs
  authenticate: async (req) => {
    const authHeader = req.headers.authorization;
    if (authHeader === "Bearer admin-token") {
      return { role: "admin", userId: "admin" };
    } else if (authHeader === "Bearer user-token") {
      return { role: "user", userId: "user1" };
    }
    throw new Error("Invalid or missing authentication");
  },
  name: "custom-routes-example",
  version: "1.0.0",
});

// Get the Hono app instance for direct access to Hono's native API
const app = server.getApp();

// Helper to get authentication from Node.js request
const getAuth = async (c: Context): Promise<null | UserAuth> => {
  const req = c.env.incoming;
  const authHeader = req.headers.authorization;
  if (authHeader === "Bearer admin-token") {
    return { role: "admin", userId: "admin" };
  } else if (authHeader === "Bearer user-token") {
    return { role: "user", userId: "user1" };
  }
  return null;
};

// ===== PUBLIC ROUTES (No Authentication Required) =====

// OAuth discovery endpoint - public by design
app.get("/.well-known/openid-configuration", async (c) => {
  return c.json({
    authorization_endpoint: "https://example.com/oauth/authorize",
    issuer: "https://example.com",
    jwks_uri: "https://example.com/.well-known/jwks.json",
    response_types_supported: ["code"],
    scopes_supported: ["openid", "profile", "email"],
    subject_types_supported: ["public"],
    token_endpoint: "https://example.com/oauth/token",
  });
});

// OAuth protected resource metadata - also public
app.get("/.well-known/oauth-protected-resource", async (c) => {
  return c.json({
    authorizationServers: ["https://example.com"],
    resource: "https://example.com/api",
    scopesSupported: ["read", "write"],
  });
});

// Public status endpoint - no auth needed
app.get("/status", async (c) => {
  return c.json({
    message: "Server is running",
    status: "healthy",
    timestamp: new Date().toISOString(),
    version: "1.0.0",
  });
});

// Public documentation endpoint
app.get("/docs", async (c) => {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>API Documentation</title>
      <style>
        body { font-family: sans-serif; margin: 40px; line-height: 1.6; }
        h1, h2 { color: #333; }
        .endpoint { background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #007bff; }
        .method { font-weight: bold; color: #28a745; }
        .auth-required { color: #dc3545; font-size: 0.9em; }
        .public { color: #6c757d; font-size: 0.9em; }
      </style>
    </head>
    <body>
      <h1>Custom Routes API Documentation</h1>

      <h2>Public Endpoints (No Authentication)</h2>
      <div class="endpoint">
        <span class="method">GET</span> <code>/status</code>
        <div class="public">✓ Public - Server health status</div>
      </div>
      <div class="endpoint">
        <span class="method">GET</span> <code>/.well-known/openid-configuration</code>
        <div class="public">✓ Public - OAuth discovery</div>
      </div>

      <h2>Private Endpoints (Authentication Required)</h2>
      <div class="endpoint">
        <span class="method">GET</span> <code>/api/users</code>
        <div class="auth-required">🔒 Requires: Bearer token</div>
      </div>
      <div class="endpoint">
        <span class="method">GET</span> <code>/admin</code>
        <div class="auth-required">🔒 Requires: admin token</div>
      </div>

      <h2>Authentication</h2>
      <p>Use one of these tokens in the Authorization header:</p>
      <ul>
        <li><code>Bearer admin-token</code> - Admin access</li>
        <li><code>Bearer user-token</code> - User access</li>
      </ul>

      <h2>Examples</h2>
      <pre>
# Public endpoint (no auth needed)
curl http://localhost:8080/status

# Private endpoint (auth required)
curl -H "Authorization: Bearer user-token" http://localhost:8080/api/users
      </pre>
    </body>
    </html>
  `;
  return c.html(html);
});

// Public static assets
app.get("/public/*", async (c) => {
  // In a real app, you'd serve actual files here
  return c.json({
    file: c.req.url,
    message: "This would serve static files",
    public: true,
  });
});

// ===== PRIVATE ROUTES (Authentication Required) =====

// Add custom routes for a REST API
app.get("/api/users", async (c) => {
  const auth = await getAuth(c);
  if (!auth) {
    return c.json({ error: "Authentication required" }, 401);
  }

  const userList = Array.from(users.values());
  return c.json({
    authenticated_as: auth.userId,
    count: userList.length,
    role: auth.role,
    users: userList,
  });
});

app.get("/api/users/:id", async (c) => {
  const auth = await getAuth(c);
  if (!auth) {
    return c.json({ error: "Authentication required" }, 401);
  }

  const id = c.req.param("id");
  const user = users.get(id);
  if (!user) {
    return c.json({ error: "User not found" }, 404);
  }
  return c.json(user);
});

app.post("/api/users", async (c) => {
  const auth = await getAuth(c);
  if (!auth) {
    return c.json({ error: "Authentication required" }, 401);
  }

  const body = (await c.req.json()) as { email: string; name: string };

  if (!body.name || !body.email) {
    return c.json({ error: "Name and email are required" }, 400);
  }

  const id = String(users.size + 1);
  const newUser: User = {
    email: body.email,
    id,
    name: body.name,
  };

  users.set(id, newUser);
  return c.json(newUser, 201);
});

app.put("/api/users/:id", async (c) => {
  const auth = await getAuth(c);
  if (!auth) {
    return c.json({ error: "Authentication required" }, 401);
  }

  const id = c.req.param("id");
  const user = users.get(id);
  if (!user) {
    return c.json({ error: "User not found" }, 404);
  }

  const body = (await c.req.json()) as Partial<User>;
  const updatedUser = { ...user, ...body, id: user.id };
  users.set(user.id, updatedUser);
  return c.json(updatedUser);
});

app.delete("/api/users/:id", async (c) => {
  const auth = await getAuth(c);
  if (!auth) {
    return c.json({ error: "Authentication required" }, 401);
  }

  const id = c.req.param("id");
  if (!users.has(id)) {
    return c.json({ error: "User not found" }, 404);
  }

  users.delete(id);
  return c.body(null, 204);
});

// Add a simple admin dashboard - requires admin role
app.get("/admin", async (c) => {
  const auth = await getAuth(c);
  if (!auth) {
    return c.json({ error: "Authentication required" }, 401);
  }

  // Check for admin role
  if (auth.role !== "admin") {
    return c.json({ error: "Admin access required" }, 403);
  }

  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Dashboard</title>
      <style>
        body { font-family: sans-serif; margin: 40px; }
        h1 { color: #333; }
        .stats { background: #f0f0f0; padding: 20px; border-radius: 8px; }
        .stat { margin: 10px 0; }
      </style>
    </head>
    <body>
      <h1>Admin Dashboard</h1>
      <div class="stats">
        <div class="stat">Total Users: ${users.size}</div>
        <div class="stat">Request Count: ${requestCount}</div>
        <div class="stat">Server Time: ${new Date().toISOString()}</div>
      </div>
      <h2>Users</h2>
      <ul>
        ${Array.from(users.values())
          .map((u) => `<li>${u.name} (${u.email})</li>`)
          .join("")}
      </ul>
    </body>
    </html>
  `;
  return c.html(html);
});

// Add a webhook endpoint
app.post("/webhook/github", async (c) => {
  const auth = await getAuth(c);
  if (!auth) {
    return c.json({ error: "Authentication required" }, 401);
  }

  const payload = await c.req.json();
  const event = c.req.header("x-github-event");

  console.log(`GitHub webhook received: ${event}`, payload);

  // Process webhook (e.g., trigger MCP tools)
  return c.json({ event, received: true });
});

// Add a file upload endpoint
app.post("/upload", async (c) => {
  const auth = await getAuth(c);
  if (!auth) {
    return c.json({ error: "Authentication required" }, 401);
  }

  try {
    const body = await c.req.text();
    const size = Buffer.byteLength(body);

    return c.json({
      message: "File received",
      size: `${size} bytes`,
    });
  } catch (error) {
    return c.json(
      {
        error: error instanceof Error ? error.message : "Upload failed",
      },
      500,
    );
  }
});

// Add middleware-like request counting
app.get("/stats", async (c) => {
  const auth = await getAuth(c);
  if (!auth) {
    return c.json({ error: "Authentication required" }, 401);
  }

  requestCount++;
  return c.json({
    requests: requestCount,
    timestamp: Date.now(),
    uptime: process.uptime(),
  });
});

// Add MCP tools that can interact with the custom routes
server.addTool({
  description: "List all users from the REST API",
  execute: async () => {
    const userList = Array.from(users.values());
    return {
      content: [
        {
          text: `Found ${userList.length} users:\n${userList
            .map((u) => `- ${u.name} (${u.email})`)
            .join("\n")}`,
          type: "text",
        },
      ],
    };
  },
  name: "list_users",
  parameters: z.object({}),
});

server.addTool({
  description: "Create a new user via the REST API",
  execute: async ({ email, name }) => {
    const id = String(users.size + 1);
    const newUser: User = { email, id, name };
    users.set(id, newUser);

    return {
      content: [
        {
          text: `User created successfully:\nID: ${id}\nName: ${name}\nEmail: ${email}`,
          type: "text",
        },
      ],
    };
  },
  name: "create_user",
  parameters: z.object({
    email: z.string().email(),
    name: z.string(),
  }),
});

server.addTool({
  description: "Get server statistics",
  execute: async () => {
    return {
      content: [
        {
          text: `Server Statistics:
- Total Users: ${users.size}
- Request Count: ${requestCount}
- Uptime: ${Math.floor(process.uptime())} seconds
- Memory Usage: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`,
          type: "text",
        },
      ],
    };
  },
  name: "get_stats",
  parameters: z.object({}),
});

// Add a resource that exposes the user list
server.addResource({
  description: "Current user database",
  load: async () => ({
    text: JSON.stringify(Array.from(users.values()), null, 2),
  }),
  mimeType: "application/json",
  name: "user-database",
  uri: "resource://users",
});

// Start the server
const PORT = process.env.FASTMCP_PORT
  ? parseInt(process.env.FASTMCP_PORT)
  : 8080;

server
  .start({
    httpStream: { port: PORT },
    transportType: "httpStream",
  })
  .then(() => {
    console.log(`
🚀 Custom Routes Example Server Started!

MCP Endpoint: http://localhost:${PORT}/mcp
Health Check: http://localhost:${PORT}/health

PUBLIC ROUTES (No Authentication):
- Status:       http://localhost:${PORT}/status
- Docs:         http://localhost:${PORT}/docs
- OAuth Config: http://localhost:${PORT}/.well-known/openid-configuration
- Static Files: http://localhost:${PORT}/public/*

PRIVATE ROUTES (Authentication Required):
- REST API:     http://localhost:${PORT}/api/users
- Admin Panel:  http://localhost:${PORT}/admin (admin only)
- Statistics:   http://localhost:${PORT}/stats
- File Upload:  http://localhost:${PORT}/upload
- GitHub Hook:  http://localhost:${PORT}/webhook/github

Authentication:
Use "Authorization: Bearer admin-token" or "Bearer user-token"

Try these commands:

# Public routes (no auth needed)
curl http://localhost:${PORT}/status
curl http://localhost:${PORT}/docs
curl http://localhost:${PORT}/.well-known/openid-configuration

# Private routes (auth required)
curl -H "Authorization: Bearer user-token" http://localhost:${PORT}/api/users
curl -H "Authorization: Bearer admin-token" http://localhost:${PORT}/admin
curl -X POST -H "Authorization: Bearer user-token" -H "Content-Type: application/json" \\
     -d '{"name":"Charlie","email":"charlie@example.com"}' \\
     http://localhost:${PORT}/api/users

# Test authentication failure
curl http://localhost:${PORT}/api/users  # Should return 401

MCP Tools available:
- list_users
- create_user  
- get_stats

Test with MCP Inspector:
npx fastmcp inspect src/examples/custom-routes.ts
  `);
  })
  .catch((error) => {
    console.error("Failed to start server:", error);
    process.exit(1);
  });
