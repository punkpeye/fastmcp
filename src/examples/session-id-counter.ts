/**
 * Example demonstrating session ID support in FastMCP
 *
 * This example shows how to use the sessionId from the Mcp-Session-Id header
 * to implement per-session state management, such as maintaining counters
 * or tracking user-specific data across multiple requests.
 *
 * To run this example:
 * npx fastmcp dev src/examples/session-id-counter.ts --http-stream
 *
 * Then test with multiple clients to see how each session maintains its own state.
 */

import { z } from "zod";

import { FastMCP } from "../FastMCP.js";

interface UserSession {
  [key: string]: unknown;
  role: "admin" | "user";
  userId: string;
}

const server = new FastMCP<UserSession>({
  authenticate: async (request) => {
    if (!request) {
      // stdio transport
      return {
        role: "user" as const,
        userId: process.env.USER_ID || "default-user",
      };
    }

    // HTTP transport - check authorization header
    const authHeader = request.headers["authorization"] as string;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      throw new Response("Missing or invalid authorization header", {
        status: 401,
      });
    }

    const token = authHeader.substring(7);

    // Mock token validation
    if (token === "admin-token") {
      return {
        role: "admin" as const,
        userId: "admin-001",
      };
    } else if (token === "user-token") {
      return {
        role: "user" as const,
        userId: "user-001",
      };
    }

    throw new Response("Invalid token", { status: 401 });
  },
  name: "Session ID Counter Demo",
  version: "1.0.0",
});

// Per-session counter storage
// In a real application, this could be Redis, a database, or any other storage
const sessionCounters = new Map<string, number>();
const sessionData = new Map<
  string,
  { createdAt: Date; lastAccessed: Date; requestCount: number }
>();

// Tool to increment a per-session counter
server.addTool({
  description:
    "Increment a counter that is unique to your session. Each client session maintains its own independent counter.",
  execute: async (_args, context) => {
    if (!context.sessionId) {
      return "❌ No session ID available. This tool requires HTTP transport with session tracking.";
    }

    const currentCount = sessionCounters.get(context.sessionId) || 0;
    const newCount = currentCount + 1;
    sessionCounters.set(context.sessionId, newCount);

    // Update session metadata
    const metadata = sessionData.get(context.sessionId) || {
      createdAt: new Date(),
      lastAccessed: new Date(),
      requestCount: 0,
    };
    metadata.lastAccessed = new Date();
    metadata.requestCount += 1;
    sessionData.set(context.sessionId, metadata);

    return `✓ Counter incremented!

Session ID: ${context.sessionId}
Counter Value: ${newCount}
User: ${context.session?.userId}
Role: ${context.session?.role}

Session Info:
- Created: ${metadata.createdAt.toISOString()}
- Last Accessed: ${metadata.lastAccessed.toISOString()}
- Total Requests: ${metadata.requestCount}`;
  },
  name: "increment-counter",
  parameters: z.object({}),
});

// Tool to get the current counter value
server.addTool({
  description: "Get the current value of your session's counter",
  execute: async (_args, context) => {
    if (!context.sessionId) {
      return "❌ No session ID available. This tool requires HTTP transport with session tracking.";
    }

    const currentCount = sessionCounters.get(context.sessionId) || 0;
    const metadata = sessionData.get(context.sessionId);

    return `Session ID: ${context.sessionId}
Counter Value: ${currentCount}
User: ${context.session?.userId}
${metadata ? `\nSession created: ${metadata.createdAt.toISOString()}\nTotal requests: ${metadata.requestCount}` : ""}`;
  },
  name: "get-counter",
  parameters: z.object({}),
});

// Tool to reset the counter
server.addTool({
  description: "Reset your session's counter to zero",
  execute: async (_args, context) => {
    if (!context.sessionId) {
      return "❌ No session ID available. This tool requires HTTP transport with session tracking.";
    }

    sessionCounters.set(context.sessionId, 0);

    return `✓ Counter reset to 0 for session ${context.sessionId}`;
  },
  name: "reset-counter",
  parameters: z.object({}),
});

// Tool to list all active sessions (admin only)
server.addTool({
  description: "List all active sessions and their counter values (admin only)",
  execute: async (_args, context) => {
    if (context.session?.role !== "admin") {
      return "❌ Access denied. This tool requires admin role.";
    }

    if (sessionCounters.size === 0) {
      return "No active sessions with counters.";
    }

    const sessions = Array.from(sessionCounters.entries())
      .map(([sessionId, count]) => {
        const metadata = sessionData.get(sessionId);
        return `- Session: ${sessionId.substring(0, 8)}...
  Counter: ${count}
  Created: ${metadata?.createdAt.toISOString() || "unknown"}
  Requests: ${metadata?.requestCount || 0}`;
      })
      .join("\n\n");

    return `Active Sessions (${sessionCounters.size}):\n\n${sessions}`;
  },
  name: "list-sessions",
  parameters: z.object({}),
});

// Tool to demonstrate request ID tracking
server.addTool({
  description:
    "Show both session ID and request ID to demonstrate per-request tracking",
  execute: async (_args, context) => {
    return `Session & Request Information:

Session ID: ${context.sessionId || "N/A"}
Request ID: ${context.requestId || "N/A"}
User ID: ${context.session?.userId || "N/A"}
Role: ${context.session?.role || "N/A"}

The session ID remains constant across multiple requests from the same client,
while the request ID is unique for each individual request.`;
  },
  name: "show-ids",
  parameters: z.object({}),
});

// Start the server
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

server.start({
  httpStream: { port: PORT },
  transportType: "httpStream",
});

console.log(`
🚀 Session ID Counter Demo server running!

Server: http://localhost:${PORT}/mcp
Health: http://localhost:${PORT}/health

Test with curl:
# User token
curl -H "Authorization: Bearer user-token" \\
     -H "Content-Type: application/json" \\
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}' \\
     http://localhost:${PORT}/mcp

# Then call tools (use the Mcp-Session-Id from the initialize response)
curl -H "Authorization: Bearer user-token" \\
     -H "Mcp-Session-Id: YOUR_SESSION_ID" \\
     -H "Content-Type: application/json" \\
     -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"increment-counter","arguments":{}}}' \\
     http://localhost:${PORT}/mcp

Available tools:
- increment-counter: Increment your session's counter
- get-counter: Get current counter value
- reset-counter: Reset counter to zero
- list-sessions: List all sessions (admin only)
- show-ids: Display session and request IDs

Try connecting with multiple clients to see how each maintains its own counter!
`);