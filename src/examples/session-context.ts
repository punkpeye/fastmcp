/**
 * Example demonstrating session context support in FastMCP stdio transport
 *
 * This example demonstrates the fix for issue #144:
 * Session context is now properly passed to tool execution handlers
 * when using stdio transport with an authenticate function.
 *
 * To run this example:
 * npx fastmcp dev src/examples/session-context.ts
 */

import { z } from "zod";

import { FastMCP } from "../FastMCP.js";

interface UserSession {
  [key: string]: unknown;
  permissions: string[];
  role: "admin" | "guest" | "user";
  userId: string;
  username: string;
}

const server = new FastMCP<UserSession>({
  authenticate: async (request) => {
    if (!request) {
      console.log(
        "[Auth] Authenticating stdio transport using environment variables",
      );

      const userId = process.env.USER_ID || "default-user";
      const username = process.env.USERNAME || "Anonymous";
      const role =
        (process.env.USER_ROLE as "admin" | "guest" | "user") || "guest";
      // Mock permissions based on role
      const permissions =
        role === "admin"
          ? ["read", "write", "delete", "admin"]
          : role === "user"
            ? ["read", "write"]
            : ["read"];
      const session: UserSession = {
        authenticatedAt: new Date().toISOString(),
        permissions,
        role,
        userId,
        username,
      };

      console.log(`[Auth] Authenticated user: ${username} (${role})`);

      return session;
    }

    // For HTTP transport (request contains headers)
    console.log("[Auth] Authenticating HTTP transport using headers");

    const authHeader = request.headers["authorization"] as string;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      throw new Response("Missing or invalid authorization header", {
        status: 401,
      });
    }

    const token = authHeader.substring(7);

    // Mock token validation (in real implementation, validate against your auth service)
    if (token === "admin-token") {
      return {
        authenticatedAt: new Date().toISOString(),
        permissions: ["read", "write", "delete", "admin"],
        role: "admin" as const,
        userId: "admin-001",
        username: "Administrator",
      };
    } else if (token === "user-token") {
      return {
        authenticatedAt: new Date().toISOString(),
        permissions: ["read", "write"],
        role: "user" as const,
        userId: "user-001",
        username: "Regular User",
      };
    }

    throw new Response("Invalid token", { status: 401 });
  },
  name: "Session Context Demo",
  version: "1.0.0",
});

// Tool that demonstrates session context access
server.addTool({
  description: "Get information about the current authenticated user",
  execute: async (_args, context) => {
    if (!context.session)
      return "No session context available (this shouldn't happen after the fix!)";

    const { session } = context;

    return `✓ Session Context Available!
    
User Info:
- User ID: ${session.userId}
- Username: ${session.username}  
- Role: ${session.role}
- Permissions: ${session.permissions.join(", ")}
- Authenticated At: ${session.authenticatedAt}`;
  },
  name: "whoami",
});

// Tool that demonstrates role-based access
server.addTool({
  description: "Perform an admin-only operation (requires admin role)",
  execute: async (args, context) => {
    if (!context.session)
      return "No session context - cannot verify permissions";
    if (context.session.role !== "admin")
      return `Access denied. Current role: ${context.session.role}, required: admin`;
    if (!context.session.permissions.includes("admin"))
      return "Insufficient permissions for admin operations";

    return `✓ Admin operation "${args.action}" executed successfully by ${context.session.username}`;
  },
  name: "admin-operation",
  parameters: z.object({
    action: z.string().describe("The admin action to perform"),
  }),
});

// Tool that demonstrates permission checks
server.addTool({
  description: "Check what permissions the current user has",
  execute: async (args, context) => {
    if (!context.session) return "No session context available";

    const hasPermission = context.session.permissions.includes(args.operation);

    return `Permission Check for "${args.operation}":
${hasPermission ? "✓ ALLOWED" : "! DENIED"}

Your permissions: ${context.session.permissions.join(", ")}
Your role: ${context.session.role}`;
  },
  name: "check-permissions",
  parameters: z.object({
    operation: z.string().describe("Operation to check permission for"),
  }),
});

// Resource that uses session context
server.addResource({
  description: "Get detailed information about the current authenticated user",
  load: async (auth) => {
    if (!auth) {
      return {
        text: JSON.stringify(
          {
            authenticated: false,
            error: "No authentication context available",
          },

          null,
          2,
        ),
      };
    }

    return {
      text: JSON.stringify(
        {
          authenticated: true,
          user: {
            authenticatedAt: auth.authenticatedAt,
            id: auth.userId,
            permissions: auth.permissions,
            role: auth.role,
            username: auth.username,
          },
        },

        null,
        2,
      ),
    };
  },
  mimeType: "application/json",
  name: "Current User Information",
  uri: "session://current-user",
});

// Prompt that uses session context
server.addPrompt({
  arguments: [
    {
      description: "Greeting style (formal, casual, friendly)",
      name: "style",
      required: false,
    },
  ],
  description: "Generate a personalized greeting based on the current user",
  load: async (args, auth) => {
    const style = args.style || "friendly";

    if (!auth) {
      return "Hello! I don't have access to your session information.";
    }

    const greetings = {
      casual: `Hey ${auth.username}! Nice to see you again.`,
      formal: `Good day, ${auth.username}. You are logged in with ${auth.role} privileges.`,
      friendly: `Hello ${auth.username}! 😊 You're logged in as a ${auth.role}. How can I help you today?`,
    };

    return greetings[style as keyof typeof greetings] || greetings.friendly;
  },
  name: "personalized-greeting",
});

// Start the server
if (process.argv.includes("--http-stream")) {
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

  server.start({
    httpStream: { port: PORT },
    transportType: "httpStream",
  });

  console.log(`
🚀 Session Context Demo server running on HTTP Stream!

Try these endpoints:
- MCP: http://localhost:${PORT}/mcp
- Health: http://localhost:${PORT}/health

Test with curl:
curl -H "Authorization: Bearer admin-token" \\
     -H "Content-Type: application/json" \\
     -d '{"method":"tools/call","params":{"name":"whoami","arguments":{}}}' \\
     http://localhost:${PORT}/mcp
`);
} else {
  server.start({ transportType: "stdio" });

  console.log(`
🚀 Session Context Demo server started with stdio transport!

Environment variables for authentication:
- USER_ID=${process.env.USER_ID || "(not set - will use 'default-user')"}
- USERNAME=${process.env.USERNAME || "(not set - will use 'Anonymous')"}  
- USER_ROLE=${process.env.USER_ROLE || "(not set - will use 'guest')"}

To test with different user roles:
USER_ID=admin001 USERNAME="John Admin" USER_ROLE=admin npx fastmcp dev src/examples/session-context.ts

Available tools:
- whoami: Get current user info
- admin-operation: Test admin permissions  
- check-permissions: Check specific permissions

Available resources:
- session://current-user: Current user JSON data

Available prompts:
- personalized-greeting: Get a personalized greeting
`);
}
