/**
 * Example FastMCP server with OAuth
 *
 * This example demonstrates how to use the simplified auth configuration
 * to enable Dynamic Client Registration for providers that don't support it natively.
 *
 * Run with: node dist/examples/oauth-proxy-server.js
 */

import { getAuthSession, GoogleProvider, requireAuth } from "../auth/index.js";
import { FastMCP } from "../FastMCP.js";

// Create FastMCP server with Google OAuth
const server = new FastMCP({
  auth: new GoogleProvider({
    baseUrl: "http://localhost:4200",
    clientId: process.env.GOOGLE_CLIENT_ID || "your-google-client-id",
    clientSecret:
      process.env.GOOGLE_CLIENT_SECRET || "your-google-client-secret",
    consentRequired: true,
    scopes: ["openid", "profile", "email"],
  }),
  name: "OAuth Example Server",
  version: "1.0.0",
});

// Add a tool that requires authentication
server.addTool({
  canAccess: requireAuth, // Only visible to authenticated users
  description: "Get user information from OAuth token",
  execute: async (_, { session }) => {
    const { accessToken } = getAuthSession(session);
    return {
      content: [
        {
          text: `Authenticated! Token starts with: ${accessToken.slice(0, 8)}...`,
          type: "text" as const,
        },
      ],
    };
  },
  name: "get-user-info",
});

// Start the server with HTTP Stream transport
await server.start({
  httpStream: { port: 4200 },
  transportType: "httpStream",
});

console.log(`
🚀 OAuth Example Server is running!

Configuration:
- Base URL: http://localhost:4200
- Provider: Google OAuth 2.0

Available Endpoints:
- MCP (HTTP Stream): http://localhost:4200/mcp
- MCP (SSE): http://localhost:4200/sse
- Health: http://localhost:4200/health

OAuth Endpoints:
- Registration (DCR): http://localhost:4200/oauth/register
- Authorization: http://localhost:4200/oauth/authorize
- Token: http://localhost:4200/oauth/token
- Callback: http://localhost:4200/oauth/callback

Discovery:
- OAuth Server Metadata: http://localhost:4200/.well-known/oauth-authorization-server

Flow:
1. Client registers via DCR endpoint (receives upstream Google credentials)
2. Client initiates OAuth flow via authorization endpoint
3. User gives consent (if required)
4. User authenticates with Google
5. Proxy exchanges tokens and generates client authorization code
6. Client exchanges code for access token
7. Client uses access token to call MCP tools

Environment Variables:
- GOOGLE_CLIENT_ID: Your Google OAuth client ID
- GOOGLE_CLIENT_SECRET: Your Google OAuth client secret

Note: Make sure to configure your Google OAuth app with the callback URL:
http://localhost:4200/oauth/callback
`);
