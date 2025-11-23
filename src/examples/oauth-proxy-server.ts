/**
 * Example FastMCP server with OAuth Proxy
 *
 * This example demonstrates how to use the OAuth Proxy to enable
 * Dynamic Client Registration for providers that don't support it natively.
 *
 * Run with: node dist/examples/oauth-proxy-server.js
 */

import { GoogleProvider } from "../auth/index.js";
import { FastMCP } from "../FastMCP.js";

// Create OAuth Proxy using Google provider
const authProxy = new GoogleProvider({
  baseUrl: "http://localhost:4200",
  clientId: process.env.GOOGLE_CLIENT_ID || "your-google-client-id",
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || "your-google-client-secret",
  consentRequired: true,
  scopes: ["openid", "profile", "email"],
});

// Create FastMCP server with OAuth Proxy
const server = new FastMCP({
  name: "OAuth Proxy Example Server",
  oauth: {
    authorizationServer: authProxy.getAuthorizationServerMetadata(),
    enabled: true,
  },
  version: "1.0.0",
});

// Add a tool that requires authentication
server.addTool({
  description: "Get user information from OAuth token",
  execute: async (_args, { session }) => {
    // In a real implementation, you would extract and verify the access token
    // from the session headers and use it to fetch user information
    return {
      content: [
        {
          text: `Authenticated session: ${session?.id || "none"}`,
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
🚀 OAuth Proxy Example Server is running!

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
