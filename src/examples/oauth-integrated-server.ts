/**
 * Example FastMCP server with INTEGRATED OAuth Proxy
 *
 * This example shows the seamless Python-style integration where
 * OAuth routes are automatically registered - no manual setup needed!
 *
 * Run with: node dist/examples/oauth-integrated-server.js
 */

import { getAuthSession, GoogleProvider, requireAuth } from "../auth/index.js";
import { FastMCP } from "../FastMCP.js";

// Create FastMCP server with OAuth Provider
// Just pass the provider via `auth` - routes are automatically registered!
const server = new FastMCP({
  auth: new GoogleProvider({
    baseUrl: "http://localhost:4300",
    clientId: process.env.GOOGLE_CLIENT_ID || "your-google-client-id",
    clientSecret:
      process.env.GOOGLE_CLIENT_SECRET || "your-google-client-secret",
    consentRequired: true,
    scopes: ["openid", "profile", "email"],
  }),
  name: "OAuth Integrated Server",
  version: "1.0.0",
});

// Add tools as normal
server.addTool({
  description: "Get current timestamp",
  execute: async () => {
    return {
      content: [
        {
          text: `Current time: ${new Date().toISOString()}`,
          type: "text" as const,
        },
      ],
    };
  },
  name: "get-time",
});

server.addTool({
  canAccess: requireAuth, // Only show this tool to authenticated users
  description: "Get user information (requires OAuth)",
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

// Start the server
await server.start({
  httpStream: { port: 4300 },
  transportType: "httpStream",
});

console.log(`
🚀 OAuth Integrated Server is running!

Base URL: http://localhost:4300

MCP Endpoints:
- HTTP Stream: http://localhost:4300/mcp
- SSE: http://localhost:4300/sse
- Health: http://localhost:4300/health

OAuth Endpoints (automatically registered!):
- Registration (DCR): http://localhost:4300/oauth/register
- Authorization: http://localhost:4300/oauth/authorize
- Token: http://localhost:4300/oauth/token
- Callback: http://localhost:4300/oauth/callback
- Consent: http://localhost:4300/oauth/consent

Discovery:
- OAuth Server Metadata: http://localhost:4300/.well-known/oauth-authorization-server

Complete OAuth Flow:
1. Client registers via DCR → receives Google credentials
2. Client initiates authorization → user sees consent screen
3. User approves → redirected to Google
4. Google authenticates user → redirects back to proxy
5. Proxy generates auth code → redirects to client
6. Client exchanges code for tokens → ready to use!

Environment Variables:
- GOOGLE_CLIENT_ID: Your Google OAuth client ID
- GOOGLE_CLIENT_SECRET: Your Google OAuth client secret

Google OAuth App Setup:
1. Go to https://console.cloud.google.com/apis/credentials
2. Create OAuth 2.0 Client ID
3. Add authorized redirect URI: http://localhost:4300/oauth/callback
4. Copy client ID and secret to environment variables

Python-Style Integration:
This TypeScript server works exactly like Python FastMCP!
Just use auth: new GoogleProvider({...}) and go! 🎉
`);
