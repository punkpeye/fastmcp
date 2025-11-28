/**
 * Example FastMCP server with INTEGRATED OAuth Proxy
 *
 * This example shows the seamless Python-style integration where
 * OAuth routes are automatically registered - no manual setup needed!
 *
 * Run with: node dist/examples/oauth-integrated-server.js
 */

import { GoogleProvider } from "../auth/index.js";
import { FastMCP } from "../FastMCP.js";

// Create OAuth Proxy
const authProxy = new GoogleProvider({
  baseUrl: "http://localhost:4300",
  clientId: process.env.GOOGLE_CLIENT_ID || "your-google-client-id",
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || "your-google-client-secret",
  consentRequired: true,
  scopes: ["openid", "profile", "email"],
});

// Create FastMCP server with OAuth Proxy
// Just pass the proxy - routes are automatically registered!
const server = new FastMCP({
  name: "OAuth Integrated Server",
  oauth: {
    // Include authorization server metadata from the proxy
    authorizationServer: authProxy.getAuthorizationServerMetadata(),
    enabled: true,
    // Pass the proxy instance - this enables automatic route registration
    proxy: authProxy,
  },
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
  description: "Get user information (requires OAuth)",
  execute: async (_args, { session }) => {
    // In a real implementation, you would extract the access token
    // from session headers and use it to call Google APIs
    return {
      content: [
        {
          text: `Session ID: ${session?.id || "none"}\nThis tool would use the OAuth access token to fetch user data from Google.`,
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
No manual route setup - just pass the OAuth Proxy and go! 🎉
`);
