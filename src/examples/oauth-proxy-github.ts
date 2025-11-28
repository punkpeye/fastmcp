/**
 * Example FastMCP server with GitHub OAuth Proxy
 *
 * This example shows how to use GitHub as the OAuth provider
 *
 * Run with: node dist/examples/oauth-proxy-github.js
 */

import { GitHubProvider } from "../auth/index.js";
import { FastMCP } from "../FastMCP.js";

// Create OAuth Proxy using GitHub provider
const authProxy = new GitHubProvider({
  baseUrl: "http://localhost:4201",
  clientId: process.env.GITHUB_CLIENT_ID || "your-github-client-id",
  clientSecret: process.env.GITHUB_CLIENT_SECRET || "your-github-client-secret",
  scopes: ["read:user", "user:email"],
});

const server = new FastMCP({
  name: "GitHub OAuth Proxy Server",
  oauth: {
    authorizationServer: authProxy.getAuthorizationServerMetadata(),
    enabled: true,
  },
  version: "1.0.0",
});

server.addTool({
  description: "Get GitHub repositories for authenticated user",
  execute: async () => {
    return {
      content: [
        {
          text: "This would fetch repositories using the OAuth access token",
          type: "text" as const,
        },
      ],
    };
  },
  name: "get-repositories",
});

await server.start({
  httpStream: { port: 4201 },
  transportType: "httpStream",
});

console.log(`
🚀 GitHub OAuth Proxy Server is running on http://localhost:4201

OAuth Provider: GitHub
Callback URL: http://localhost:4201/oauth/callback

Make sure to configure this callback URL in your GitHub OAuth App settings.
`);
