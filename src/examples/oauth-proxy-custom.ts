/**
 * Example FastMCP server with custom OAuth Proxy
 *
 * This example shows how to configure a custom OAuth provider
 *
 * Run with: node dist/examples/oauth-proxy-custom.js
 */

import { OAuthProxy } from "../auth/index.js";
import { FastMCP } from "../FastMCP.js";

// Create OAuth Proxy with custom provider configuration
const authProxy = new OAuthProxy({
  baseUrl: "http://localhost:4202",
  scopes: ["openid", "profile"],
  upstreamAuthorizationEndpoint: "https://your-provider.com/oauth/authorize",
  upstreamClientId: process.env.OAUTH_CLIENT_ID || "your-client-id",
  upstreamClientSecret: process.env.OAUTH_CLIENT_SECRET || "your-client-secret",
  upstreamTokenEndpoint: "https://your-provider.com/oauth/token",
});

const server = new FastMCP({
  name: "Custom OAuth Proxy Server",
  oauth: {
    authorizationServer: authProxy.getAuthorizationServerMetadata(),
    enabled: true,
  },
  version: "1.0.0",
});

server.addTool({
  description: "Protected tool requiring OAuth authentication",
  execute: async () => {
    return {
      content: [
        {
          text: "This tool is protected by OAuth",
          type: "text" as const,
        },
      ],
    };
  },
  name: "protected-tool",
});

await server.start({
  httpStream: { port: 4202 },
  transportType: "httpStream",
});

console.log(`
🚀 Custom OAuth Proxy Server is running on http://localhost:4202

Configure your OAuth provider with callback URL: http://localhost:4202/oauth/callback
`);
