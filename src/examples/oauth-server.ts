/**
 * Example FastMCP server demonstrating OAuth well-known endpoint support.
 *
 * This example shows how to configure FastMCP to serve OAuth discovery endpoints
 * for both authorization server metadata and protected resource metadata.
 *
 * Run with: node dist/examples/oauth-server.js --transport http-stream --port 4111
 * Then visit:
 * - http://localhost:4111/.well-known/oauth-authorization-server
 * - http://localhost:4111/.well-known/oauth-protected-resource
 */

import { FastMCP } from "../FastMCP.js";

const server = new FastMCP({
  name: "OAuth Example Server",
  oauth: {
    authorizationServer: {
      authorizationEndpoint: "https://auth.example.com/oauth/authorize",
      codeChallengeMethodsSupported: ["S256"],
      // DPoP support
      dpopSigningAlgValuesSupported: ["ES256", "RS256"],
      grantTypesSupported: ["authorization_code", "refresh_token"],

      introspectionEndpoint: "https://auth.example.com/oauth/introspect",
      // Required fields
      issuer: "https://auth.example.com",
      // Optional fields
      jwksUri: "https://auth.example.com/.well-known/jwks.json",
      opPolicyUri: "https://example.com/policy",
      opTosUri: "https://example.com/terms",
      registrationEndpoint: "https://auth.example.com/oauth/register",
      responseModesSupported: ["query", "fragment"],
      responseTypesSupported: ["code"],
      revocationEndpoint: "https://auth.example.com/oauth/revoke",
      scopesSupported: ["read", "write", "admin"],
      serviceDocumentation: "https://docs.example.com/oauth",
      tokenEndpoint: "https://auth.example.com/oauth/token",
      tokenEndpointAuthMethodsSupported: [
        "client_secret_basic",
        "client_secret_post",
      ],
      tokenEndpointAuthSigningAlgValuesSupported: ["RS256", "ES256"],

      uiLocalesSupported: ["en-US", "es-ES"],
    },
    enabled: true,
    protectedResource: {
      authorizationServers: ["https://auth.example.com"],
      bearerMethodsSupported: ["header"],
      jwksUri: "https://oauth-example-server.example.com/.well-known/jwks.json",
      resource: "mcp://oauth-example-server",
      resourceDocumentation: "https://docs.example.com/mcp-api",
      resourcePolicyUri: "https://example.com/resource-policy",
    },
  },
  version: "1.0.0",
});

// Add a simple tool to demonstrate the server functionality
server.addTool({
  description: "Get information about this OAuth-enabled MCP server",
  execute: async () => {
    return {
      content: [
        {
          text: `This is an OAuth-enabled FastMCP server!

OAuth Discovery Endpoints:
- Authorization Server: /.well-known/oauth-authorization-server
- Protected Resource: /.well-known/oauth-protected-resource

The server demonstrates how to configure OAuth metadata for MCP servers
that need to integrate with OAuth 2.0 authorization flows.`,
          type: "text",
        },
      ],
    };
  },
  name: "get-server-info",
});

// Start the server
await server.start({
  httpStream: { port: 4111 },
  transportType: "httpStream",
});

console.log(`
🚀 OAuth Example Server is running!

Try these endpoints:
- MCP (HTTP Stream): http://localhost:4111/mcp
- MCP (SSE): http://localhost:4111/sse
- Health: http://localhost:4111/health
- OAuth Authorization Server: http://localhost:4111/.well-known/oauth-authorization-server
- OAuth Protected Resource: http://localhost:4111/.well-known/oauth-protected-resource

The OAuth endpoints work with both SSE and HTTP Stream transports and return
JSON metadata following RFC 8414 standards.
`);
