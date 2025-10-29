/**
 * Example demonstrating CORS configuration in FastMCP
 *
 * This example shows how to customize CORS settings when using HTTP Stream transport.
 * By default, CORS is enabled with permissive settings. You can customize or disable it.
 *
 * To run this example:
 * node dist/examples/cors-configuration.js
 *
 * Or with tsx:
 * npx tsx src/examples/cors-configuration.ts
 */

import { z } from "zod";

import { FastMCP } from "../FastMCP.js";

const server = new FastMCP({
  name: "CORS Configuration Demo",
  version: "1.0.0",
});

server.addTool({
  description: "A simple echo tool to test CORS",
  execute: async (args) => {
    return `Echo: ${args.message}`;
  },
  name: "echo",
  parameters: z.object({
    message: z.string().describe("The message to echo back"),
  }),
});

// Example 1: Default CORS (permissive, enabled by default)
// This is what happens if you don't specify cors option
console.log("\n=== Example 1: Default CORS Settings ===");
console.log("CORS is enabled by default with permissive settings:");
console.log("- origin: '*' (all origins allowed)");
console.log("- methods: ['GET', 'POST', 'OPTIONS']");
console.log("- allowedHeaders: 'Content-Type, Authorization, Accept, Mcp-Session-Id, Last-Event-Id'");
console.log("- credentials: true");
console.log("- exposedHeaders: ['Mcp-Session-Id']");

// Example 2: Custom CORS configuration
console.log("\n=== Example 2: Custom CORS Configuration ===");
const customCorsServer = new FastMCP({
  name: "Custom CORS Demo",
  version: "1.0.0",
});

customCorsServer.addTool({
  description: "A simple echo tool",
  execute: async (args) => {
    return `Echo: ${args.message}`;
  },
  name: "echo",
  parameters: z.object({
    message: z.string().describe("The message to echo back"),
  }),
});

// Start with custom CORS settings
const PORT_CUSTOM = 8081;
customCorsServer.start({
  httpStream: {
    cors: {
      // Allow specific headers
      allowedHeaders: ["Content-Type", "Authorization"],
      // Enable credentials
      credentials: true,
      // Expose custom headers
      exposedHeaders: ["X-Custom-Header"],
      // Cache preflight requests for 1 hour
      maxAge: 3600,
      // Allow specific methods
      methods: ["GET", "POST"],
      // Allow only specific origins
      origin: ["http://localhost:3000", "https://example.com"],
    },
    port: PORT_CUSTOM,
  },
  transportType: "httpStream",
});

console.log(`Custom CORS server running on http://localhost:${PORT_CUSTOM}/mcp`);

// Example 3: Dynamic origin validation with function
console.log("\n=== Example 3: Dynamic Origin Validation ===");
const dynamicCorsServer = new FastMCP({
  name: "Dynamic CORS Demo",
  version: "1.0.0",
});

dynamicCorsServer.addTool({
  description: "A simple echo tool",
  execute: async (args) => {
    return `Echo: ${args.message}`;
  },
  name: "echo",
  parameters: z.object({
    message: z.string().describe("The message to echo back"),
  }),
});

const PORT_DYNAMIC = 8082;
dynamicCorsServer.start({
  httpStream: {
    cors: {
      credentials: true,
      // Use a function to dynamically validate origins
      origin: (origin: string) => {
        // Allow all localhost origins and example.com
        return origin.startsWith("http://localhost") || 
               origin.endsWith(".example.com");
      },
    },
    port: PORT_DYNAMIC,
  },
  transportType: "httpStream",
});

console.log(`Dynamic CORS server running on http://localhost:${PORT_DYNAMIC}/mcp`);

// Example 4: Disable CORS
console.log("\n=== Example 4: CORS Disabled ===");
const noCorsServer = new FastMCP({
  name: "No CORS Demo",
  version: "1.0.0",
});

noCorsServer.addTool({
  description: "A simple echo tool",
  execute: async (args) => {
    return `Echo: ${args.message}`;
  },
  name: "echo",
  parameters: z.object({
    message: z.string().describe("The message to echo back"),
  }),
});

const PORT_NO_CORS = 8083;
noCorsServer.start({
  httpStream: {
    // Disable CORS entirely
    cors: false,
    port: PORT_NO_CORS,
  },
  transportType: "httpStream",
});

console.log(`No CORS server running on http://localhost:${PORT_NO_CORS}/mcp`);

// Example 5: Start the default server (using default CORS)
const PORT_DEFAULT = 8080;
server.start({
  httpStream: {
    port: PORT_DEFAULT,
  },
  transportType: "httpStream",
});

console.log(`\nDefault CORS server running on http://localhost:${PORT_DEFAULT}/mcp`);

console.log("\n=== Testing the servers ===");
console.log("You can test CORS by making requests from different origins:");
console.log("\nFrom browser console (assuming you're on http://localhost:3000):");
console.log(`
fetch('http://localhost:${PORT_CUSTOM}/mcp', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    jsonrpc: '2.0',
    method: 'tools/list',
    id: 1
  })
})
  .then(r => r.json())
  .then(console.log)
  .catch(console.error);
`);

console.log("\nOr use curl to test preflight requests:");
console.log(`
curl -X OPTIONS http://localhost:${PORT_CUSTOM}/mcp \\
  -H "Origin: http://localhost:3000" \\
  -H "Access-Control-Request-Method: POST" \\
  -v
`);

console.log("\n=== Summary ===");
console.log("CORS options available:");
console.log("- origin: string | string[] | ((origin: string) => boolean) - Control allowed origins");
console.log("- methods: string[] - Allowed HTTP methods");
console.log("- allowedHeaders: string | string[] - Allowed request headers");
console.log("- credentials: boolean - Allow credentials");
console.log("- exposedHeaders: string[] - Headers exposed to the client");
console.log("- maxAge: number - Preflight cache duration in seconds");
console.log("\nSet cors: false to disable CORS entirely");
console.log("Omit cors option to use default permissive settings");

