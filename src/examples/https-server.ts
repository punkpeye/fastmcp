import { z } from "zod";

import { FastMCP } from "../FastMCP.js";

/**
 * Example demonstrating HTTPS support in FastMCP
 *
 * This example uses pre-generated self-signed certificates from src/fixtures/certs/
 *
 * To run this example:
 * ```bash
 * npx tsx src/examples/https-server.ts
 * ```
 *
 * Test with curl (use -k to ignore self-signed cert warnings):
 * ```bash
 * # Health check
 * curl -k https://localhost:8443/health
 *
 * # Call the greet tool
 * curl -k -X POST https://localhost:8443/mcp \
 *   -H "Content-Type: application/json" \
 *   -H "Accept: application/json, text/event-stream" \
 *   -d '{
 *     "jsonrpc": "2.0",
 *     "id": 1,
 *     "method": "tools/call",
 *     "params": {
 *       "name": "greet",
 *       "arguments": {
 *         "name": "World"
 *       }
 *     }
 *   }'
 * ```
 *
 * For production, obtain certificates from a trusted CA like Let's Encrypt:
 * ```bash
 * # Using certbot for Let's Encrypt
 * certbot certonly --standalone -d yourdomain.com
 *
 * # Or for testing with self-signed (NOT for production):
 * openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=yourdomain.com"
 * ```
 */

const server = new FastMCP({
  name: "HTTPS Example Server",
  version: "1.0.0",
});

server.addTool({
  description: "Greet someone over HTTPS",
  execute: async ({ name }) => {
    return `Hello, ${name}! This response came over HTTPS.`;
  },
  name: "greet",
  parameters: z.object({
    name: z.string(),
  }),
});

server.start({
  httpStream: {
    port: 8443,
    sslCert: "./src/fixtures/certs/server-cert.pem",
    sslKey: "./src/fixtures/certs/server-key.pem",
    stateless: true,
    // sslCa: "./ca.pem",   // Optional: CA certificate for client cert auth
  },
  transportType: "httpStream",
});
