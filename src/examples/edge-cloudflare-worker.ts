/**
 * EdgeFastMCP - Cloudflare Workers Example
 *
 * This example demonstrates how to use FastMCP on Cloudflare Workers
 * using the edge-compatible module.
 *
 * To deploy:
 * 1. Copy this file to your Cloudflare Workers project
 * 2. Install fastmcp: npm install fastmcp
 * 3. Change the import to: import { EdgeFastMCP } from "fastmcp/edge";
 * 4. Create a wrangler.toml with:
 *    name = "my-mcp-server"
 *    main = "src/index.ts"
 *    compatibility_date = "2024-11-01"
 * 5. Deploy with: npx wrangler deploy
 */

import { z } from "zod";

// NOTE: In your deployed project, use: import { EdgeFastMCP } from "fastmcp/edge";
import { EdgeFastMCP } from "../edge/index.js";

// Create the edge-compatible MCP server
const server = new EdgeFastMCP({
  description: "An MCP server running on Cloudflare Workers",
  name: "CloudflareWorkerMCP",
  version: "1.0.0",
});

// Add a simple tool
server.addTool({
  description: "Greet someone by name",
  execute: async ({ name }) => {
    return `Hello, ${name}! This response is from a Cloudflare Worker.`;
  },
  name: "greet",
  parameters: z.object({
    name: z.string().describe("The name to greet"),
  }),
});

// Add a tool that returns structured content
server.addTool({
  description: "Get weather information for a location",
  execute: async ({ location }) => {
    // In a real app, you would call a weather API here
    return {
      content: [
        {
          text: `Weather for ${location}:\n- Temperature: 72°F\n- Conditions: Sunny\n- Humidity: 45%`,
          type: "text",
        },
      ],
    };
  },
  name: "get_weather",
  parameters: z.object({
    location: z.string().describe("The city or location"),
  }),
});

// Add a static resource
server.addResource({
  description: "Information about this MCP server",
  load: async () => {
    return "This is a FastMCP server running on Cloudflare Workers edge runtime.";
  },
  mimeType: "text/plain",
  name: "Server Info",
  uri: "info://server",
});

// Add a prompt template
server.addPrompt({
  arguments: [
    { description: "Programming language", name: "language", required: true },
    {
      description: "What to focus on (optional)",
      name: "focus",
      required: false,
    },
  ],
  description: "Generate a prompt to analyze code",
  load: async (args) => {
    const focus = args.focus ? ` focusing on ${args.focus}` : "";
    return {
      messages: [
        {
          content: {
            text: `Please analyze the following ${args.language} code${focus}:`,
            type: "text",
          },
          role: "user",
        },
      ],
    };
  },
  name: "analyze_code",
});

// Export the server as the default (Cloudflare Workers format)
export default server;

// Alternative: You can also access the underlying Hono app for custom routes
// const app = server.getApp();
// app.get("/custom", (c) => c.text("Custom route!"));
// export default { fetch: (req) => server.fetch(req) };
