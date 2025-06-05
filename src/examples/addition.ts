/**
 * Example FastMCP server demonstrating core functionality plus streaming output.
 *
 * Features demonstrated:
 * - Basic tool with type-safe parameters
 * - Streaming-enabled tool for incremental output
 * - Advanced tool annotations
 *
 * For a complete project template, see https://github.com/punkpeye/fastmcp-boilerplate
 */
import { type } from "arktype";
import * as v from "valibot";
import { z } from "zod";

import { FastMCP } from "../FastMCP.js";

const server = new FastMCP({
  name: "Addition",
  ping: {
    // enabled: undefined,
    // Automatically enabled/disabled based on transport type
    // Using a longer interval to reduce log noise
    intervalMs: 10000, // default is 5000ms
    // Reduce log verbosity
    logLevel: "debug", // default
  },
  roots: {
    // You can explicitly disable roots support if needed
    // enabled: false,
  },
  version: "1.0.0",
});

// --- Zod Example ---
const AddParamsZod = z.object({
  a: z.number().describe("The first number"),
  b: z.number().describe("The second number"),
});

server.addTool({
  annotations: {
    openWorldHint: false, // This tool doesn't interact with external systems
    readOnlyHint: true, // This tool doesn't modify anything
    title: "Addition (Zod)",
  },
  description: "Add two numbers (using Zod schema)",
  execute: async (args) => {
    // args is typed as { a: number, b: number }
    console.log(`[Zod] Adding ${args.a} and ${args.b}`);
    return String(args.a + args.b);
  },
  name: "add-zod",
  parameters: AddParamsZod,
});

// --- ArkType Example ---
const AddParamsArkType = type({
  a: "number",
  b: "number",
});

server.addTool({
  annotations: {
    destructiveHint: true, // This would perform destructive operations
    idempotentHint: true, // But operations can be repeated safely
    openWorldHint: true, // Interacts with external systems
    readOnlyHint: false, // Example showing a modifying tool
    title: "Addition (ArkType)",
  },
  description: "Add two numbers (using ArkType schema)",
  execute: async (args, { log }) => {
    // args is typed as { a: number, b: number } based on AddParamsArkType.infer
    console.log(`[ArkType] Adding ${args.a} and ${args.b}`);

    // Demonstrate long-running operation that might need a timeout
    log.info("Starting calculation with potential delay...");

    // Simulate a complex calculation process
    if (args.a > 1000 || args.b > 1000) {
      log.warn("Large numbers detected, operation might take longer");
      // In a real implementation, this delay might be a slow operation
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }

    return String(args.a + args.b);
  },
  name: "add-arktype",
  parameters: AddParamsArkType,
  // Will abort execution after 2s
  timeoutMs: 2000,
});

// --- Valibot Example ---
const AddParamsValibot = v.object({
  a: v.number("The first number"),
  b: v.number("The second number"),
});

server.addTool({
  annotations: {
    openWorldHint: false,
    readOnlyHint: true,
    title: "Addition (Valibot)",
  },
  description: "Add two numbers (using Valibot schema)",
  execute: async (args) => {
    console.log(`[Valibot] Adding ${args.a} and ${args.b}`);
    return String(args.a + args.b);
  },
  name: "add-valibot",
  parameters: AddParamsValibot,
});

server.addResource({
  async load() {
    return {
      text: "Example log content",
    };
  },
  mimeType: "text/plain",
  name: "Application Logs",
  uri: "file:///logs/app.log",
});

server.addTool({
  annotations: {
    openWorldHint: false,
    readOnlyHint: true,
    streamingHint: true,
  },
  description: "Generate a poem line by line with streaming output",
  execute: async (args, context) => {
    const { theme } = args;
    const lines = [
      `Poem about ${theme} - line 1`,
      `Poem about ${theme} - line 2`,
      `Poem about ${theme} - line 3`,
      `Poem about ${theme} - line 4`,
    ];

    for (const line of lines) {
      await context.streamContent({
        text: line,
        type: "text",
      });

      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    return;
  },
  name: "stream-poem",
  parameters: z.object({
    theme: z.string().describe("Theme for the poem"),
  }),
});

server.addTool({
  annotations: {
    openWorldHint: false,
    readOnlyHint: false,
  },
  description: "Test progress reporting without buffering delays",
  execute: async (args, { reportProgress }) => {
    console.log("Testing progress reporting fix for HTTP Stream buffering...");

    await reportProgress({ progress: 0, total: 100 });
    await new Promise((resolve) => setTimeout(resolve, 500));

    await reportProgress({ progress: 25, total: 100 });
    await new Promise((resolve) => setTimeout(resolve, 500));

    await reportProgress({ progress: 75, total: 100 });
    await new Promise((resolve) => setTimeout(resolve, 500));

    // This progress should be received immediately
    await reportProgress({ progress: 100, total: 100 });

    return `Buffering test completed for ${args.testCase}`;
  },
  name: "test-buffering-fix",
  parameters: z.object({
    testCase: z.string().describe("Test case description"),
  }),
});

server.addPrompt({
  arguments: [
    {
      description: "Git diff or description of changes",
      name: "changes",
      required: true,
    },
  ],
  description: "Generate a Git commit message",
  load: async (args) => {
    return `Generate a concise but descriptive commit message for these changes:\n\n${args.changes}`;
  },
  name: "git-commit",
});

server.addResourceTemplate({
  arguments: [
    {
      description: "Documentation section to retrieve",
      name: "section",
      required: true,
    },
  ],
  description: "Get project documentation",
  load: async (args) => {
    const docs = {
      "api-reference":
        "# API Reference\n\n## Authentication\nAll API requests require a valid API key in the Authorization header.\n\n## Endpoints\n- GET /users - List all users\n- POST /users - Create new user",
      deployment:
        "# Deployment Guide\n\nTo deploy this application:\n\n1. Build the project: `npm run build`\n2. Set environment variables\n3. Deploy to your hosting platform",
      "getting-started":
        "# Getting Started\n\nWelcome to our project! Follow these steps to set up your development environment:\n\n1. Clone the repository\n2. Install dependencies with `npm install`\n3. Run `npm start` to begin",
    };

    return {
      text:
        docs[args.section as keyof typeof docs] ||
        "Documentation section not found",
    };
  },
  mimeType: "text/markdown",
  name: "Project Documentation",
  uriTemplate: "docs://project/{section}",
});

server.addTool({
  annotations: {
    openWorldHint: false,
    readOnlyHint: true,
    title: "Get Documentation (Embedded)",
  },
  description:
    "Retrieve project documentation using embedded resources - demonstrates the new embedded() feature",
  execute: async (args) => {
    return {
      content: [
        {
          resource: await server.embedded(`docs://project/${args.section}`),
          type: "resource",
        },
      ],
    };
  },
  name: "get-documentation",
  parameters: z.object({
    section: z
      .enum(["getting-started", "api-reference", "deployment"])
      .describe("Documentation section to retrieve"),
  }),
});

// Select transport type based on command line arguments
const transportType = process.argv.includes("--http-stream")
  ? "httpStream"
  : "stdio";

if (transportType === "httpStream") {
  // Start with HTTP streaming transport
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 8080;

  server.start({
    httpStream: {
      port: PORT,
    },
    transportType: "httpStream",
  });

  console.log(
    `HTTP Stream MCP server is running at http://localhost:${PORT}/stream`,
  );
  console.log("Use StreamableHTTPClientTransport to connect to this server");
  console.log("For example:");
  console.log(`
  import { Client } from "@modelcontextprotocol/sdk/client/index.js";
  import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
  
  const client = new Client(
    {
      name: "example-client",
      version: "1.0.0",
    },
    {
      capabilities: {},
    },
  );
  
  const transport = new StreamableHTTPClientTransport(
    new URL("http://localhost:${PORT}/stream"),
  );
  
  await client.connect(transport);
  `);
} else if (process.argv.includes("--explicit-ping-config")) {
  server.start({
    transportType: "stdio",
  });

  console.log(
    "Started stdio transport with explicit ping configuration from server options",
  );
} else if (process.argv.includes("--disable-roots")) {
  // Example of disabling roots at runtime
  const serverWithDisabledRoots = new FastMCP({
    name: "Addition (No Roots)",
    ping: {
      intervalMs: 10000,
      logLevel: "debug",
    },
    roots: {
      enabled: false,
    },
    version: "1.0.0",
  });

  serverWithDisabledRoots.start({
    transportType: "stdio",
  });

  console.log("Started stdio transport with roots support disabled");
} else {
  // Disable by default for:
  server.start({
    transportType: "stdio",
  });

  console.log("Started stdio transport with ping disabled by default");
}
