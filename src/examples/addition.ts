import { type } from "arktype";
import * as v from "valibot";
import { z } from "zod";

/**
 * This is a complete example of an MCP server.
 */
import { FastMCP } from "../FastMCP.js";

const server = new FastMCP({
  name: "Addition",
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

server.start({
  transportType: "stdio",
});
