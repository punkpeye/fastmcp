/**
 * This is a complete example of an MCP server.
 */
import { FastMCP } from "../FastMCP.js";
import { z } from "zod";
import { type } from "arktype";
import * as v from "valibot";

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
  name: "add-zod",
  description: "Add two numbers (using Zod schema)",
  parameters: AddParamsZod,
  execute: async (args) => {
    // args is typed as { a: number, b: number }
    console.log(`[Zod] Adding ${args.a} and ${args.b}`);
    return String(args.a + args.b);
  },
});

// --- ArkType Example ---
const AddParamsArkType = type({
  a: "number",
  b: "number",
});

server.addTool({
  name: "add-arktype",
  description: "Add two numbers (using ArkType schema)",
  parameters: AddParamsArkType,
  execute: async (args) => {
    // args is typed as { a: number, b: number } based on AddParamsArkType.infer
    console.log(`[ArkType] Adding ${args.a} and ${args.b}`);
    return String(args.a + args.b);
  },
});

// --- Valibot Example ---
const AddParamsValibot = v.object({
  a: v.number("The first number"),
  b: v.number("The second number"),
});

server.addTool({
  name: "add-valibot",
  description: "Add two numbers (using Valibot schema)",
  parameters: AddParamsValibot,
  execute: async (args) => {
    console.log(`[Valibot] Adding ${args.a} and ${args.b}`);
    return String(args.a + args.b);
  },
});

server.addResource({
  uri: "file:///logs/app.log",
  name: "Application Logs",
  mimeType: "text/plain",
  async load() {
    return {
      text: "Example log content",
    };
  },
});

server.addPrompt({
  name: "git-commit",
  description: "Generate a Git commit message",
  arguments: [
    {
      name: "changes",
      description: "Git diff or description of changes",
      required: true,
    },
  ],
  load: async (args) => {
    return `Generate a concise but descriptive commit message for these changes:\n\n${args.changes}`;
  },
});

server.start({
  transportType: "stdio",
});
