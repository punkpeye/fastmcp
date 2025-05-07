#!/usr/bin/env node

import { execa } from "execa";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

await yargs(hideBin(process.argv))
  .scriptName("fastmcp")
  .command(
    "dev <file>",
    "Start a development server",
    (yargs) => {
      return yargs.positional("file", {
        demandOption: true,
        describe: "The path to the server file",
        type: "string",
      });
    },
    async (argv) => {
      try {
        await execa({
          stderr: "inherit",
          stdin: "inherit",
          stdout: "inherit",
        })`npx @wong2/mcp-cli npx tsx ${argv.file}`;
      } catch (error) {
        console.error(
          "[FastMCP Error] Failed to start development server:",
          error instanceof Error ? error.message : String(error),
        );
        process.exit(1);
      }
    },
  )
  .command(
    "inspect <file>",
    "Inspect a server file",
    (yargs) => {
      return yargs.positional("file", {
        demandOption: true,
        describe: "The path to the server file",
        type: "string",
      });
    },
    async (argv) => {
      try {
        await execa({
          stderr: "inherit",
          stdout: "inherit",
        })`npx @modelcontextprotocol/inspector npx tsx ${argv.file}`;
      } catch (error) {
        console.error(
          "[FastMCP Error] Failed to inspect server:",
          error instanceof Error ? error.message : String(error),
        );
        process.exit(1);
      }
    },
  )
  .help()
  .parseAsync();
