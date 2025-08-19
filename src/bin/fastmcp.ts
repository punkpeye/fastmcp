#!/usr/bin/env node

import { execa } from "execa";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

(async () => {
  await yargs(hideBin(process.argv))
    .scriptName("fastmcp")
    .command(
      "dev <file>",
      "Start a development server",
      (yargs) => {
        return yargs
          .positional("file", {
            demandOption: true,
            describe: "The path to the server file",
            type: "string",
          })

          .option("watch", {
            alias: "w",
            default: false,
            describe: "Watch for file changes and restart server",
            type: "boolean",
          })

          .option("verbose", {
            alias: "v",
            default: false,
            describe: "Enable verbose logging",
            type: "boolean",
          })

          .option("direct", {
            alias: "d",
            default: false,
            describe:
              "Run server directly without mcp-cli wrapper (recommended for troubleshooting)",
            type: "boolean",
          });
      },

      async (argv) => {
        try {
          const env = {
            ...process.env,
            XDG_CONFIG_HOME:
              process.env.XDG_CONFIG_HOME ||
              `${process.env.HOME || process.cwd()}/.config`,
          };

          let command: string;

          if (argv.direct) {
            // direct execution without mcp-cli wrapper
            // more reliable but less interactive
            command = argv.watch
              ? `npx jiti --watch ${argv.file}`
              : `npx jiti ${argv.file}`;
          } else {
            // standard mcp-cli wrapper for interactive dev
            command = argv.watch
              ? `npx @wong2/mcp-cli npx jiti --watch ${argv.file}`
              : `npx @wong2/mcp-cli npx jiti ${argv.file}`;
          }

          if (argv.verbose) {
            console.log(`[FastMCP] Starting server: ${command}`);
            console.log(`[FastMCP] File: ${argv.file}`);
            console.log(
              `[FastMCP] Watch mode: ${argv.watch ? "enabled" : "disabled"}`,
            );
            console.log(
              `[FastMCP] Direct mode: ${argv.direct ? "enabled" : "disabled"}`,
            );
            console.log(
              `[FastMCP] Environment: NODE_ENV=${process.env.NODE_ENV || "development"}`,
            );
          }

          await execa({
            env,
            shell: true,
            stderr: "inherit",
            stdin: "inherit",
            stdout: "inherit",
          })`${command}`;
        } catch (error) {
          console.error(
            "[FastMCP Error] Failed to start development server:",
            error instanceof Error ? error.message : String(error),
          );

          if (argv.verbose && error instanceof Error && error.stack)
            console.error("[FastMCP Debug] Stack trace:", error.stack);

          // Provide helpful troubleshooting information
          console.error("\n[FastMCP] Troubleshooting tips:");
          console.error(
            "1. Ensure your FastMCP server file is properly structured",
          );
          console.error(
            "2. Try running with --direct flag: fastmcp dev --direct",
            argv.file,
          );
          console.error(
            "3. Try running the file directly: npx jiti",
            argv.file,
          );
          console.error(
            "4. Check if @wong2/mcp-cli is compatible with your Node.js version",
          );
          console.error("5. Use --verbose flag for more debugging information");

          if (!argv.direct) {
            console.error(
              "\n[FastMCP] Note: Consider using --direct flag to bypass mcp-cli wrapper",
            );
          }

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
          const env = {
            ...process.env,
            XDG_CONFIG_HOME:
              process.env.XDG_CONFIG_HOME ||
              `${process.env.HOME || process.cwd()}/.config`,
          };

          await execa({
            env,
            stderr: "inherit",
            stdout: "inherit",
          })`npx @modelcontextprotocol/inspector npx jiti ${argv.file}`;
        } catch (error) {
          console.error(
            "[FastMCP Error] Failed to inspect server:",
            error instanceof Error ? error.message : String(error),
          );

          console.error("\n[FastMCP] Troubleshooting for inspect:");
          console.error(
            "1. Make sure @modelcontextprotocol/inspector is available",
          );
          console.error(
            "2. Ensure your server file starts properly with: npx jiti",
            argv.file,
          );
          console.error(
            "3. Check that your server exports a valid FastMCP instance",
          );

          process.exit(1);
        }
      },
    )

    .command(
      "diagnose <file>",
      "Diagnose potential issues with FastMCP server and environment",
      (yargs) => {
        return yargs.positional("file", {
          demandOption: true,
          describe: "The path to the server file",
          type: "string",
        });
      },

      async (argv) => {
        console.log("[FastMCP] Running diagnostic checks...\n");

        try {
          const { existsSync } = await import("fs");
          const { resolve } = await import("path");
          const filePath = resolve(argv.file);

          console.log("✓ 1/6 Checking file existence...");

          if (!existsSync(filePath)) {
            console.error(`✗ File not found: ${filePath}`);
            process.exit(1);
          }

          console.log("✓ 2/6 Checking TypeScript compilation...");

          try {
            await execa({
              shell: true,
              stderr: "pipe",
              stdout: "pipe",
            })`npx tsc --noEmit ${filePath}`;
          } catch (tsError) {
            console.error("✗ TypeScript compilation failed");

            if (tsError instanceof Error && "stderr" in tsError)
              console.error(tsError.stderr);

            process.exit(1);
          }

          console.log("✓ 3/6 Checking environment variables...");
          console.log(
            `  XDG_CONFIG_HOME: ${process.env.XDG_CONFIG_HOME || "NOT SET (will be auto-configured)"}`,
          );
          console.log(
            `  NODE_ENV: ${process.env.NODE_ENV || "development (default)"}`,
          );
          console.log(`  HOME: ${process.env.HOME || "NOT SET"}`);
          console.log("✓ 4/6 Checking required dependencies...");

          try {
            await execa({ stderr: "pipe", stdout: "pipe" })`npx tsx --version`;

            console.log("  tsx: Available");
          } catch {
            console.error("✗ tsx not available - this may cause issues");
          }

          try {
            await execa({
              stderr: "pipe",
              stdout: "pipe",
            })`npx @wong2/mcp-cli --version`;

            console.log("  @wong2/mcp-cli: Available");
          } catch {
            console.log(
              "  @wong2/mcp-cli: Not available (--direct mode will be used)",
            );
          }

          console.log("✓ 5/6 Testing direct server execution...");

          try {
            await Promise.race([
              execa({
                shell: true,
                stderr: "pipe",
                stdout: "pipe",
                timeout: 5000,
              })`echo 'test' | npx tsx ${filePath}`,
              new Promise((_, reject) =>
                setTimeout(
                  () => reject(new Error("Server start timeout")),
                  5000,
                ),
              ),
            ]);
            console.log("  Direct execution: Successful");
          } catch (directError) {
            if (
              directError instanceof Error &&
              directError.message.includes("timeout")
            ) {
              console.log(
                "  Direct execution: Server started (timed out as expected)",
              );
            } else {
              console.log("  Direct execution: Issues detected");
              console.log(
                `  Error: ${directError instanceof Error ? directError.message : String(directError)}`,
              );
            }
          }

          console.log("✓ 6/6 All diagnostic checks completed");
          console.log("\n[FastMCP] Recommendations:");
          console.log(
            "• Use 'fastmcp dev --direct' for the most reliable experience",
          );
          console.log("• Use 'fastmcp dev --verbose' for detailed debugging");
          console.log(
            "• If issues persist, try running directly: npx tsx " + argv.file,
          );
        } catch (error) {
          console.error(
            "[FastMCP Error] Diagnostic failed:",
            error instanceof Error ? error.message : String(error),
          );

          process.exit(1);
        }
      },
    )

    .command(
      "diagnose",
      "Diagnose FastMCP CLI and environment issues",
      (yargs) => {
        return yargs.option("verbose", {
          alias: "v",
          default: false,
          describe: "Show detailed diagnostic information",
          type: "boolean",
        });
      },

      async () => {
        console.log("[FastMCP] Running diagnostic checks...\n");

        try {
          console.log(`✓ Node.js version: ${process.version}`);
          console.log(
            `✓ XDG_CONFIG_HOME: ${process.env.XDG_CONFIG_HOME || "NOT SET (will be auto-set)"}`,
          );
          console.log(`✓ HOME: ${process.env.HOME || "NOT SET"}`);
          console.log(
            `✓ NODE_ENV: ${process.env.NODE_ENV || "development (default)"}`,
          );

          try {
            await execa`npx tsx --version`;

            console.log("✓ tsx is available");
          } catch {
            console.log("✗ tsx is not available or has issues");
          }

          try {
            await execa`npx @wong2/mcp-cli --version`;

            console.log("✓ @wong2/mcp-cli is available");
          } catch {
            console.log("✗ @wong2/mcp-cli is not available or has issues");
          }

          try {
            await execa`npx @modelcontextprotocol/inspector --version`;

            console.log("✓ @modelcontextprotocol/inspector is available");
          } catch {
            console.log("✗ @modelcontextprotocol/inspector is not available");
          }

          console.log("\n[FastMCP] Diagnostic complete!");
          console.log("If you're experiencing issues:");
          console.log(
            "1. Use 'fastmcp dev --direct <file>' to bypass mcp-cli wrapper",
          );
          console.log(
            "2. Use 'fastmcp dev --verbose <file>' for detailed logging",
          );
          console.log(
            "3. Try running your server directly with 'npx tsx <file>'",
          );
        } catch (error) {
          console.error(
            "[FastMCP Error] Diagnostic failed:",
            error instanceof Error ? error.message : String(error),
          );

          process.exit(1);
        }
      },
    )

    .command(
      "validate <file>",
      "Validate a FastMCP server file for syntax and basic structure",
      (yargs) => {
        return yargs
          .positional("file", {
            demandOption: true,
            describe: "The path to the server file",
            type: "string",
          })

          .option("strict", {
            alias: "s",
            default: false,
            describe: "Enable strict validation (type checking)",
            type: "boolean",
          });
      },

      async (argv) => {
        try {
          const { existsSync } = await import("fs");
          const { resolve } = await import("path");
          const filePath = resolve(argv.file);

          if (!existsSync(filePath)) {
            console.error(`[FastMCP Error] File not found: ${filePath}`);
            process.exit(1);
          }

          console.log(`[FastMCP] Validating server file: ${filePath}`);

          const command = argv.strict
            ? `npx tsc --noEmit --strict ${filePath}`
            : `npx tsc --noEmit ${filePath}`;

          try {
            await execa({
              shell: true,
              stderr: "pipe",
              stdout: "pipe",
            })`${command}`;

            console.log("[FastMCP] ✓ TypeScript compilation successful");
          } catch (tsError) {
            console.error("[FastMCP] ✗ TypeScript compilation failed");

            if (tsError instanceof Error && "stderr" in tsError)
              console.error(tsError.stderr);

            process.exit(1);
          }

          try {
            await execa({
              shell: true,
              stderr: "pipe",
              stdout: "pipe",
            })`node -e "
            (async () => {
              try {
                const { FastMCP } = await import('fastmcp');
                await import('file://${filePath}');
                console.log('[FastMCP] ✓ Server structure validation passed');
              } catch (error) {
                console.error('[FastMCP] ✗ Server structure validation failed:', error.message);
                process.exit(1);
              }
            })();
          "`;
          } catch {
            console.error("[FastMCP] ✗ Server structure validation failed");
            console.error(
              "Make sure the file properly imports and uses FastMCP",
            );

            process.exit(1);
          }

          console.log(
            "[FastMCP] ✓ All validations passed! Server file looks good.",
          );
        } catch (error) {
          console.error(
            "[FastMCP Error] Validation failed:",
            error instanceof Error ? error.message : String(error),
          );

          process.exit(1);
        }
      },
    )

    .help()
    .parseAsync();
})();
