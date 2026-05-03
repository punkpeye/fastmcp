import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// ---------------------------------------------------------------------------
// Integration test: verifies the actual zombie-process fix works end-to-end.
// Spawns a real FastMCP stdio server as a child process, then destroys stdin
// to simulate client disconnect. The child must exit cleanly.
// ---------------------------------------------------------------------------

const FIXTURE_SCRIPT = `
import { FastMCP } from "./FastMCP.js";

const server = new FastMCP({ name: "ExitTest", version: "1.0.0" });
server.addTool({
  name: "noop",
  description: "no-op",
  execute: async () => "ok",
});

// Signal readiness
process.stdout.write("READY\\n");
server.start({ transportType: "stdio" }).catch(() => process.exit(1));
`;

describe("stdio zombie-process prevention (integration)", () => {
  it("child exits cleanly when stdin is destroyed", async () => {
    // Use tsx/jiti to run inline TypeScript. Falls back to node with --loader.
    const child = spawn("tsx", ["--eval", FIXTURE_SCRIPT], {
      cwd: resolve(__dirname, ".."),
      env: { ...process.env, NODE_OPTIONS: "" },
      stdio: ["pipe", "pipe", "pipe"],
    });

    // Wait for the server to signal readiness (or timeout)
    const ready = await new Promise<boolean>((resolve) => {
      const timeout = setTimeout(() => resolve(false), 15_000);
      child.stdout?.on("data", (chunk: Buffer) => {
        if (chunk.toString().includes("READY")) {
          clearTimeout(timeout);
          resolve(true);
        }
      });
      child.on("error", () => {
        clearTimeout(timeout);
        resolve(false);
      });
    });

    expect(ready).toBe(true);

    // Simulate client disconnect by destroying stdin
    child.stdin?.destroy();

    // Child must exit within 5 seconds (previously it would zombie forever)
    const exitCode = await new Promise<null | number>((resolve) => {
      const timeout = setTimeout(() => {
        child.kill("SIGKILL");
        resolve(null);
      }, 5_000);
      child.on("exit", (code) => {
        clearTimeout(timeout);
        resolve(code);
      });
    });

    // null means we had to kill it — that's the bug this PR fixes
    expect(exitCode).not.toBeNull();
    // Process should exit cleanly (0) or with a graceful signal exit
    expect(exitCode === 0 || exitCode === 143).toBe(true);
  }, 30_000); // tsx is a devDep so no download — 30s covers slow CI runners
});
