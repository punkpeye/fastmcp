import { execa } from "execa";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

import {
  buildStructureCheckCommand,
  buildTypeCheckCommand,
  formatCommandFailure,
  STRUCTURE_CHECK_SCRIPT,
} from "./validateCommand.js";

describe("buildTypeCheckCommand", () => {
  it("passes the file as an argument rather than through a shell", () => {
    expect(buildTypeCheckCommand("server.ts")).toEqual([
      "npx",
      "tsc",
      "--noEmit",
      "server.ts",
    ]);
  });

  it("places --strict before the file", () => {
    expect(buildTypeCheckCommand("server.ts", true)).toEqual([
      "npx",
      "tsc",
      "--noEmit",
      "--strict",
      "server.ts",
    ]);
  });

  it("keeps a path containing spaces as a single argument", () => {
    const file = "C:\\my servers\\server.ts";

    expect(buildTypeCheckCommand(file).at(-1)).toBe(file);
  });
});

describe("buildStructureCheckCommand", () => {
  it("keeps the target out of the script source", () => {
    const args = buildStructureCheckCommand("C:\\Users\\dev\\server.ts");

    expect(args[2]).toBe(STRUCTURE_CHECK_SCRIPT);

    // A Windows path spliced into this source lands inside a JavaScript string
    // literal, so the child's parser eats the backslashes and the import fails
    // with ERR_INVALID_URL. Keeping the script free of the target is the fix.
    expect(STRUCTURE_CHECK_SCRIPT).not.toContain("file://");
    expect(STRUCTURE_CHECK_SCRIPT).not.toContain("server.ts");
  });

  it("passes the target as a file: URL", () => {
    const file = "/tmp/my servers/server.ts";
    const url = buildStructureCheckCommand(file).at(-1);

    expect(url).toBe(pathToFileURL(file).href);
    expect(url).toMatch(/^file:\/\//);
    expect(url).toContain("%20");
  });
});

describe("the structure check script", () => {
  const created: string[] = [];

  afterAll(async () => {
    await Promise.all(
      created.map((dir) => rm(dir, { force: true, recursive: true })),
    );
  });

  /**
   * A throwaway project directory holding just enough of a `fastmcp` package for
   * the script's own `import("fastmcp")` to resolve.
   *
   * The script is run with this directory as its working directory, because a
   * bare specifier in a `node -e` script resolves from there. Standing in a
   * minimal package matters: this repo's `Test` job runs before its `Build` step,
   * so the real entry point (`dist/FastMCP.js`) does not exist yet, and resolving
   * the real package would make these tests depend on the build order.
   */
  const makeProject = async (): Promise<string> => {
    const dir = await mkdtemp(join(tmpdir(), "fastmcp-validate-"));
    created.push(dir);
    const pkg = join(dir, "node_modules", "fastmcp");
    await mkdir(pkg, { recursive: true });
    await writeFile(
      join(pkg, "package.json"),
      JSON.stringify({
        exports: "./index.js",
        name: "fastmcp",
        type: "module",
        version: "0.0.0",
      }),
      "utf8",
    );
    await writeFile(
      join(pkg, "index.js"),
      "export const FastMCP = class {};\n",
      "utf8",
    );
    return dir;
  };

  it("imports a server file whose path needs escaping", async () => {
    const project = await makeProject();
    const dir = join(project, "with spaces");
    await mkdir(dir);
    const file = join(dir, "server.mjs");
    await writeFile(file, "export default {};\n", "utf8");

    const [command, ...args] = buildStructureCheckCommand(file);
    const result = await execa(command, args, { cwd: project, reject: false });

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Server structure validation passed");
  });

  it("reports the reason on stderr when the server file cannot be imported", async () => {
    const project = await makeProject();
    const file = join(project, "broken.mjs");
    await writeFile(file, "throw new Error('boom');\n", "utf8");

    const [command, ...args] = buildStructureCheckCommand(file);
    const result = await execa(command, args, { cwd: project, reject: false });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("boom");
  });
});

describe("formatCommandFailure", () => {
  it("reports diagnostics that tsc wrote to stdout", () => {
    const error = Object.assign(new Error("Command failed"), {
      stderr: "",
      stdout: "server.ts(1,1): error TS2304: Cannot find name 'x'.",
    });

    expect(formatCommandFailure(error)).toContain("error TS2304");
  });

  it("falls back to stderr when the compiler never ran", () => {
    const error = Object.assign(new Error("Command failed"), {
      stderr: "npx: command not found",
      stdout: "",
    });

    expect(formatCommandFailure(error)).toBe("npx: command not found");
  });

  it("returns an empty string when there is no compiler output", () => {
    expect(formatCommandFailure("boom")).toBe("");
  });
});
