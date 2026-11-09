import { execa } from "execa";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  buildDevCommand,
  buildDevConfig,
  DEV_SERVER_NAME,
} from "./devCommand.js";

describe("buildDevCommand", () => {
  it("launches the interactive inspector when no tool is given", () => {
    expect(buildDevCommand({ file: "server.ts" })).toEqual([
      "npx",
      "@wong2/mcp-cli",
      "--",
      "npx",
      "tsx",
      "server.ts",
    ]);
  });

  it("adds --watch to the interactive command", () => {
    expect(buildDevCommand({ file: "server.ts", watch: true })).toEqual([
      "npx",
      "@wong2/mcp-cli",
      "--",
      "npx",
      "tsx",
      "--watch",
      "server.ts",
    ]);
  });

  it("builds a non-interactive call-tool command", () => {
    expect(
      buildDevCommand({
        configPath: "/tmp/cfg.json",
        file: "server.ts",
        tool: "add",
      }),
    ).toEqual([
      "npx",
      "@wong2/mcp-cli",
      "-c",
      "/tmp/cfg.json",
      "call-tool",
      `${DEV_SERVER_NAME}:add`,
    ]);
  });

  it("forwards tool args via --args", () => {
    expect(
      buildDevCommand({
        configPath: "/tmp/cfg.json",
        file: "server.ts",
        tool: "add",
        toolArgs: '{"a":1,"b":2}',
      }),
    ).toEqual([
      "npx",
      "@wong2/mcp-cli",
      "-c",
      "/tmp/cfg.json",
      "call-tool",
      `${DEV_SERVER_NAME}:add`,
      "--args",
      '{"a":1,"b":2}',
    ]);
  });

  it("passes tool args through verbatim, without shell quoting", () => {
    const command = buildDevCommand({
      configPath: "/tmp/cfg.json",
      file: "server.ts",
      tool: "echo",
      toolArgs: `{"text":"it's"}`,
    });

    expect(command.at(-1)).toBe(`{"text":"it's"}`);
  });

  it("keeps paths containing spaces intact", () => {
    const command = buildDevCommand({
      configPath: "/tmp/my configs/cfg.json",
      file: "server.ts",
      tool: "add",
    });

    expect(command).toContain("/tmp/my configs/cfg.json");
  });

  it("requires a config path in non-interactive mode", () => {
    expect(() => buildDevCommand({ file: "server.ts", tool: "add" })).toThrow(
      /configPath is required/,
    );
  });

  it("forwards watch and the filename through mcp-cli's argument parser", async () => {
    const dir = await mkdtemp(join(tmpdir(), "fastmcp-dev-"));
    const output = join(dir, "argv.json");
    const recorder = join(dir, "record.cjs");

    try {
      await writeFile(
        recorder,
        `require("node:fs").writeFileSync(${JSON.stringify(output)}, JSON.stringify(process.argv.slice(2)));`,
      );
      const args = buildDevCommand({
        file: "server with spaces.ts",
        watch: true,
      }).slice(2);
      // Run the installed parser, replacing npx/tsx with an argv recorder.
      args.splice(args.indexOf("npx"), 2, process.execPath, recorder);
      await execa(
        process.execPath,
        [
          createRequire(import.meta.url).resolve("@wong2/mcp-cli/src/cli.js"),
          ...args,
        ],
        {
          env: { APPDATA: dir, XDG_CONFIG_HOME: dir },
          reject: false,
          timeout: 10_000,
        },
      );

      expect(JSON.parse(await readFile(output, "utf8"))).toEqual([
        "--watch",
        "server with spaces.ts",
      ]);
    } finally {
      await rm(dir, { force: true, recursive: true });
    }
  });
});

describe("buildDevConfig", () => {
  it("registers the dev server with an inline tsx command", () => {
    const config = JSON.parse(buildDevConfig("server.ts"));

    expect(config.mcpServers[DEV_SERVER_NAME]).toEqual({
      args: ["tsx", "server.ts"],
      command: "npx",
    });
  });

  it("never watches, because a non-interactive call runs the server once", () => {
    const config = JSON.parse(buildDevConfig("server.ts"));

    expect(config.mcpServers[DEV_SERVER_NAME].args).not.toContain("--watch");
  });
});
