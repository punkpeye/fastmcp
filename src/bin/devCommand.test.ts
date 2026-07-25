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
      "npx",
      "tsx",
      "server.ts",
    ]);
  });

  it("adds --watch to the interactive command", () => {
    expect(buildDevCommand({ file: "server.ts", watch: true })).toEqual([
      "npx",
      "@wong2/mcp-cli",
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
