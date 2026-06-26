import { describe, expect, it } from "vitest";

import {
  buildDevCommand,
  buildDevConfig,
  DEV_SERVER_NAME,
} from "./devCommand.js";

describe("buildDevCommand", () => {
  it("launches the interactive inspector when no tool is given", () => {
    expect(buildDevCommand({ file: "server.ts" })).toBe(
      "npx @wong2/mcp-cli npx tsx server.ts",
    );
  });

  it("adds --watch to the interactive command", () => {
    expect(buildDevCommand({ file: "server.ts", watch: true })).toBe(
      "npx @wong2/mcp-cli npx tsx --watch server.ts",
    );
  });

  it("builds a non-interactive call-tool command", () => {
    expect(
      buildDevCommand({
        configPath: "/tmp/cfg.json",
        file: "server.ts",
        tool: "add",
      }),
    ).toBe(
      `npx @wong2/mcp-cli -c '/tmp/cfg.json' call-tool '${DEV_SERVER_NAME}:add'`,
    );
  });

  it("forwards tool args via --args", () => {
    expect(
      buildDevCommand({
        configPath: "/tmp/cfg.json",
        file: "server.ts",
        tool: "add",
        toolArgs: '{"a":1,"b":2}',
      }),
    ).toBe(
      `npx @wong2/mcp-cli -c '/tmp/cfg.json' call-tool '${DEV_SERVER_NAME}:add' --args '{"a":1,"b":2}'`,
    );
  });

  it("escapes single quotes in tool args", () => {
    const command = buildDevCommand({
      configPath: "/tmp/cfg.json",
      file: "server.ts",
      tool: "echo",
      toolArgs: `{"text":"it's"}`,
    });

    expect(command).toContain(`--args '{"text":"it'\\''s"}'`);
  });

  it("requires a config path in non-interactive mode", () => {
    expect(() => buildDevCommand({ file: "server.ts", tool: "add" })).toThrow(
      /configPath is required/,
    );
  });
});

describe("buildDevConfig", () => {
  it("registers the dev server with an inline tsx command", () => {
    const config = JSON.parse(buildDevConfig("server.ts", false));

    expect(config.mcpServers[DEV_SERVER_NAME]).toEqual({
      args: ["tsx", "server.ts"],
      command: "npx",
    });
  });

  it("includes --watch in the config when watch is enabled", () => {
    const config = JSON.parse(buildDevConfig("server.ts", true));

    expect(config.mcpServers[DEV_SERVER_NAME].args).toEqual([
      "tsx",
      "--watch",
      "server.ts",
    ]);
  });
});
