export type DevCommandOptions = {
  /**
   * Path to a temporary mcp-cli config file that registers the dev server.
   * Only used in non-interactive mode (when `tool` is set).
   */
  configPath?: string;
  /**
   * Path to the server file to run.
   */
  file: string;
  /**
   * Name of the tool to call non-interactively. When omitted, the dev
   * command launches the interactive mcp-cli inspector instead.
   */
  tool?: string;
  /**
   * JSON string of arguments forwarded to the tool via mcp-cli `--args`.
   * Only used in non-interactive mode.
   */
  toolArgs?: string;
  /**
   * Watch the file for changes and restart the server. Only used in
   * interactive mode; a non-interactive call runs the server once.
   */
  watch?: boolean;
};

/**
 * The server name registered in the generated mcp-cli config. mcp-cli
 * addresses non-interactive targets as `<server-name>:<tool>`.
 */
export const DEV_SERVER_NAME = "dev";

/**
 * Build the JSON config that registers the dev server with mcp-cli so it can
 * be invoked non-interactively. mcp-cli's non-interactive mode resolves the
 * server by name from a config file's `mcpServers` map, so an inline command
 * cannot be passed directly alongside `call-tool`.
 *
 * The server is never started in watch mode here: a non-interactive call
 * connects, calls one tool, and exits, so there is nothing to restart into.
 */
export const buildDevConfig = (file: string): string =>
  JSON.stringify(
    {
      mcpServers: {
        [DEV_SERVER_NAME]: {
          args: ["tsx", file],
          command: "npx",
        },
      },
    },
    null,
    2,
  );

/**
 * Build the argv that the dev command runs.
 *
 * This is an argv array rather than a shell string so that nothing has to be
 * quoted: file paths, tool names and JSON `--args` are passed to the child
 * process verbatim. Quoting through a shell would be wrong on Windows, where
 * cmd.exe treats single quotes as literal characters rather than as quoting.
 *
 * - Without `tool`: launches the interactive @wong2/mcp-cli inspector
 *   against an inline `npx tsx <file>` server (existing behaviour).
 * - With `tool`: runs @wong2/mcp-cli in non-interactive mode against a
 *   generated config file, calling the named tool and forwarding `--args`.
 */
export const buildDevCommand = (
  options: DevCommandOptions,
): [string, ...string[]] => {
  const { configPath, file, tool, toolArgs, watch = false } = options;

  if (tool) {
    if (!configPath) {
      throw new Error(
        "configPath is required when calling a tool non-interactively",
      );
    }

    return [
      "npx",
      "@wong2/mcp-cli",
      "-c",
      configPath,
      "call-tool",
      `${DEV_SERVER_NAME}:${tool}`,
      ...(toolArgs === undefined ? [] : ["--args", toolArgs]),
    ];
  }

  return [
    "npx",
    "@wong2/mcp-cli",
    "npx",
    "tsx",
    ...(watch ? ["--watch"] : []),
    file,
  ];
};
