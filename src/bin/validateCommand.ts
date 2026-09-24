import { pathToFileURL } from "node:url";

/**
 * The script that `fastmcp validate` runs to check a server file can be
 * imported.
 *
 * The target file is read from `process.argv[1]` instead of being spliced into
 * this source. Splicing is not equivalent: the path would land inside a
 * JavaScript string literal, so the child's own parser would consume the
 * backslashes of a Windows path as string escapes. `C:\Users\dev\server.ts`
 * reaches the import as `C:Usersdevserver.ts`, which throws `ERR_INVALID_URL`
 * and is reported to the user as "does not import FastMCP" even though the file
 * is fine.
 */
export const STRUCTURE_CHECK_SCRIPT = `
(async () => {
  try {
    const { FastMCP } = await import("fastmcp");
    await import(process.argv[1]);
    console.log("[FastMCP] ✓ Server structure validation passed");
  } catch (error) {
    console.error("[FastMCP] ✗ Server structure validation failed:", error.message);
    process.exit(1);
  }
})();
`;

/**
 * Build the argv for the type-check step.
 *
 * This is an argv array rather than a shell string so that nothing has to be
 * quoted: the file path is passed to tsc verbatim, so a path containing spaces
 * stays one argument. Quoting through a shell would be wrong on Windows, where
 * cmd.exe re-parses the command line and splits such a path into several root
 * files.
 */
export const buildTypeCheckCommand = (
  file: string,
  strict = false,
): [string, ...string[]] => [
  "npx",
  "tsc",
  "--noEmit",
  ...(strict ? ["--strict"] : []),
  file,
];

/**
 * Build the argv for the structure-check step.
 *
 * As above, the file is passed as an argument rather than quoted into a shell
 * command. It is converted to a file URL by the parent process, so the child
 * receives the URL as-is and never has to reconstruct it. The child is the same
 * Node binary running the CLI, so no PATH lookup is involved.
 */
export const buildStructureCheckCommand = (
  file: string,
  execPath: string = process.execPath,
): [string, ...string[]] => [
  execPath,
  "-e",
  STRUCTURE_CHECK_SCRIPT,
  pathToFileURL(file).href,
];

/**
 * The output streams a failed command carries. execa sets both on the error it
 * throws, but they are optional here so the extraction stays honest about not
 * every `Error` having them.
 */
type CommandOutputStreams = {
  stderr?: unknown;
  stdout?: unknown;
};

const hasOutputStreams = (
  error: Error,
): error is CommandOutputStreams & Error =>
  "stdout" in error || "stderr" in error;

/**
 * Extract the output of a failed command.
 *
 * tsc writes its diagnostics to stdout, while a failure to launch the compiler
 * at all (a missing `npx`, for instance) reports on stderr — reading only
 * stderr left the message empty for every real type error. The structure check
 * reports the reason on stderr, which execa captures, so it has to be replayed
 * here as well or the caller can only print a generic hint.
 */
export const formatCommandFailure = (error: unknown): string => {
  if (!(error instanceof Error) || !hasOutputStreams(error)) {
    return "";
  }

  const collect = (value: unknown): string =>
    typeof value === "string" ? value.trim() : "";

  return [collect(error.stderr), collect(error.stdout)]
    .filter(Boolean)
    .join("\n");
};
