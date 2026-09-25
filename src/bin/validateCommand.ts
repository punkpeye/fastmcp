import { existsSync } from "node:fs";
import { rm, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

/**
 * Compiler options for type-checking a server file with no `tsconfig.json`
 * above it. tsc's own defaults (ES5, CommonJS-era module resolution) cannot
 * even read FastMCP's declarations, which use private class fields and a
 * default import of `http`, so no real server file could pass under them.
 * These describe how a server actually runs instead: as an ES module on a
 * current Node, which can import `.ts` files directly.
 */
export const DEFAULT_TYPE_CHECK_OPTIONS = [
  "--allowImportingTsExtensions",
  "--module",
  "esnext",
  "--moduleResolution",
  "bundler",
  "--skipLibCheck",
  "--target",
  "es2022",
];

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
 *
 * The script exits explicitly once the import settles. Importing a server file
 * normally starts the server, and a running server — a stdio transport waiting
 * on stdin, an HTTP listener — keeps the process alive indefinitely, so
 * validating a server that calls `start()` would otherwise never finish.
 */
export const STRUCTURE_CHECK_SCRIPT = `
(async () => {
  try {
    const { FastMCP } = await import("fastmcp");
    await import(process.argv[1]);
    console.log("[FastMCP] ✓ Server structure validation passed");
  } catch (error) {
    console.error("[FastMCP] ✗ Server structure validation failed:", error.message);
    process.exitCode = 1;
  }

  process.exit();
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
 *
 * Given a `project` (see `withTypeCheckProject`), tsc checks the file through
 * it; without one, the file is passed directly with
 * `DEFAULT_TYPE_CHECK_OPTIONS`.
 */
export const buildTypeCheckCommand = (
  file: string,
  { project, strict = false }: { project?: string; strict?: boolean } = {},
): [string, ...string[]] => [
  "npx",
  "tsc",
  "--noEmit",
  ...(strict ? ["--strict"] : []),
  ...(project ? ["--project", project] : [...DEFAULT_TYPE_CHECK_OPTIONS, file]),
];

/**
 * Build a tsconfig that checks only `file`, with the compiler options of the
 * project's own `tsconfig`.
 *
 * `tsc <file>` ignores tsconfig.json altogether and falls back to tsc's
 * defaults, while `tsc --project tsconfig.json` checks every file in the
 * project rather than the one being validated. Extending the project's config
 * and listing just `file` gets both right. A project that is `incremental` or
 * `composite` still writes a `.tsbuildinfo` under `--noEmit`, so both are
 * switched off: validating a file should leave the project untouched.
 */
export const buildTypeCheckProject = (tsconfig: string, file: string): string =>
  JSON.stringify({
    compilerOptions: { composite: false, incremental: false },
    extends: `./${basename(tsconfig)}`,
    files: [file],
    include: [],
  });

/**
 * Find the `tsconfig.json` that applies to files in `dir`: the nearest one in
 * it or any of its parents, which is where tsc and editors look too.
 */
export const findTsconfig = (dir: string): string | undefined => {
  const candidate = join(dir, "tsconfig.json");

  if (existsSync(candidate)) {
    return candidate;
  }

  const parent = dirname(dir);

  return parent === dir ? undefined : findTsconfig(parent);
};

/**
 * Run `check` with a throwaway tsconfig for `file` (see
 * `buildTypeCheckProject`), or with no project when the file has no
 * `tsconfig.json` above it.
 *
 * The throwaway config is written next to the one it extends and removed once
 * `check` settles. It cannot live in a temporary directory: tsc looks for the
 * `@types` packages it includes by default relative to the config file, so
 * from anywhere else a server using, say, `process.env` would stop compiling.
 */
export const withTypeCheckProject = async <T>(
  file: string,
  check: (project?: string) => Promise<T>,
): Promise<T> => {
  const tsconfig = findTsconfig(dirname(file));

  if (!tsconfig) {
    return check();
  }

  const project = join(
    dirname(tsconfig),
    `tsconfig.fastmcp-validate-${process.pid}.json`,
  );

  await writeFile(project, buildTypeCheckProject(tsconfig, file), "utf8");

  try {
    return await check(project);
  } finally {
    await rm(project, { force: true });
  }
};

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
 *
 * An error that did not come from a command at all — the throwaway tsconfig
 * could not be written, say — is reported by its message.
 */
export const formatCommandFailure = (error: unknown): string => {
  if (!(error instanceof Error)) {
    return "";
  }

  if (!hasOutputStreams(error)) {
    return error.message;
  }

  const collect = (value: unknown): string =>
    typeof value === "string" ? value.trim() : "";

  return [collect(error.stderr), collect(error.stdout)]
    .filter(Boolean)
    .join("\n");
};
