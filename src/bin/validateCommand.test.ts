import { execa } from "execa";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, parse } from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

import {
  buildStructureCheckCommand,
  buildTypeCheckCommand,
  buildTypeCheckProject,
  DEFAULT_TYPE_CHECK_OPTIONS,
  findTsconfig,
  formatCommandFailure,
  STRUCTURE_CHECK_SCRIPT,
  withTypeCheckProject,
} from "./validateCommand.js";

const created: string[] = [];

afterAll(async () => {
  await Promise.all(
    created.map((dir) => rm(dir, { force: true, recursive: true })),
  );
});

const makeTemporaryDirectory = async (): Promise<string> => {
  const dir = await mkdtemp(join(tmpdir(), "fastmcp-validate-"));
  created.push(dir);
  return dir;
};

describe("buildTypeCheckCommand", () => {
  it("passes the file as an argument rather than through a shell", () => {
    expect(buildTypeCheckCommand("server.ts")).toEqual([
      "npx",
      "tsc",
      "--noEmit",
      ...DEFAULT_TYPE_CHECK_OPTIONS,
      "server.ts",
    ]);
  });

  it("places --strict before the file", () => {
    expect(buildTypeCheckCommand("server.ts", { strict: true })).toEqual([
      "npx",
      "tsc",
      "--noEmit",
      "--strict",
      ...DEFAULT_TYPE_CHECK_OPTIONS,
      "server.ts",
    ]);
  });

  it("checks through a project, if given one, instead of passing the file", () => {
    expect(
      buildTypeCheckCommand("server.ts", {
        project: "tsconfig.check.json",
        strict: true,
      }),
    ).toEqual([
      "npx",
      "tsc",
      "--noEmit",
      "--strict",
      "--project",
      "tsconfig.check.json",
    ]);
  });

  it("keeps a path containing spaces as a single argument", () => {
    const file = "C:\\my servers\\server.ts";

    expect(buildTypeCheckCommand(file).at(-1)).toBe(file);
  });
});

describe("buildTypeCheckProject", () => {
  it("extends the project's config, checks only the file, and writes no build info", () => {
    expect(
      JSON.parse(
        buildTypeCheckProject("/app/tsconfig.json", "/app/src/server.ts"),
      ),
    ).toEqual({
      compilerOptions: { composite: false, incremental: false },
      extends: "./tsconfig.json",
      files: ["/app/src/server.ts"],
      include: [],
    });
  });
});

describe("findTsconfig", () => {
  it("finds the nearest tsconfig.json in a directory or its parents", async () => {
    const root = await makeTemporaryDirectory();
    const api = join(root, "packages", "api");
    await mkdir(join(api, "src"), { recursive: true });
    await writeFile(join(root, "tsconfig.json"), "{}", "utf8");
    await writeFile(join(api, "tsconfig.json"), "{}", "utf8");

    expect(findTsconfig(join(api, "src"))).toBe(join(api, "tsconfig.json"));
    expect(findTsconfig(join(root, "packages"))).toBe(
      join(root, "tsconfig.json"),
    );
  });

  it("stops at the filesystem root", () => {
    expect(findTsconfig(parse(process.cwd()).root)).toBeUndefined();
  });
});

describe("withTypeCheckProject", () => {
  /**
   * Valid TypeScript that tsc's own default target (ES5) rejects: private
   * class fields need ES2015 or later. It only type-checks if the options of
   * the project's tsconfig.json, or the defaults used without one, apply.
   */
  const MODERN_SOURCE = `class Counter {
  #count = 0;

  next() {
    return ++this.#count;
  }
}

export const counter = new Counter();
`;

  const typeCheck = (file: string) =>
    withTypeCheckProject(file, (project) => {
      const [command, ...args] = buildTypeCheckCommand(file, { project });

      return execa(command, args);
    });

  /**
   * A project whose tsconfig.json targets a modern runtime and is
   * `incremental`, so a check that went through tsc's defaults, or wrote a
   * `.tsbuildinfo` next to the project's config, would show.
   */
  const makeTypeScriptProject = async (source: string) => {
    const project = await makeTemporaryDirectory();
    await mkdir(join(project, "src"));
    await writeFile(
      join(project, "tsconfig.json"),
      JSON.stringify({
        compilerOptions: { incremental: true, target: "es2022" },
      }),
      "utf8",
    );
    const file = join(project, "src", "server.ts");
    await writeFile(file, source, "utf8");

    return { file, project };
  };

  it(
    "type-checks the file with the options of its project's tsconfig.json and leaves the project as it was",
    { timeout: 60_000 },
    async () => {
      const { file, project } = await makeTypeScriptProject(MODERN_SOURCE);

      await expect(typeCheck(file)).resolves.toMatchObject({ exitCode: 0 });
      expect((await readdir(project)).sort()).toEqual(["src", "tsconfig.json"]);
    },
  );

  it(
    "reports a type error in the file, and still removes its tsconfig",
    { timeout: 60_000 },
    async () => {
      const { file, project } = await makeTypeScriptProject(
        'export const port: number = "8080";\n',
      );

      const error = await typeCheck(file).then(
        () => undefined,
        (reason: unknown) => reason,
      );

      expect(formatCommandFailure(error)).toContain("error TS2322");
      expect((await readdir(project)).sort()).toEqual(["src", "tsconfig.json"]);
    },
  );

  it(
    "uses modern defaults for a file with no tsconfig.json above it",
    { timeout: 60_000 },
    async () => {
      const dir = await makeTemporaryDirectory();
      const file = join(dir, "server.ts");
      await writeFile(file, MODERN_SOURCE, "utf8");

      expect(findTsconfig(dir)).toBeUndefined();
      await expect(typeCheck(file)).resolves.toMatchObject({ exitCode: 0 });
    },
  );
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
    const dir = await makeTemporaryDirectory();
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

  it("reports the message of an error that did not come from a command", () => {
    expect(
      formatCommandFailure(new Error("EACCES: permission denied, open")),
    ).toBe("EACCES: permission denied, open");
  });

  it("returns an empty string when there is no compiler output", () => {
    expect(formatCommandFailure("boom")).toBe("");
  });
});
