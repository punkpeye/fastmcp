// Fetches the large benchmark specs listed in
// benchmark-specs/sources.json into benchmark-specs/, verifying each against
// its pinned sha256.
//
// They are not vendored: the five of them are ~20MB, which is permanent
// growth on every clone of this repo for files nobody reads in review. The
// hash pin is what keeps a benchmark run reproducible without committing
// them — a spec that drifts upstream fails loudly rather than silently
// changing what the suite tests.
//
// Shared by fromOpenAPI.benchmark.test.ts (fetch if missing) and
// scripts/refresh-openapi-benchmark-specs.mjs (re-fetch and re-pin).

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const SPECS_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "benchmark-specs",
);

const MANIFEST_PATH = path.join(SPECS_DIR, "sources.json");

export async function readManifest() {
  return JSON.parse(await readFile(MANIFEST_PATH, "utf8")).specs;
}

export function sha256(text) {
  return createHash("sha256").update(text).digest("hex");
}

/**
 * Slack's own example OAuth responses embed realistic-looking (but fake)
 * bot/user tokens, which trip GitHub's push-protection secret scanner.
 * Redacted generically — by shape, not by literal value, so this file's
 * own source never contains a token-shaped string. Applied before hashing,
 * so the pinned digest is of the redacted text.
 */
export function normalizeSpec(file, text) {
  if (file !== "slack.json") {
    return text;
  }

  return text.replace(
    /xox[abpr]-\d{5,}-\d{5,}-[A-Za-z0-9]{10,}/g,
    "xoxb-EXAMPLE-REDACTED-TOKEN",
  );
}

export async function download(file, url) {
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`${url} responded with ${response.status}`);
  }

  return normalizeSpec(file, await response.text());
}

/**
 * Ensures every manifest spec is present on disk and matches its pin.
 * A cached file that fails the hash check is re-downloaded once before
 * being treated as a real mismatch.
 */
export async function ensureBenchmarkSpecs() {
  const manifest = await readManifest();
  await mkdir(SPECS_DIR, { recursive: true });

  for (const [file, { sha256: expected, url }] of Object.entries(manifest)) {
    const target = path.join(SPECS_DIR, file);
    let text = await readFile(target, "utf8").catch(() => undefined);

    if (text !== undefined && sha256(text) === expected) {
      continue;
    }

    text = await download(file, url);

    const actual = sha256(text);

    if (actual !== expected) {
      throw new Error(
        `${file} does not match its pinned hash.\n` +
          `  expected ${expected}\n  actual   ${actual}\n  from     ${url}\n` +
          "The spec changed upstream. Re-pin it with `pnpm test:openapi:refresh` " +
          "and commit the updated sources.json.",
      );
    }

    await writeFile(target, text);
  }

  return SPECS_DIR;
}
