// Fetches the large benchmark specs listed in
// benchmark-specs/sources.json into benchmark-specs/, verifying each against
// its pinned sha256.
//
// They are not vendored: the five of them are ~20MB, which is permanent
// growth on every clone of this repo for files nobody reads in review. The
// hash pin is what keeps a benchmark run reproducible without committing
// them — a spec that drifts upstream fails loudly rather than silently
// changing what the suite tests. GitHub-hosted specs are fetched from a
// pinned commit, so they only change when the pin is moved on purpose (see
// parseGitHubRawUrl). One exception: see UNSTABLE_SPECS below.
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
 * Specs whose upstream content is known to be transiently unstable — not
 * "changed since we last pinned it," but genuinely different on back-to-back
 * fetches seconds apart, apparently served from different backend instances
 * or during a deploy. PostHog's `/api/schema/` was observed returning three
 * different (each individually valid) responses within a few minutes, while
 * every GitHub-hosted spec here has only ever changed via a real upstream
 * update. A byte-for-byte hash isn't a meaningful signal for these, so a
 * mismatch is a warning, not a hard failure that blocks the whole suite —
 * `fromOpenAPI.benchmark.test.ts`'s own assertions are still what actually
 * verifies whatever gets fetched converts correctly.
 */
const UNSTABLE_SPECS = new Set(["posthog.yaml"]);

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

const GITHUB_RAW =
  /^https:\/\/raw\.githubusercontent\.com\/([^/]+)\/([^/]+)\/([^/]+)\/(.+)$/;

/**
 * GitHub-hosted specs are fetched from a commit, not a branch: a branch URL
 * serves whatever was pushed last, so the pin broke every time upstream
 * touched the file. `track` names the branch that
 * `pnpm test:openapi:refresh` follows when it moves the pin forward.
 */
export function parseGitHubRawUrl(url) {
  const match = GITHUB_RAW.exec(url);

  return match
    ? { owner: match[1], path: match[4], ref: match[3], repo: match[2] }
    : undefined;
}

export function githubRawUrl({ owner, path: filePath, repo }, commit) {
  return `https://raw.githubusercontent.com/${owner}/${repo}/${commit}/${filePath}`;
}

/**
 * The newest commit on `branch` that touched the spec file, so re-pinning to
 * it changes nothing unless the file itself changed.
 */
export async function latestCommitFor(source, branch) {
  const api = new URL(
    `https://api.github.com/repos/${source.owner}/${source.repo}/commits`,
  );
  api.searchParams.set("sha", branch);
  api.searchParams.set("path", source.path);
  api.searchParams.set("per_page", "1");

  const headers = { Accept: "application/vnd.github+json" };

  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }

  const response = await fetch(api, { headers });

  if (!response.ok) {
    throw new Error(`${api} responded with ${response.status}`);
  }

  const [latest] = await response.json();

  if (!latest?.sha) {
    throw new Error(`no commit on ${branch} touches ${source.path}`);
  }

  return latest.sha;
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
      if (UNSTABLE_SPECS.has(file)) {
        console.warn(
          `${file} does not match its pinned hash (expected ${expected}, got ${actual}) — ` +
            "this spec's upstream is known to be transiently unstable, so proceeding with " +
            "the freshly-fetched content rather than failing the run. Re-pin with " +
            "`pnpm test:openapi:refresh` if this persists across runs.",
        );
      } else {
        throw new Error(
          `${file} does not match its pinned hash.\n` +
            `  expected ${expected}\n  actual   ${actual}\n  from     ${url}\n` +
            "The spec changed upstream. Re-pin it with `pnpm test:openapi:refresh` " +
            "and commit the updated sources.json.",
        );
      }
    }

    await writeFile(target, text);
  }

  return SPECS_DIR;
}
