#!/usr/bin/env node
// Re-downloads the large benchmark specs and re-pins their hashes in
// src/openapi/__fixtures__/benchmark-specs/sources.json. A GitHub-hosted spec
// is first moved to the newest commit on its `track` branch that touched it.
//
// The spec files themselves are not committed (see ensureBenchmarkSpecs.mjs);
// what lands in a commit is the sources.json hash change, which is the part
// worth reviewing. Run this when a spec legitimately changes upstream and the
// benchmark reports a hash mismatch.

import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import {
  download,
  githubRawUrl,
  latestCommitFor,
  parseGitHubRawUrl,
  readManifest,
  sha256,
  SPECS_DIR,
} from "../src/openapi/__fixtures__/ensureBenchmarkSpecs.mjs";

const MANIFEST_PATH = path.join(SPECS_DIR, "sources.json");

const manifest = await readManifest();
const document = JSON.parse(await readFile(MANIFEST_PATH, "utf8"));

for (const [file, { sha256: previous, track, url: pinned }] of Object.entries(
  manifest,
)) {
  const source = parseGitHubRawUrl(pinned);
  const url =
    source && track
      ? githubRawUrl(source, await latestCommitFor(source, track))
      : pinned;

  if (url !== pinned) {
    console.log(`  moved ${file} to ${url}`);
    document.specs[file].url = url;
  }

  console.log(`Fetching ${file} <- ${url}`);

  const text = await download(file, url);
  const digest = sha256(text);

  await writeFile(path.join(SPECS_DIR, file), text);
  document.specs[file].sha256 = digest;

  console.log(
    digest === previous
      ? `  unchanged (${digest})`
      : `  re-pinned ${previous} -> ${digest}`,
  );
}

await writeFile(MANIFEST_PATH, `${JSON.stringify(document, null, 2)}\n`);

console.log("Done. Review and commit sources.json.");
