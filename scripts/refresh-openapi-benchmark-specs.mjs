#!/usr/bin/env node
// Re-downloads the large benchmark specs and re-pins their hashes in
// src/openapi/__fixtures__/benchmark-specs/sources.json.
//
// The spec files themselves are not committed (see ensureBenchmarkSpecs.mjs);
// what lands in a commit is the sources.json hash change, which is the part
// worth reviewing. Run this when a spec legitimately changes upstream and the
// benchmark reports a hash mismatch.

import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import {
  download,
  readManifest,
  sha256,
  SPECS_DIR,
} from "../src/openapi/__fixtures__/ensureBenchmarkSpecs.mjs";

const MANIFEST_PATH = path.join(SPECS_DIR, "sources.json");

const manifest = await readManifest();
const document = JSON.parse(await readFile(MANIFEST_PATH, "utf8"));

for (const [file, { sha256: previous, url }] of Object.entries(manifest)) {
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
