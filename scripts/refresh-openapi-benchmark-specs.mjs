#!/usr/bin/env node
// Re-downloads the specs vendored under
// src/openapi/__fixtures__/benchmark-specs/ for fromOpenAPI.benchmark.ts.
// They are not fetched automatically (the benchmark suite is meant to be
// deterministic and network-free), so run this manually when a spec needs
// updating and review the diff before committing — some of these are
// several megabytes.

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const FIXTURES_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../src/openapi/__fixtures__/benchmark-specs",
);

// slack.json is intentionally left as Swagger 2.0 — Slack does not publish
// an OpenAPI 3.x spec, and the benchmark asserts that fromOpenAPI() rejects
// it (see the comment in fromOpenAPI.benchmark.ts).
const SPECS = {
  "box.json":
    "https://raw.githubusercontent.com/box/box-openapi/main/openapi.json",
  "petstore.json": "https://petstore3.swagger.io/api/v3/openapi.json",
  "posthog.yaml": "https://app.posthog.com/api/schema/",
  "slack.json":
    "https://raw.githubusercontent.com/slackapi/slack-api-specs/master/web-api/slack_web_openapi_v2.json",
  "stripe.json":
    "https://raw.githubusercontent.com/stripe/openapi/master/openapi/spec3.json",
  "twilio.json":
    "https://raw.githubusercontent.com/twilio/twilio-oai/main/spec/json/twilio_api_v2010.json",
};

await mkdir(FIXTURES_DIR, { recursive: true });

for (const [file, url] of Object.entries(SPECS)) {
  console.log(`Fetching ${file} <- ${url}`);
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`${url} responded with ${response.status}`);
  }

  let text = await response.text();

  if (file === "slack.json") {
    // Slack's own example OAuth responses embed realistic-looking (but
    // fake) bot/user tokens, which trip GitHub's push-protection secret
    // scanner. Redacted generically — by shape, not by literal value, so
    // this script's own source never contains a token-shaped string —
    // so a refresh doesn't reintroduce one.
    text = text.replace(
      /xox[abpr]-\d{5,}-\d{5,}-[A-Za-z0-9]{10,}/g,
      "xoxb-EXAMPLE-REDACTED-TOKEN",
    );
  }

  await writeFile(path.join(FIXTURES_DIR, file), text);
}

console.log("Done.");
