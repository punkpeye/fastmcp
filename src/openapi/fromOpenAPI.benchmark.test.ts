import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, test, vi } from "vitest";

import type { FastMCP } from "../FastMCP.js";
import type { JsonSchemaObject } from "../jsonSchemaAdapter.js";

import { jsonSchemaAdapter } from "../jsonSchemaAdapter.js";
// @ts-expect-error -- plain .mjs helper, shared with the refresh script
import { ensureBenchmarkSpecs } from "./__fixtures__/ensureBenchmarkSpecs.mjs";
import { fromOpenAPI } from "./fromOpenAPI.js";
import { loadSpec } from "./loadSpec.js";
import { extractRoutes } from "./routes.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.join(__dirname, "__fixtures__");

/**
 * The five large specs (~20MB combined) are fetched on demand rather than
 * vendored, and verified against the sha256 pins in
 * __fixtures__/benchmark-specs/sources.json — so a run is still reproducible
 * without that weight sitting in every clone. `petstore.json` and the
 * multi-file YAML fixture are small enough to commit, and keep part of this
 * suite runnable offline. Re-pin with `pnpm test:openapi:refresh`.
 */
beforeAll(async () => {
  await ensureBenchmarkSpecs();
}, 180_000);

/**
 * Real-world OpenAPI 3.x documents covering the shapes that break naive
 * converters: multi-file `$ref`s, `nullable` next to `oneOf`, recursive
 * component schemas, and specs large enough to surface naming collisions.
 */
const SPECS = [
  { file: "benchmark-specs/petstore.json", name: "Petstore" },
  { file: "benchmark-specs/box.json", name: "Box" },
  { file: "benchmark-specs/twilio.json", name: "Twilio" },
  { file: "benchmark-specs/posthog.yaml", name: "PostHog" },
  { file: "benchmark-specs/stripe.json", name: "Stripe" },
  { file: "multi-file-spec/root.yaml", name: "Multi-file YAML spec" },
];

describe.each(SPECS)("fromOpenAPI benchmark: $name", ({ file }) => {
  test(
    "converts every non-deprecated operation into a uniquely-named tool with a well-formed JSON Schema",
    { timeout: 60_000 },
    async () => {
      const specPath = path.join(FIXTURES_DIR, file);

      const { document } = await loadSpec(specPath);
      const expectedToolCount = extractRoutes(document).filter(
        (route) => !route.deprecated,
      ).length;

      const server = await fromOpenAPI({ maxTools: Infinity, spec: specPath });
      const client = await connect(server);
      const { tools } = await client.listTools();

      expect(tools).toHaveLength(expectedToolCount);
      expect(new Set(tools.map((tool) => tool.name)).size).toBe(tools.length);

      // Compiles each tool's schema through the same AJV path FastMCP uses
      // at runtime (jsonSchemaAdapter) — a malformed schema rejects here
      // instead of resolving to a validation result. AJV (strict: false,
      // matching production) logs a console.warn for every non-standard
      // `format` a real spec uses (e.g. Twilio's "phone-number", Stripe's
      // "unix-time"/"decimal") — harmless and expected, so it's muted here
      // rather than left to spam the test run.
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

      try {
        for (const tool of tools) {
          const schema = jsonSchemaAdapter(
            tool.inputSchema as JsonSchemaObject,
          );
          await expect(schema["~standard"].validate({})).resolves.toBeDefined();
        }
      } finally {
        warn.mockRestore();
      }
    },
  );
});

/**
 * Slack does not currently publish an OpenAPI 3.x spec — the "v2" in the
 * file name refers to Slack's Web API version, not OpenAPI's; the document
 * itself is Swagger 2.0. `fromOpenAPI` is documented to reject that (see
 * "Known limitations" in docs/openapi.md), so this pins the rejection
 * itself as the benchmark case instead of faking a spec that doesn't exist.
 */
test("fromOpenAPI benchmark: Slack's real spec is Swagger 2.0, which is rejected", async () => {
  const specPath = path.join(FIXTURES_DIR, "benchmark-specs/slack.json");

  await expect(fromOpenAPI({ spec: specPath })).rejects.toThrow(
    /Swagger 2\.0 is not supported/,
  );
});

async function connect(server: FastMCP) {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "benchmark-client", version: "0.0.0" });

  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);

  return client;
}
