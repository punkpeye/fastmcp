import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import type { FastMCP } from "../FastMCP.js";
import type { JsonSchemaObject } from "../jsonSchemaAdapter.js";

import { jsonSchemaAdapter } from "../jsonSchemaAdapter.js";
import { fromOpenAPI } from "./fromOpenAPI.js";
import { loadSpec } from "./loadSpec.js";
import { extractRoutes } from "./routes.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.join(__dirname, "__fixtures__");

/**
 * Real-world OpenAPI 3.x documents, vendored under __fixtures__/ so this
 * suite is deterministic and network-free. Refresh them with
 * `pnpm bench:openapi:refresh` (see scripts/refresh-openapi-benchmark-specs.mjs).
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
      // instead of resolving to a validation result.
      for (const tool of tools) {
        const schema = jsonSchemaAdapter(tool.inputSchema as JsonSchemaObject);
        await expect(schema["~standard"].validate({})).resolves.toBeDefined();
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
