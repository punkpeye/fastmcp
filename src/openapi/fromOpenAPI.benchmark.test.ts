import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, test, vi } from "vitest";

import type { FastMCP } from "../FastMCP.js";
import type { JsonSchemaObject } from "../jsonSchemaAdapter.js";
import type { HttpRoute } from "./types.js";

import { jsonSchemaAdapter } from "../jsonSchemaAdapter.js";
// @ts-expect-error -- plain .mjs helper, shared with the refresh script
import { ensureBenchmarkSpecs } from "./__fixtures__/ensureBenchmarkSpecs.mjs";
import { fromOpenAPI } from "./fromOpenAPI.js";
import { loadSpec } from "./loadSpec.js";
import { generateNames } from "./naming.js";
import { extractRoutes } from "./routes.js";
import {
  buildFlatSchema,
  buildSharedDefs,
  SUPPORTED_BODY_CONTENT_TYPES,
} from "./schemas.js";
import { selectRoutes } from "./selection.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.join(__dirname, "__fixtures__");
const SUPPORTED_BODY_CONTENT_TYPE_SET = new Set<string>(
  SUPPORTED_BODY_CONTENT_TYPES,
);

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
 * component schemas, form-urlencoded-only request bodies (Stripe, Twilio),
 * and specs large enough to surface naming collisions.
 */
const SPECS = [
  { file: "benchmark-specs/petstore.json", name: "Petstore" },
  { file: "benchmark-specs/box.json", name: "Box" },
  { file: "benchmark-specs/twilio.json", name: "Twilio" },
  { file: "benchmark-specs/posthog.yaml", name: "PostHog" },
  { file: "benchmark-specs/stripe.json", name: "Stripe" },
  { file: "multi-file-spec/root.yaml", name: "Multi-file YAML spec" },
];

/**
 * Whether `fromOpenAPI` skips this route entirely rather than turning it
 * into a tool — reuses `buildFlatSchema` itself (the actual production
 * logic) instead of re-deriving "which content types are unsupported" as a
 * second, parallel heuristic here. A prior version of this check only
 * looked at the declared content-type string, which drifted out of sync
 * with `extractBodyProperties` (schemas.ts) treating a non-object body
 * declared as form-urlencoded as unsupported too — silently over-counting
 * `expectedToolCount` against real specs that hit that case.
 *
 * The document's real shared definitions have to be passed along, exactly
 * as `fromOpenAPI` does: a form body declared as a `$ref` (Box's OAuth
 * operations) is only flattenable once that reference resolves.
 */
function isSkipped(
  route: HttpRoute,
  sharedDefs: ReturnType<typeof buildSharedDefs>,
): boolean {
  return !!buildFlatSchema(route, sharedDefs).unsupportedBodyContentType;
}

describe.each(SPECS)("fromOpenAPI benchmark: $name", ({ file }) => {
  test(
    "converts every non-deprecated, encodable operation into a uniquely-named tool with a well-formed JSON Schema — and a body-bearing one actually carries its body",
    { timeout: 60_000 },
    async () => {
      const specPath = path.join(FIXTURES_DIR, file);

      const { document } = await loadSpec(specPath);
      const sharedDefs = buildSharedDefs(document);
      const routes = extractRoutes(document);
      const nonDeprecated = routes.filter((route) => !route.deprecated);
      const expectedToolCount = nonDeprecated.filter(
        (route) => !isSkipped(route, sharedDefs),
      ).length;

      // Mirrors fromOpenAPI's own internal selection/naming so a tool's name
      // can be matched back to the route it came from below.
      const selected = selectRoutes(routes, { maxTools: Infinity });
      const names = generateNames(selected, undefined);
      const routesByName = new Map(
        [...names].map(([route, name]) => [name, route]),
      );

      // Compiles each tool's schema through the same AJV path FastMCP uses
      // at runtime (jsonSchemaAdapter) — a malformed schema rejects here
      // instead of resolving to a validation result. AJV (strict: false,
      // matching production) logs a console.warn for every non-standard
      // `format` a real spec uses (e.g. Twilio's "phone-number", Stripe's
      // "unix-time"/"decimal"), and fromOpenAPI itself warns once for any
      // operations it skipped (Box has 11, unsupported content types) —
      // both expected and muted here rather than spamming the test run.
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

      try {
        const server = await fromOpenAPI({
          maxTools: Infinity,
          spec: specPath,
        });
        const client = await connect(server);
        const { tools } = await client.listTools();

        expect(tools).toHaveLength(expectedToolCount);
        expect(new Set(tools.map((tool) => tool.name)).size).toBe(tools.length);

        for (const tool of tools) {
          const schema = jsonSchemaAdapter(
            tool.inputSchema as JsonSchemaObject,
          );
          await expect(schema["~standard"].validate({})).resolves.toBeDefined();

          // The actual regression this benchmark exists to catch: before
          // form-urlencoded support, every Stripe/Twilio write operation
          // silently generated a tool with zero body properties. For any
          // non-GET tool whose route declares a body in a supported
          // encoding with real properties, the tool's schema must have
          // *more* properties than the route's own parameter list — i.e.
          // the body actually contributed something. `buildFlatSchema`
          // always contributes exactly one property per parameter
          // occurrence regardless of collision-suffixing, so
          // `route.parameters.length` is an exact, generic baseline.
          const route = routesByName.get(tool.name);

          if (!route || route.method === "get") {
            continue;
          }

          const contentTypes = Object.keys(route.requestBody?.content ?? {});
          const supportedType = contentTypes.find((ct) =>
            SUPPORTED_BODY_CONTENT_TYPE_SET.has(ct),
          );

          if (!supportedType) {
            continue;
          }

          const bodySchema = route.requestBody?.content?.[supportedType]
            ?.schema as JsonSchemaObject | undefined;
          const bodyProperties = bodySchema?.properties as
            | Record<string, unknown>
            | undefined;
          const declaresProperties =
            !!bodySchema &&
            (bodySchema.type !== "object" ||
              Object.keys(bodyProperties ?? {}).length > 0);

          if (!declaresProperties) {
            continue;
          }

          const toolPropertyCount = Object.keys(
            (tool.inputSchema as JsonSchemaObject).properties ?? {},
          ).length;

          expect(toolPropertyCount).toBeGreaterThan(route.parameters.length);
        }
      } finally {
        warn.mockRestore();
      }
    },
  );

  test(
    "with resources: true, every eligible operation lands in exactly one of tools/resources/resourceTemplates",
    { timeout: 60_000 },
    async () => {
      const specPath = path.join(FIXTURES_DIR, file);
      const { document } = await loadSpec(specPath);
      const sharedDefs = buildSharedDefs(document);
      const expectedCount = extractRoutes(document).filter(
        (route) => !route.deprecated && !isSkipped(route, sharedDefs),
      ).length;

      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

      try {
        const server = await fromOpenAPI({
          maxTools: Infinity,
          resources: true,
          spec: specPath,
        });
        const client = await connect(server);

        const [{ tools }, { resources }, { resourceTemplates }] =
          await Promise.all([
            client.listTools(),
            hasResourcesCapability(client)
              ? client.listResources()
              : Promise.resolve({ resources: [] as { name: string }[] }),
            hasResourcesCapability(client)
              ? client.listResourceTemplates()
              : Promise.resolve({
                  resourceTemplates: [] as { name: string }[],
                }),
          ]);

        const allNames = [
          ...tools.map((t) => t.name),
          ...resources.map((r) => r.name),
          ...resourceTemplates.map((t) => t.name),
        ];

        expect(allNames).toHaveLength(expectedCount);
        expect(new Set(allNames).size).toBe(allNames.length);
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

function hasResourcesCapability(client: Client): boolean {
  return !!client.getServerCapabilities()?.resources;
}
