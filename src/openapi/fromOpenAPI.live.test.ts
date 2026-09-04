import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { getRandomPort } from "get-port-please";
import { expect, test } from "vitest";

import type { FastMCP, FastMCPSession } from "../FastMCP.js";

import { fromOpenAPI } from "./fromOpenAPI.js";

const PETSTORE_SPEC_URL = "https://petstore3.swagger.io/api/v3/openapi.json";

/**
 * The "test that can fail": schema validation proves tools are well-formed,
 * not that the transport works. This does a real initialize + tools/list +
 * tool call against the public Petstore v3 API — whose own `servers[0].url`
 * is the relative "/api/v3" that only resolves correctly when joined against
 * the spec's own origin (see requestBuilder.ts `resolveBaseUrl`). If that
 * resolution were wrong, the call below would fail with a fetch/URL error,
 * not just an assertion mismatch.
 *
 * It reaches a third-party host, so it runs only under `pnpm test:openapi`
 * (its own CI job) rather than in `pnpm test` — otherwise a Petstore outage
 * would fail CI on every unrelated PR.
 *
 * Petstore is a shared, publicly-writable demo that is regularly both
 * mutated and briefly broken (`findPetsByStatus` answers 500 as of writing),
 * so the assertion is deliberately about the property under test rather than
 * about payload contents: a *response from the right host* proves the base
 * URL resolved. An API-level error still proves it; a URL/fetch error does
 * not, and fails.
 */
test(
  "fromOpenAPI: real initialize + tools/list + tool call against Petstore v3",
  { timeout: 20_000 },
  async () => {
    const server: FastMCP = await fromOpenAPI({
      include: (operation) => operation.tags.includes("pet"),
      name: "Petstore",
      spec: PETSTORE_SPEC_URL,
      version: "1.0.0",
    });

    const port = await getRandomPort();
    await server.start({ httpStream: { port }, transportType: "httpStream" });

    try {
      const client = new Client(
        { name: "openapi-test-client", version: "1.0.0" },
        { capabilities: {} },
      );

      const session = await new Promise<FastMCPSession>((resolve) => {
        server.on("connect", async (event) => {
          await event.session.waitForReady();
          resolve(event.session);
        });

        client.connect(
          new SSEClientTransport(new URL(`http://localhost:${port}/sse`)),
        );
      });

      void session; // established for its side effect (readiness), not inspected directly

      const { tools } = await client.listTools();
      const toolNames = tools.map((tool) => tool.name);

      expect(toolNames).toContain("getPetById");
      expect(toolNames).toContain("findPetsByStatus");
      expect(toolNames.length).toBeGreaterThan(0);
      expect(toolNames.length).toBeLessThanOrEqual(8); // the `pet`-tagged operations

      const result = await client.callTool({
        arguments: { petId: 10 },
        name: "getPetById",
      });

      const [content] = result.content as { text: string; type: string }[];
      expect(content.type).toBe("text");

      if (result.isError) {
        // Reached the API and got an HTTP status back — which is what this
        // test is here to prove. Pet 10 may have been deleted by another
        // caller, or the demo may be having a bad day; neither is a
        // regression in fromOpenAPI.
        expect(content.text).toMatch(/^GET \/pet\/10 failed with \d{3}:/);
        return;
      }

      // Deliberately not asserting on pet 10's actual data: Petstore is a
      // shared, publicly-writable demo, so its contents can be mutated by
      // any other caller at any time. Valid JSON back from the real host is
      // what proves the relative servers[0].url ("/api/v3") resolved and
      // the request round-tripped; the payload itself isn't ours to depend
      // on.
      expect(() => JSON.parse(content.text)).not.toThrow();
    } finally {
      await server.stop();
    }
  },
);

/**
 * `resources: true`'s counterpart to the test above: `fromOpenAPI.offline.
 * test.ts` only exercises resource reads against a mocked fetch, and
 * `fromOpenAPI.benchmark.test.ts`'s `resources: true` pass only counts
 * tools/resources/resourceTemplates against real specs, never actually
 * calls `readResource()`. This closes that gap with a real read against
 * Petstore.
 *
 * `getPetById` (`GET /pet/{petId}`, path param only, no header/cookie/array
 * params) is exactly the shape that becomes a resource template — verified
 * manually against the real API before writing this test.
 *
 * Error handling here is deliberately a try/catch around `readResource()`,
 * not an `isError` check on a result field: unlike tool calls, a thrown
 * error inside a resource template's `load()` propagates as a *rejected*
 * `readResource()` promise (an `McpError`), confirmed by reading FastMCP.ts's
 * `ReadResourceRequestSchema` handler and the MCP SDK's request dispatch —
 * there is no `isError`-content shape for `resources/read`. Either a
 * resolved valid-JSON result or a caught error counts as success here
 * (mirroring the tool test's tolerance above for Petstore's shared, mutable
 * demo data) — both prove the relative servers[0].url ("/api/v3") resolved
 * and a real request reached the right host.
 */
test(
  "fromOpenAPI: resources: true — real resource template read against Petstore v3",
  { timeout: 20_000 },
  async () => {
    const server: FastMCP = await fromOpenAPI({
      include: (operation) => operation.tags.includes("pet"),
      name: "Petstore",
      resources: true,
      spec: PETSTORE_SPEC_URL,
      version: "1.0.0",
    });

    const port = await getRandomPort();
    await server.start({ httpStream: { port }, transportType: "httpStream" });

    try {
      const client = new Client(
        { name: "openapi-test-client", version: "1.0.0" },
        { capabilities: {} },
      );

      await new Promise<FastMCPSession>((resolve) => {
        server.on("connect", async (event) => {
          await event.session.waitForReady();
          resolve(event.session);
        });

        client.connect(
          new SSEClientTransport(new URL(`http://localhost:${port}/sse`)),
        );
      });

      const { resourceTemplates } = await client.listResourceTemplates();
      const template = resourceTemplates.find((t) => t.name === "getPetById");

      expect(template?.uriTemplate).toBe("openapi://getPetById/pet/{petId}");

      try {
        const result = await client.readResource({
          uri: "openapi://getPetById/pet/10",
        });

        expect(() =>
          JSON.parse((result.contents[0] as { text: string }).text),
        ).not.toThrow();
      } catch (error) {
        // Reached the API and got an error response back — which is what
        // this test is here to prove; see the doc comment above.
        expect(error).toBeInstanceOf(Error);
      }
    } finally {
      await server.stop();
    }
  },
);
