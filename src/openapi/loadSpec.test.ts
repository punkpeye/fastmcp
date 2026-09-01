import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

import { loadSpec } from "./loadSpec.js";
import { extractRoutes } from "./routes.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const MULTI_FILE_SPEC = path.join(
  __dirname,
  "__fixtures__/multi-file-spec/root.yaml",
);

test("resolves external $refs across YAML files, including the bare fragment form", async () => {
  const { document, origin } = await loadSpec(MULTI_FILE_SPEC);

  expect(origin).toBeUndefined(); // loaded from a file path, not a URL
  expect(document.openapi).toBe("3.0.3");

  const routes = extractRoutes(document);
  const createPet = routes.find((route) => route.operationId === "createPet");
  const getPet = routes.find((route) => route.operationId === "getPet");

  // "resources/pets.yaml#/Pet" — relative path + bare fragment (no
  // "components" prefix)
  expect(createPet?.requestBody?.content?.["application/json"]?.schema).toEqual(
    {
      properties: {
        id: { type: "integer" },
        name: { type: "string" },
        tag: expect.anything(), // the nested "#/Tag" ref, resolved or spliced in
      },
      required: ["id", "name"],
      type: "object",
    },
  );

  // "resources/pets.yaml#/components/parameters/PetId" — relative path into
  // a nested "components" section of the *external* file.
  expect(getPet?.parameters).toEqual([
    { in: "path", name: "petId", required: true, schema: { type: "integer" } },
  ]);
});

test("a spec passed as an already-parsed object has no real resolution base for external $refs", async () => {
  // If a caller fetches a spec's text themselves and hands loadSpec the parsed object
  // instead of the URL/path, any external $ref in it resolves against the
  // wrong base (here, the process's cwd) instead of the document's own
  // location — so it fails loudly rather than silently dropping operations.
  // `loadSpec` avoids this itself by always passing the original
  // string/object straight through to swagger-parser (see loadSpec.ts).
  await expect(
    loadSpec({
      info: { title: "x", version: "1.0.0" },
      openapi: "3.0.3",
      paths: {
        "/x": {
          get: {
            requestBody: {
              content: {
                "application/json": {
                  schema: { $ref: "resources/pets.yaml#/Pet" },
                },
              },
            },
            responses: { 200: { description: "OK" } },
          },
        },
      },
    }),
  ).rejects.toThrow();
});
