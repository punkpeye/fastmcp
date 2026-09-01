import { expect, test } from "vitest";

import type { HttpRoute } from "./types.js";

import {
  buildResourceMapping,
  isEligibleForResource,
} from "./resourceMapping.js";

function route(overrides: Partial<HttpRoute>): HttpRoute {
  return {
    deprecated: false,
    method: "get",
    parameters: [],
    path: "/pets/{petId}",
    tags: [],
    ...overrides,
  };
}

test("a route with only path/query parameters is eligible", () => {
  expect(
    isEligibleForResource(
      route({
        parameters: [
          {
            in: "path",
            name: "petId",
            required: true,
            schema: { type: "integer" },
          },
          { in: "query", name: "verbose", schema: { type: "boolean" } },
        ],
      }),
    ),
  ).toBe(true);
});

test("a header parameter makes a route ineligible", () => {
  expect(
    isEligibleForResource(
      route({
        parameters: [
          { in: "header", name: "x-api-key", schema: { type: "string" } },
        ],
      }),
    ),
  ).toBe(false);
});

test("a cookie parameter makes a route ineligible", () => {
  expect(
    isEligibleForResource(
      route({
        parameters: [
          { in: "cookie", name: "session", schema: { type: "string" } },
        ],
      }),
    ),
  ).toBe(false);
});

test("an array-typed query parameter makes a route ineligible", () => {
  expect(
    isEligibleForResource(
      route({
        parameters: [
          {
            in: "query",
            name: "tags",
            schema: { items: { type: "string" }, type: "array" },
          },
        ],
      }),
    ),
  ).toBe(false);
});

test("an empty parameterMap produces a static resource", () => {
  const mapping = buildResourceMapping(
    route({ path: "/pets" }),
    "listPets",
    {},
    undefined,
  );
  expect(mapping).toEqual({ kind: "resource", uri: "openapi://listPets/pets" });
});

test("path-only parameters produce a resource template reusing the OpenAPI path verbatim", () => {
  const mapping = buildResourceMapping(
    route({ path: "/pets/{petId}" }),
    "getPetById",
    { petId: { in: "path", name: "petId" } },
    ["petId"],
  );
  expect(mapping).toEqual({
    args: [{ name: "petId", required: true }],
    kind: "template",
    uriTemplate: "openapi://getPetById/pets/{petId}",
  });
});

test("query-only parameters append an RFC 6570 query-expansion segment", () => {
  const mapping = buildResourceMapping(
    route({ path: "/pets" }),
    "findPets",
    { status: { in: "query", name: "status" } },
    undefined,
  );
  expect(mapping).toEqual({
    args: [{ name: "status", required: false }],
    kind: "template",
    uriTemplate: "openapi://findPets/pets{?status}",
  });
});

test("path and query parameters combine, path substitution first", () => {
  const mapping = buildResourceMapping(
    route({ path: "/pets/{petId}/photos" }),
    "getPetPhotos",
    {
      petId: { in: "path", name: "petId" },
      size: { in: "query", name: "size" },
    },
    ["petId"],
  );
  expect(mapping).toEqual({
    args: [
      { name: "petId", required: true },
      { name: "size", required: false },
    ],
    kind: "template",
    uriTemplate: "openapi://getPetPhotos/pets/{petId}/photos{?size}",
  });
});

test("a collision-suffixed flat key rewrites the specific path variable it replaced", () => {
  // e.g. a path param "id" colliding with a query param also named "id" —
  // buildFlatSchema would have suffixed the path one to "id__path".
  const mapping = buildResourceMapping(
    route({ path: "/items/{id}" }),
    "getItem",
    {
      id__path: { in: "path", name: "id" },
      id__query: { in: "query", name: "id" },
    },
    ["id__path"],
  );
  expect(mapping.kind).toBe("template");
  expect((mapping as { uriTemplate: string }).uriTemplate).toBe(
    "openapi://getItem/items/{id__path}{?id__query}",
  );
});
