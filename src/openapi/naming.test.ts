import { expect, test } from "vitest";

import type { HttpRoute } from "./types.js";

import { generateToolNames } from "./naming.js";

function route(overrides: Partial<HttpRoute>): HttpRoute {
  return {
    deprecated: false,
    method: "get",
    parameters: [],
    path: "/x",
    tags: [],
    ...overrides,
  };
}

test("uses operationId, slugified", () => {
  const names = generateToolNames(
    [route({ operationId: "list Pets!" })],
    undefined,
  );
  expect([...names.values()]).toEqual(["list_Pets"]);
});

test("mcpNames overrides operationId", () => {
  const names = generateToolNames([route({ operationId: "listPets" })], {
    listPets: "getAllPets",
  });
  expect([...names.values()]).toEqual(["getAllPets"]);
});

test("strips FastAPI-style __ suffixes from operationId", () => {
  const names = generateToolNames(
    [route({ operationId: "get_user__users__get" })],
    undefined,
  );
  expect([...names.values()]).toEqual(["get_user"]);
});

test("falls back to method_path when there is no operationId or summary", () => {
  const names = generateToolNames(
    [route({ method: "get", path: "/pets/{id}" })],
    undefined,
  );
  expect([...names.values()]).toEqual(["get_pets_id"]);
});

test("collisions get a numeric suffix", () => {
  const routes = [
    route({ operationId: "listPets", path: "/v1/pets" }),
    route({ operationId: "listPets", path: "/v2/pets" }),
    route({ operationId: "listPets", path: "/v3/pets" }),
  ];
  const names = generateToolNames(routes, undefined);
  expect([...names.values()]).toEqual(["listPets", "listPets_2", "listPets_3"]);
});

test("a collision is checked against the final name, not just the base — a spec whose own operationId already looks auto-suffixed never produces a duplicate", () => {
  const routes = [
    route({ operationId: "foo", path: "/1" }),
    route({ operationId: "foo_2", path: "/2" }),
    route({ operationId: "foo", path: "/3" }),
  ];
  const names = [...generateToolNames(routes, undefined).values()];
  expect(names).toEqual(["foo", "foo_2", "foo_3"]);
  expect(new Set(names).size).toBe(3);
});

test("a collision suffix never pushes the name past 56 characters", () => {
  const longId = "a".repeat(80);
  const routes = [
    route({ operationId: longId, path: "/1" }),
    route({ operationId: longId, path: "/2" }),
    route({ operationId: longId, path: "/3" }),
  ];
  const names = [...generateToolNames(routes, undefined).values()];
  expect(new Set(names).size).toBe(3);

  for (const name of names) {
    expect(name.length).toBeLessThanOrEqual(56);
  }
});
