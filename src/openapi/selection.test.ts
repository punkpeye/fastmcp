import { expect, test } from "vitest";

import type { HttpRoute } from "./types.js";

import { DEFAULT_MAX_OPERATIONS, selectRoutes } from "./selection.js";

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

test("excludes deprecated operations by default", () => {
  const routes = [
    route({ operationId: "active" }),
    route({ deprecated: true, operationId: "old" }),
  ];
  expect(selectRoutes(routes, {}).map((r) => r.operationId)).toEqual([
    "active",
  ]);
});

test("include keeps only matching operations", () => {
  const routes = [
    route({ operationId: "a", tags: ["pets"] }),
    route({ operationId: "b", tags: ["orders"] }),
  ];
  const selected = selectRoutes(routes, {
    include: (op) => op.tags.includes("pets"),
  });
  expect(selected.map((r) => r.operationId)).toEqual(["a"]);
});

test("exclude is applied after include", () => {
  const routes = [
    route({ method: "get", operationId: "read", tags: ["pets"] }),
    route({ method: "delete", operationId: "purge", tags: ["pets"] }),
  ];
  const selected = selectRoutes(routes, {
    exclude: (op) => op.method === "delete",
    include: (op) => op.tags.includes("pets"),
  });
  expect(selected.map((r) => r.operationId)).toEqual(["read"]);
});

test("orders by method priority (GET, POST, PUT, PATCH, DELETE), then path", () => {
  const routes = [
    route({ method: "delete", operationId: "d", path: "/b" }),
    route({ method: "post", operationId: "c", path: "/b" }),
    route({ method: "get", operationId: "a", path: "/z" }),
    route({ method: "get", operationId: "b", path: "/a" }),
  ];
  expect(selectRoutes(routes, {}).map((r) => r.operationId)).toEqual([
    "b",
    "a",
    "c",
    "d",
  ]);
});

test("throws instead of silently generating a huge tool list when no selection was made", () => {
  const routes = Array.from({ length: DEFAULT_MAX_OPERATIONS + 1 }, (_, i) =>
    route({ operationId: `op${i}`, path: `/${i}` }),
  );
  expect(() => selectRoutes(routes, {})).toThrow(/exceeds the default limit/);
});

test("an explicit include is treated as the user's deliberate choice, even over the default threshold without maxTools", () => {
  const routes = Array.from({ length: DEFAULT_MAX_OPERATIONS + 1 }, (_, i) =>
    route({ operationId: `op${i}`, path: `/${i}` }),
  );
  expect(() => selectRoutes(routes, { include: () => true })).not.toThrow();
});

test("maxTools throws when the selection still exceeds it", () => {
  const routes = [route({ operationId: "a" }), route({ operationId: "b" })];
  expect(() => selectRoutes(routes, { maxTools: 1 })).toThrow(/maxTools/);
});
