import { expect, test, vi } from "vitest";

import type { HttpRoute } from "./types.js";

import { executeRequest, resolveBaseUrl } from "./requestBuilder.js";

test("a relative servers[0].url is resolved against the spec's own origin", () => {
  // The Petstore's own servers entry is
  // "/api/v3", which is only usable once resolved against where the spec
  // itself was loaded from.
  const url = resolveBaseUrl(
    [{ url: "/api/v3" }],
    "https://petstore3.swagger.io/api/v3/openapi.json",
    undefined,
  );
  expect(url).toBe("https://petstore3.swagger.io/api/v3");
});

test("an absolute servers[0].url is left untouched", () => {
  const url = resolveBaseUrl(
    [{ url: "https://api.example.com/v1" }],
    undefined,
    undefined,
  );
  expect(url).toBe("https://api.example.com/v1");
});

test("baseUrl option always wins", () => {
  const url = resolveBaseUrl(
    [{ url: "/api/v3" }],
    "https://petstore3.swagger.io/api/v3/openapi.json",
    "https://staging.example.com",
  );
  expect(url).toBe("https://staging.example.com");
});

test("server variables are substituted before resolution", () => {
  const url = resolveBaseUrl(
    [
      {
        url: "https://{host}/v1",
        variables: { host: { default: "api.example.com" } },
      },
    ],
    undefined,
    undefined,
  );
  expect(url).toBe("https://api.example.com/v1");
});

test("a relative servers[0].url with no origin and no baseUrl override throws instead of silently building a broken request", () => {
  expect(() =>
    resolveBaseUrl([{ url: "/api/v3" }], undefined, undefined),
  ).toThrow(/relative/);
});

test("no servers entry and no baseUrl throws", () => {
  expect(() => resolveBaseUrl(undefined, undefined, undefined)).toThrow(
    /servers/,
  );
});

function route(overrides: Partial<HttpRoute>): HttpRoute {
  return {
    deprecated: false,
    method: "get",
    parameters: [],
    path: "/pets/{id}",
    tags: [],
    ...overrides,
  };
}

test("executeRequest builds the URL, path substitution, query, headers, and JSON body, then unflattens the response", async () => {
  const fetchImpl = vi.fn<typeof fetch>(
    async () =>
      new Response(JSON.stringify({ ok: true }), {
        headers: { "content-type": "application/json" },
        status: 200,
      }),
  );

  const result = await executeRequest({
    args: { id: "42", limit: 10, tag: ["a", "b"] },
    fetchImpl: fetchImpl as unknown as typeof fetch,
    headers: { "x-api-key": "secret" },
    parameterMap: {
      id: { in: "path", name: "id" },
      limit: { in: "query", name: "limit" },
      tag: { in: "query", name: "tag" },
    },
    route: route({ method: "get" }),
    servers: [{ url: "https://api.example.com" }],
  });

  expect(result).toContain('"ok": true');

  const [calledUrl, calledInit] = fetchImpl.mock.calls[0];
  const parsed = new URL(calledUrl);
  expect(parsed.origin + parsed.pathname).toBe(
    "https://api.example.com/pets/42",
  );
  expect(parsed.searchParams.getAll("tag")).toEqual(["a", "b"]);
  expect(parsed.searchParams.get("limit")).toBe("10");
  expect((calledInit!.headers as Headers).get("x-api-key")).toBe("secret");
});

test("a caller-supplied header overrides the generated content-type, case-insensitively", async () => {
  const fetchImpl = vi.fn<typeof fetch>(
    async () => new Response("{}", { status: 200 }),
  );

  await executeRequest({
    args: { name: "Rex" },
    fetchImpl,
    headers: { "Content-Type": "application/vnd.api+json" },
    parameterMap: { name: { in: "body", name: "name" } },
    route: route({ method: "post" }),
    servers: [{ url: "https://api.example.com" }],
  });

  const [, calledInit] = fetchImpl.mock.calls[0]!;
  const headers = calledInit!.headers as Headers;
  // Exactly the caller's value — not combined into
  // "application/vnd.api+json, application/json".
  expect(headers.get("content-type")).toBe("application/vnd.api+json");
});

test("a form-encoded body (bodyEncoding: 'form') is serialized with URLSearchParams and gets the right content-type", async () => {
  const fetchImpl = vi.fn<typeof fetch>(
    async () => new Response("{}", { status: 200 }),
  );

  await executeRequest({
    args: { amount: 500, description: "a widget & gear" },
    bodyEncoding: "form",
    fetchImpl,
    parameterMap: {
      amount: { in: "body", name: "amount" },
      description: { in: "body", name: "description" },
    },
    route: route({ method: "post" }),
    servers: [{ url: "https://api.example.com" }],
  });

  const [, calledInit] = fetchImpl.mock.calls[0]!;
  const headers = calledInit!.headers as Headers;
  expect(headers.get("content-type")).toBe("application/x-www-form-urlencoded");

  const body = new URLSearchParams(calledInit!.body as string);
  expect(body.get("amount")).toBe("500");
  expect(body.get("description")).toBe("a widget & gear");
});

test("a caller-supplied content-type header overrides the generated form-urlencoded one", async () => {
  const fetchImpl = vi.fn<typeof fetch>(
    async () => new Response("{}", { status: 200 }),
  );

  await executeRequest({
    args: { name: "Rex" },
    bodyEncoding: "form",
    fetchImpl,
    headers: { "Content-Type": "application/vnd.api+json" },
    parameterMap: { name: { in: "body", name: "name" } },
    route: route({ method: "post" }),
    servers: [{ url: "https://api.example.com" }],
  });

  const [, calledInit] = fetchImpl.mock.calls[0]!;
  expect((calledInit!.headers as Headers).get("content-type")).toBe(
    "application/vnd.api+json",
  );
});

test("an array-valued form body property is sent as repeated keys", async () => {
  const fetchImpl = vi.fn<typeof fetch>(
    async () => new Response("{}", { status: 200 }),
  );

  await executeRequest({
    args: { tag: ["a", "b"] },
    bodyEncoding: "form",
    fetchImpl,
    parameterMap: { tag: { in: "body", name: "tag" } },
    route: route({ method: "post" }),
    servers: [{ url: "https://api.example.com" }],
  });

  const [, calledInit] = fetchImpl.mock.calls[0]!;
  const body = new URLSearchParams(calledInit!.body as string);
  expect(body.getAll("tag")).toEqual(["a", "b"]);
});

test("a non-ok response throws with the status and body surfaced", async () => {
  const fetchImpl = vi.fn(
    async () => new Response("not found", { status: 404 }),
  );

  await expect(
    executeRequest({
      args: {},
      fetchImpl: fetchImpl as unknown as typeof fetch,
      parameterMap: {},
      route: route({}),
      servers: [{ url: "https://api.example.com" }],
    }),
  ).rejects.toThrow(/404/);
});
