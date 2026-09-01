# OpenAPI to MCP

`fromOpenAPI()` (`fastmcp/openapi`) converts an OpenAPI 3.x document into a FastMCP server, turning each operation into a tool.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Choosing which operations become tools](#choosing-which-operations-become-tools)
- [GET → resources](#get--resources)
- [Options](#options)
- [Authentication](#authentication)
- [Adding to an existing server](#adding-to-an-existing-server)
- [Known limitations](#known-limitations)

## Basic Usage

```typescript
import { fromOpenAPI } from "fastmcp/openapi";

const server = await fromOpenAPI({
  spec: "https://petstore3.swagger.io/api/v3/openapi.json",
  include: (operation) => operation.tags.includes("pet"),
});

await server.start({ transportType: "stdio" });
```

`spec` accepts a URL, a local file path, or an already-parsed OpenAPI document (JSON or YAML). Passing a URL or file path — rather than an object you fetched and parsed yourself — is what lets external `$ref`s (multi-file specs) and a relative `servers[0].url` resolve correctly, since both are resolved relative to that value.

## Choosing which operations become tools

Turning every operation in a large spec into a tool produces a tool list most MCP clients can't work with well. There is no way to make this fully automatic, so `fromOpenAPI` asks you to choose:

```typescript
const server = await fromOpenAPI({
  spec: "https://api.example.com/openapi.json",
  include: (operation) => operation.tags.includes("orders"),
  exclude: (operation) => operation.operationId === "deleteAllOrders",
});
```

`include`/`exclude` receive an `OperationSummary` (`{ deprecated, method, operationId, path, tags }`). Deprecated operations are excluded by default.

If neither `include`/`exclude` nor `maxTools` is given and the spec still produces more than 40 operations, `fromOpenAPI` throws instead of silently generating a wall of tools. Pass `maxTools` to raise that limit explicitly once you've decided that's really what you want.

## GET → resources

Pass `resources: true` to map an eligible `GET` operation to an MCP resource (no parameters) or resource template (path and/or query parameters) instead of a tool:

```typescript
const server = await fromOpenAPI({
  spec: "https://petstore3.swagger.io/api/v3/openapi.json",
  include: (operation) => operation.tags.includes("pet"),
  resources: true,
});
```

`getPetById` (`GET /pet/{petId}`) becomes a resource template at `openapi://getPetById/pet/{petId}`, readable via `client.readResource({ uri: "openapi://getPetById/pet/10" })`. A `GET` with no parameters at all becomes a static resource.

A `GET` stays a tool instead — even with `resources: true` — when:

- it has any `header` or `cookie` parameter (these can't be expressed in a resource URI, and resource reads have no per-call side channel for them), or
- any of its path/query parameters is array-typed (OpenAPI's array query serialization and RFC 6570's don't match).

This means a "get by ID" style endpoint typically becomes a resource template, while a "search/filter" endpoint with array-valued query parameters typically stays a tool — which tends to match how each is actually used.

There's no per-operation override for this — an eligible `GET` always maps to a resource when `resources: true`; use `exclude` if you want a specific one to stay a tool instead of being generated at all.

## Options

| Option      | Type                                                       | Description                                                                                |
| ----------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `spec`      | `string \| object`                                         | Required. A URL, file path, or parsed OpenAPI document.                                    |
| `name`      | `string`                                                   | Name for a newly-created server. Defaults to the spec's `info.title`, or "OpenAPI Server". |
| `version`   | `` `${number}.${number}.${number}` ``                      | Version for a newly-created server. Defaults to `"1.0.0"`.                                 |
| `server`    | `FastMCP`                                                  | Register the generated tools onto an existing server instead of creating one.              |
| `include`   | `(operation: OperationSummary) => boolean`                 | Only keep matching operations.                                                             |
| `exclude`   | `(operation: OperationSummary) => boolean`                 | Drop matching operations, applied after `include`.                                         |
| `maxTools`  | `number`                                                   | Hard cap; throws if the selected operation count exceeds it.                               |
| `mcpNames`  | `Record<string, string>`                                   | Override the generated tool name for a given `operationId`.                                |
| `resources` | `boolean`                                                  | Map eligible `GET`s to resources/resource templates instead of tools. Default `false`.     |
| `baseUrl`   | `string`                                                   | Overrides the resolved `servers[0].url`.                                                   |
| `headers`   | `Record<string, string> \| (() => Record<string, string>)` | Static or dynamically-resolved headers sent with every generated tool call.                |
| `fetch`     | `typeof fetch`                                             | HTTP client used to execute tool calls. Defaults to the global `fetch`.                    |

## Authentication

Most APIs need an API key or bearer token. Use `headers`:

```typescript
const server = await fromOpenAPI({
  spec: "https://api.example.com/openapi.json",
  headers: { Authorization: `Bearer ${process.env.API_TOKEN}` },
});
```

Pass a function instead of a plain object if the token needs to be refreshed per call.

## Adding to an existing server

Pass `server` to register the generated tools onto a server you've already created, alongside hand-written tools:

```typescript
const server = new FastMCP({ name: "My Server", version: "1.0.0" });
server.addTool({ name: "customTool", execute: async () => "..." });

await fromOpenAPI({ spec: "https://api.example.com/openapi.json", server });
```

## Known limitations

This scope is deliberately kept tight:

- **Tools by default.** Every operation becomes a tool unless you opt into [`resources: true`](#get--resources), and even then only an eligible `GET` is affected.
- **`application/json` and `application/x-www-form-urlencoded` request bodies.** A nested object/array _value_ inside a form-urlencoded body property is JSON-stringified into a single form value rather than expanded with bracket notation (e.g. Stripe's own `metadata[key]=value` style) — correct for flat scalar properties, which cover the large majority of real-world form-encoded APIs (Stripe, Twilio), not a full form-encoding implementation. Other content types (`multipart/form-data`, `application/json-patch+json`, `application/octet-stream`, ...) are skipped, not silently turned into a tool with no way to carry its payload — `fromOpenAPI` logs one `console.warn` listing every operation it skipped this way.
- **Common query parameter styles only.** Array query parameters are sent as repeated keys (the OpenAPI default `style: form, explode: true`). `deepObject`, `spaceDelimited`, and `pipeDelimited` are not implemented.
- **OpenAPI 3.x only.** Swagger 2.0 documents are rejected with a clear error.
- **No response/`outputSchema` validation.** A tool's result is the raw response body (pretty-printed if JSON), not validated against the spec's response schemas.
- **No CLI.** `fromOpenAPI` is a programmatic API; there is no `fastmcp openapi <spec>` command yet.
