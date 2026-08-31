# OpenAPI to MCP

`fromOpenAPI()` (`fastmcp/openapi`) converts an OpenAPI 3.x document into a FastMCP server, turning each operation into a tool.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Choosing which operations become tools](#choosing-which-operations-become-tools)
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

## Options

| Option     | Type                                                       | Description                                                                                |
| ---------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `spec`     | `string \| object`                                         | Required. A URL, file path, or parsed OpenAPI document.                                    |
| `name`     | `string`                                                   | Name for a newly-created server. Defaults to the spec's `info.title`, or "OpenAPI Server". |
| `version`  | `` `${number}.${number}.${number}` ``                      | Version for a newly-created server. Defaults to `"1.0.0"`.                                 |
| `server`   | `FastMCP`                                                  | Register the generated tools onto an existing server instead of creating one.              |
| `include`  | `(operation: OperationSummary) => boolean`                 | Only keep matching operations.                                                             |
| `exclude`  | `(operation: OperationSummary) => boolean`                 | Drop matching operations, applied after `include`.                                         |
| `maxTools` | `number`                                                   | Hard cap; throws if the selected operation count exceeds it.                               |
| `mcpNames` | `Record<string, string>`                                   | Override the generated tool name for a given `operationId`.                                |
| `baseUrl`  | `string`                                                   | Overrides the resolved `servers[0].url`.                                                   |
| `headers`  | `Record<string, string> \| (() => Record<string, string>)` | Static or dynamically-resolved headers sent with every generated tool call.                |
| `fetch`    | `typeof fetch`                                             | HTTP client used to execute tool calls. Defaults to the global `fetch`.                    |

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

This is a v1 scope, deliberately kept tight:

- **Tools only.** Every operation becomes a tool, including `GET`s — there is no resource/resource-template mapping yet.
- **`application/json` request bodies only.** Multipart and form-urlencoded bodies are not supported.
- **Common query parameter styles only.** Array query parameters are sent as repeated keys (the OpenAPI default `style: form, explode: true`). `deepObject`, `spaceDelimited`, and `pipeDelimited` are not implemented.
- **OpenAPI 3.x only.** Swagger 2.0 documents are rejected with a clear error.
- **No response/`outputSchema` validation.** A tool's result is the raw response body (pretty-printed if JSON), not validated against the spec's response schemas.
- **No CLI.** `fromOpenAPI` is a programmatic API; there is no `fastmcp openapi <spec>` command yet.
