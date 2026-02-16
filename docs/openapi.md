# OpenAPI Integration

FastMCP can automatically convert any [OpenAPI 3.x](https://swagger.io/specification/) specification into MCP tools, resources, and resource templates — allowing you to expose any REST API to LLMs without writing individual tool definitions.

## Quick Start

```typescript
import { FastMCP } from "fastmcp";
import { fromOpenAPI } from "fastmcp/openapi";
import fs from "node:fs";

// Load your OpenAPI spec
const spec = JSON.parse(fs.readFileSync("openapi.json", "utf-8"));

// Convert to MCP definitions
const { tools, resources, resourceTemplates } = fromOpenAPI({
  spec,
  client: {
    request: async (config) => {
      const res = await fetch(config.url, {
        method: config.method,
        headers: config.headers,
        body: config.body ? JSON.stringify(config.body) : undefined,
      });
      return { status: res.status, data: await res.json() };
    },
  },
});

// Register with FastMCP
const server = new FastMCP({ name: "My API", version: "1.0.0" });

for (const tool of tools) {
  server.addTool(tool);
}

for (const resource of resources) {
  server.addResource(resource);
}

for (const template of resourceTemplates) {
  server.addResourceTemplate(template);
}

server.start({ transportType: "stdio" });
```

## How Routes Are Classified

`fromOpenAPI` automatically classifies each OpenAPI operation:

| HTTP Method | Path Parameters | MCP Type |
|---|---|---|
| `GET` | None | **Resource** — static data the LLM can read |
| `GET` | Has `{params}` | **Resource Template** — parameterized data |
| `POST`, `PUT`, `PATCH`, `DELETE` | Any | **Tool** — an action the LLM can invoke |

For example, given this OpenAPI spec:

```yaml
paths:
  /pets:
    get:
      operationId: listPets
      summary: List all pets
  /pets/{petId}:
    get:
      operationId: getPet
      summary: Get a pet by ID
      parameters:
        - name: petId
          in: path
    delete:
      operationId: deletePet
      summary: Delete a pet
      parameters:
        - name: petId
          in: path
```

`fromOpenAPI` produces:
- **Resource**: `listPets` (URI: `api:///pets`)
- **Resource Template**: `getPet` (URI template: `api:///pets/{petId}`)
- **Tool**: `deletePet`

## Options

### `spec` (required)

The parsed OpenAPI 3.x specification object.

```typescript
const spec = JSON.parse(fs.readFileSync("openapi.json", "utf-8"));
```

### `client` (required)

An HTTP client implementing the `HttpClient` interface. This is how `fromOpenAPI` makes requests to the underlying API.

```typescript
type HttpClient = {
  request: (config: {
    url: string;
    method: string;
    headers?: Record<string, string>;
    body?: unknown;
  }) => Promise<{ status: number; data: unknown }>;
};
```

You can use `fetch`, `axios`, or any HTTP library:

**Using fetch:**
```typescript
const client = {
  request: async (config) => {
    const res = await fetch(config.url, {
      method: config.method,
      headers: config.headers,
      body: config.body ? JSON.stringify(config.body) : undefined,
    });
    return { status: res.status, data: await res.json() };
  },
};
```

**Using axios:**
```typescript
import axios from "axios";

const client = {
  request: async (config) => {
    const res = await axios({
      url: config.url,
      method: config.method,
      headers: config.headers,
      data: config.body,
    });
    return { status: res.status, data: res.data };
  },
};
```

### `baseUrl` (optional)

Override the base URL for API requests. If not provided, uses the first `servers[].url` from the spec, or falls back to `http://localhost`.

```typescript
const { tools } = fromOpenAPI({
  spec,
  client,
  baseUrl: "https://api.example.com/v2",
});
```

### `headers` (optional)

Default headers to include with every request. Useful for authentication:

```typescript
const { tools } = fromOpenAPI({
  spec,
  client,
  headers: {
    Authorization: "Bearer sk-...",
    "X-API-Key": "my-key",
  },
});
```

## Parameter Handling

### Path Parameters

Path parameters are automatically substituted into the URL:

```
GET /pets/{petId} + { petId: "123" } → GET /pets/123
```

### Query Parameters

Query parameters are appended to the URL:

```
GET /pets?limit=10&status=available
```

### Header Parameters

Header parameters defined in the OpenAPI spec are extracted from tool arguments and sent as HTTP headers.

### Request Body

For operations with a request body, the body properties are flattened into the tool parameters with a `body_` prefix to avoid name collisions with path/query parameters:

```yaml
# OpenAPI spec
paths:
  /pets:
    post:
      requestBody:
        content:
          application/json:
            schema:
              properties:
                name:
                  type: string
                tag:
                  type: string
```

The tool will accept `body_name` and `body_tag` parameters, which are reassembled into the request body:

```typescript
// LLM calls tool with: { body_name: "Fido", body_tag: "dog" }
// Request body sent:   { name: "Fido", tag: "dog" }
```

## `$ref` Resolution

`fromOpenAPI` fully resolves `$ref` references within the spec, including:

- Schema references (`$ref: "#/components/schemas/Pet"`)
- Parameter references (`$ref: "#/components/parameters/PetId"`)
- Request body references (`$ref: "#/components/requestBodies/PetBody"`)

Circular references are handled gracefully.

## Full Example: Petstore API

```typescript
import { FastMCP } from "fastmcp";
import { fromOpenAPI } from "fastmcp/openapi";

const petstoreSpec = {
  openapi: "3.0.0",
  info: { title: "Petstore", version: "1.0.0" },
  servers: [{ url: "https://petstore.example.com" }],
  paths: {
    "/pets": {
      get: {
        operationId: "listPets",
        summary: "List all pets",
        parameters: [
          { name: "limit", in: "query", schema: { type: "integer" } },
        ],
      },
      post: {
        operationId: "createPet",
        summary: "Create a pet",
        requestBody: {
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  tag: { type: "string" },
                },
                required: ["name"],
              },
            },
          },
        },
      },
    },
    "/pets/{petId}": {
      get: {
        operationId: "getPet",
        summary: "Get a pet by ID",
        parameters: [
          { name: "petId", in: "path", required: true, schema: { type: "string" } },
        ],
      },
    },
  },
};

const { tools, resources, resourceTemplates } = fromOpenAPI({
  spec: petstoreSpec,
  client: {
    request: async (config) => {
      const res = await fetch(config.url, {
        method: config.method,
        headers: config.headers,
        body: config.body ? JSON.stringify(config.body) : undefined,
      });
      return { status: res.status, data: await res.json() };
    },
  },
});

const server = new FastMCP({ name: "Petstore MCP", version: "1.0.0" });

// Registers: listPets (resource), getPet (resource template), createPet (tool)
for (const tool of tools) server.addTool(tool);
for (const resource of resources) server.addResource(resource);
for (const template of resourceTemplates) server.addResourceTemplate(template);

server.start({ transportType: "stdio" });
```

## API Reference

### `fromOpenAPI(options)`

Converts an OpenAPI spec into FastMCP-compatible definitions.

**Parameters:**
- `options.spec` — `OpenAPIDocument` — Parsed OpenAPI 3.x spec
- `options.client` — `HttpClient` — HTTP client for making requests
- `options.baseUrl` — `string` (optional) — Override the API base URL
- `options.headers` — `Record<string, string>` (optional) — Default request headers

**Returns:**
```typescript
{
  tools: Array<{
    name: string;
    description: string;
    parameters: JsonSchema;
    execute: (args: Record<string, unknown>) => Promise<{ content: Array<{ text: string; type: "text" }> }>;
  }>;
  resources: Array<{
    name: string;
    description: string;
    uri: string;
    read: () => Promise<{ text: string }>;
  }>;
  resourceTemplates: Array<{
    name: string;
    description: string;
    uriTemplate: string;
    read: (args: Record<string, unknown>) => Promise<{ text: string }>;
  }>;
}
```

### Exported Types

```typescript
import type { FromOpenAPIOptions, HttpClient } from "fastmcp/openapi";
import type { OpenAPIDocument, OpenAPIRoute } from "fastmcp/openapi";
```
