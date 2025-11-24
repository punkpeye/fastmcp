# FastMCP

A TypeScript framework for building [MCP](https://glama.ai/mcp) servers capable of handling client sessions.

> [!NOTE]
>
> For a Python implementation, see [FastMCP](https://github.com/jlowin/fastmcp).

## Table of Contents

- [Getting Started](#getting-started)
  - [What is FastMCP?](#what-is-fastmcp)
  - [When to use FastMCP over the official SDK?](#when-to-use-fastmcp-over-the-official-sdk)
  - [Installation](#installation)
  - [Quickstart](#quickstart)
- [Core Concepts](#core-concepts)
  - [Tools](#tools)
  - [Resources](#resources)
  - [Prompts](#prompts)
  - [Server Configuration](#server-configuration)
- [Advanced Features](#advanced-features)
  - [Authentication](#authentication)
  - [Sessions and Context](#sessions-and-context)
  - [Advanced Tool Features](#advanced-tool-features)
  - [FastMCPSession API](#fastmcpsession-api)
- [Deployment & Testing](#deployment--testing)
  - [Transport Options](#transport-options)
  - [Testing and Debugging](#testing-and-debugging)
  - [Claude Desktop Integration](#claude-desktop-integration)
  - [Proxy Configuration](#proxy-configuration)
- [Reference](#reference)
  - [Showcase](#showcase)
  - [Acknowledgements](#acknowledgements)

## Getting Started

### What is FastMCP?

FastMCP is a batteries-included framework for building MCP (Model Context Protocol) servers in TypeScript. It provides:

- **Simple, intuitive APIs** for defining Tools, Resources, and Prompts
- **Built-in authentication** with OAuth and session support
- **Multiple transport options** (stdio, HTTP streaming, SSE)
- **Session management** with state tracking and context passing
- **Rich content support** (images, audio, embedded resources)
- **Developer experience** features (typed events, progress notifications, streaming)
- **Production-ready** capabilities (error handling, logging, health checks)

### When to use FastMCP over the official SDK?

FastMCP is built on top of the official SDK.

The official SDK provides foundational blocks for building MCPs, but leaves many implementation details to you:

- [Initiating and configuring](https://github.com/punkpeye/fastmcp/blob/06c2af7a3d7e3d8c638deac1964ce269ce8e518b/src/FastMCP.ts#L664-L744) all the server components
- [Handling of connections](https://github.com/punkpeye/fastmcp/blob/06c2af7a3d7e3d8c638deac1964ce269ce8e518b/src/FastMCP.ts#L760-L850)
- [Handling of tools](https://github.com/punkpeye/fastmcp/blob/06c2af7a3d7e3d8c638deac1964ce269ce8e518b/src/FastMCP.ts#L1303-L1498)
- [Handling of responses](https://github.com/punkpeye/fastmcp/blob/06c2af7a3d7e3d8c638deac1964ce269ce8e518b/src/FastMCP.ts#L989-L1060)
- [Handling of resources](https://github.com/punkpeye/fastmcp/blob/06c2af7a3d7e3d8c638deac1964ce269ce8e518b/src/FastMCP.ts#L1151-L1242)
- Adding [prompts](https://github.com/punkpeye/fastmcp/blob/06c2af7a3d7e3d8c638deac1964ce269ce8e518b/src/FastMCP.ts#L760-L850), [resources](https://github.com/punkpeye/fastmcp/blob/06c2af7a3d7e3d8c638deac1964ce269ce8e518b/src/FastMCP.ts#L960-L962), [resource templates](https://github.com/punkpeye/fastmcp/blob/06c2af7a3d7e3d8c638deac1964ce269ce8e518b/src/FastMCP.ts#L964-L987)
- Embedding [resources](https://github.com/punkpeye/fastmcp/blob/06c2af7a3d7e3d8c638deac1964ce269ce8e518b/src/FastMCP.ts#L1569-L1643), [image](https://github.com/punkpeye/fastmcp/blob/06c2af7a3d7e3d8c638deac1964ce269ce8e518b/src/FastMCP.ts#L51-L111) and [audio](https://github.com/punkpeye/fastmcp/blob/06c2af7a3d7e3d8c638deac1964ce269ce8e518b/src/FastMCP.ts#L113-L173) content blocks

FastMCP eliminates this complexity by providing an opinionated framework that:

- Handles all the boilerplate automatically
- Provides simple, intuitive APIs for common tasks
- Includes built-in best practices and error handling
- Lets you focus on your MCP's core functionality

**When to choose FastMCP:** You want to build MCP servers quickly without dealing with low-level implementation details.

**When to use the official SDK:** You need maximum control or have specific architectural requirements. In this case, we encourage referencing FastMCP's implementation to avoid common pitfalls.

### Installation

```bash
npm install fastmcp
```

### Quickstart

> [!NOTE]
>
> For real-world examples, see the [Showcase](#showcase). For a boilerplate repository, check out [fastmcp-boilerplate](https://github.com/punkpeye/fastmcp-boilerplate).

```ts
import { FastMCP } from "fastmcp";
import { z } from "zod";

const server = new FastMCP({
  name: "My Server",
  version: "1.0.0",
});

server.addTool({
  name: "add",
  description: "Add two numbers",
  parameters: z.object({
    a: z.number(),
    b: z.number(),
  }),
  execute: async (args) => {
    return String(args.a + args.b);
  },
});

server.start({
  transportType: "stdio",
});
```

_That's it!_ You have a working MCP server.

Test it locally:

```bash
git clone https://github.com/punkpeye/fastmcp.git
cd fastmcp
pnpm install
pnpm build

# Test using CLI:
npx fastmcp dev src/examples/addition.ts
# Test using MCP Inspector:
npx fastmcp inspect src/examples/addition.ts
```

## Core Concepts

### Tools

[Tools](https://modelcontextprotocol.io/docs/concepts/tools) allow servers to expose executable functions that clients and LLMs can invoke to perform actions.

#### Schema Validation

FastMCP uses the [Standard Schema](https://standardschema.dev) specification, supporting any validation library that implements the spec (Zod, ArkType, Valibot).

**Zod Example:**

```typescript
import { z } from "zod";

server.addTool({
  name: "fetch-zod",
  description: "Fetch the content of a url",
  parameters: z.object({
    url: z.string(),
  }),
  execute: async (args) => {
    return await fetchWebpageContent(args.url);
  },
});
```

**ArkType Example:**

```typescript
import { type } from "arktype";

server.addTool({
  name: "fetch-arktype",
  description: "Fetch the content of a url",
  parameters: type({
    url: "string",
  }),
  execute: async (args) => {
    return await fetchWebpageContent(args.url);
  },
});
```

**Valibot Example:**

Valibot requires the peer dependency @valibot/to-json-schema.

```typescript
import * as v from "valibot";

server.addTool({
  name: "fetch-valibot",
  description: "Fetch the content of a url",
  parameters: v.object({
    url: v.string(),
  }),
  execute: async (args) => {
    return await fetchWebpageContent(args.url);
  },
});
```

#### Tools Without Parameters

Omit the parameters property or use an empty object:

```typescript
server.addTool({
  name: "sayHello",
  description: "Say hello",
  execute: async () => {
    return "Hello, world!";
  },
});
```

#### Return Types

Tools can return various content types. FastMCP provides helpers for common formats.

**String:**

```js
server.addTool({
  name: "download",
  description: "Download a file",
  parameters: z.object({ url: z.string() }),
  execute: async (args) => {
    return "Hello, world!";
  },
});
```

**List of Messages:**

```js
server.addTool({
  name: "download",
  description: "Download a file",
  parameters: z.object({ url: z.string() }),
  execute: async (args) => {
    return {
      content: [
        { type: "text", text: "First message" },
        { type: "text", text: "Second message" },
      ],
    };
  },
});
```

**Image:**

```js
import { imageContent } from "fastmcp";

server.addTool({
  name: "download",
  description: "Download a file",
  parameters: z.object({ url: z.string() }),
  execute: async (args) => {
    return imageContent({
      url: "https://example.com/image.png",
      // or path: "/path/to/image.png"
      // or buffer: Buffer.from("...", "base64")
    });
  },
});
```

**Audio:**

```js
import { audioContent } from "fastmcp";

server.addTool({
  name: "download",
  description: "Download audio",
  parameters: z.object({ url: z.string() }),
  execute: async (args) => {
    return audioContent({
      url: "https://example.com/audio.mp3",
      // or path: "/path/to/audio.mp3"
      // or buffer: Buffer.from("...", "base64")
    });
  },
});
```

**Combined Types:**

```js
server.addTool({
  name: "download",
  description: "Download a file",
  parameters: z.object({ url: z.string() }),
  execute: async (args) => {
    return {
      content: [
        { type: "text", text: "Download complete!" },
        await imageContent({ url: "https://example.com/preview.png" }),
        await audioContent({ url: "https://example.com/sound.mp3" }),
      ],
    };
  },
});
```

### Resources

[Resources](https://modelcontextprotocol.io/docs/concepts/resources) allow servers to expose data and content that can be read by clients and used as context for LLMs.

#### Direct Resources

```ts
server.addResource({
  uri: "config://app",
  name: "App Configuration",
  mimeType: "application/json",
  description: "Application settings and preferences",
  async load() {
    return {
      text: JSON.stringify({
        theme: "dark",
        language: "en",
      }),
    };
  },
});
```

Resources can also return binary content:

```ts
async load() {
  return {
    blob: 'base64-encoded-data'
  };
}
```

#### Resource Templates

Define resources with dynamic URI patterns:

```ts
server.addResourceTemplate({
  uriTemplate: "file:///logs/{name}.log",
  name: "Application Logs",
  mimeType: "text/plain",
  arguments: [
    {
      name: "name",
      description: "Name of the log",
      required: true,
    },
  ],
  async load({ name }) {
    return {
      text: `Example log content for ${name}`,
    };
  },
});
```

**Auto-completion:**

```ts
server.addResourceTemplate({
  uriTemplate: "file:///logs/{name}.log",
  name: "Application Logs",
  mimeType: "text/plain",
  arguments: [
    {
      name: "name",
      description: "Name of the log",
      required: true,
      complete: async (value) => {
        if (value === "Example") {
          return { values: ["Example Log"] };
        }
        return { values: [] };
      },
    },
  ],
  async load({ name }) {
    return {
      text: `Example log content for ${name}`,
    };
  },
});
```

#### Embedded Resources

Use `embedded()` to reference resources within tool responses:

```ts
server.addTool({
  name: "get_user_data",
  description: "Retrieve user information",
  parameters: z.object({ userId: z.string() }),
  execute: async (args) => {
    return {
      content: [
        {
          type: "resource",
          resource: await server.embedded(`user://profile/${args.userId}`),
        },
      ],
    };
  },
});
```

### Prompts

[Prompts](https://modelcontextprotocol.io/docs/concepts/prompts) enable servers to define reusable prompt templates and workflows.

```ts
server.addPrompt({
  name: "git-commit",
  description: "Generate a Git commit message",
  arguments: [
    {
      name: "changes",
      description: "Git diff or description of changes",
      required: true,
    },
  ],
  load: async (args) => {
    return `Generate a concise but descriptive commit message for these changes:\n\n${args.changes}`;
  },
});
```

**Auto-completion with custom function:**

```js
server.addPrompt({
  name: "countryPoem",
  description: "Writes a poem about a country",
  arguments: [
    {
      name: "name",
      description: "Name of the country",
      required: true,
      complete: async (value) => {
        if (value === "Germ") {
          return {
            values: ["Germany"],
          };
        }

        return {
          values: [],
        };
      },
    },
  ],
  load: async ({ name }) => {
    return `Write a poem about ${name}`;
  },
});
```

**Auto-completion using `enum`:**

```js
server.addPrompt({
  name: "countryPoem",
  description: "Writes a poem about a country",
  arguments: [
    {
      name: "name",
      description: "Name of the country",
      required: true,
      enum: ["Germany", "France", "Italy"],
    },
  ],
  load: async ({ name }) => {
    return `Write a poem about ${name}`;
  },
});
```

### Server Configuration

#### Logging

**Custom Logger:**

```ts
import { FastMCP, Logger } from "fastmcp";

class CustomLogger implements Logger {
  debug(...args: unknown[]): void {
    console.log("[DEBUG]", new Date().toISOString(), ...args);
  }
  error(...args: unknown[]): void {
    console.error("[ERROR]", new Date().toISOString(), ...args);
  }
  info(...args: unknown[]): void {
    console.info("[INFO]", new Date().toISOString(), ...args);
  }
  log(...args: unknown[]): void {
    console.log("[LOG]", new Date().toISOString(), ...args);
  }
  warn(...args: unknown[]): void {
    console.warn("[WARN]", new Date().toISOString(), ...args);
  },
}

const server = new FastMCP({
  name: "My Server",
  version: "1.0.0",
  logger: new CustomLogger(),
});
```

See `src/examples/custom-logger.ts` for Winston, Pino, and file-based logging examples.

**Tool Logging:**

Tools can log messages to the client:

```js
server.addTool({
  name: "download",
  description: "Download a file",
  parameters: z.object({ url: z.string() }),
  execute: async (args, { log }) => {
    log.info("Downloading file...", { url: args.url });
    // ...
    log.info("Downloaded file");
    return "done";
  },
});
```

Log methods: `debug()`, `error()`, `info()`, `warn()`

#### Error Handling

Throw `UserError` for user-facing errors:

```js
import { UserError } from "fastmcp";

server.addTool({
  name: "download",
  description: "Download a file",
  parameters: z.object({ url: z.string() }),
  execute: async (args) => {
    if (args.url.startsWith("https://example.com")) {
      throw new UserError("This URL is not allowed");
    }
    return "done";
  },
});
```

#### Progress Notifications

```js
server.addTool({
  name: "download",
  description: "Download a file",
  parameters: z.object({ url: z.string() }),
  execute: async (args, { reportProgress }) => {
    reportProgress({
      progress: 50,
      total: 100,
    });
    return "done";
  },
});
```

#### Streaming Output

FastMCP supports streaming partial results from tools while they're executing, enabling responsive UIs and real-time feedback. This is useful for:

- Long-running operations that generate content incrementally
- Progressive generation of text, images, or other media
- Operations where users benefit from seeing immediate partial results

**Basic streaming with `createTextStream`:**

```js
server.addTool({
  name: "stream",
  description: "Stream data",
  parameters: z.object({}),
  execute: async (args, context) => {
    const stream = context.createTextStream();
    stream.write("Hello");
    stream.write(" World");
    stream.close();
    return stream;
  },
});
```

**Advanced streaming with `streamContent` and `streamingHint` annotation:**

```js
server.addTool({
  name: "generateText",
  description: "Generate text incrementally",
  parameters: z.object({
    prompt: z.string(),
  }),
  annotations: {
    streamingHint: true, // Signals this tool uses streaming
    readOnlyHint: true,
  },
  execute: async (args, { streamContent }) => {
    // Send initial content immediately
    await streamContent({ type: "text", text: "Starting generation...\n" });

    // Simulate incremental content generation
    const words = "The quick brown fox jumps over the lazy dog.".split(" ");
    for (const word of words) {
      await streamContent({ type: "text", text: word + " " });
      await new Promise((resolve) => setTimeout(resolve, 300));
    }

    // When using streamContent, you can:
    // 1. Return void (if all content was streamed)
    // 2. Return a final result (appended to streamed content)
    return;
  },
});
```

**Combining streaming with progress reporting:**

```js
server.addTool({
  name: "processData",
  description: "Process data with streaming updates",
  parameters: z.object({
    datasetSize: z.number(),
  }),
  annotations: {
    streamingHint: true,
  },
  execute: async (args, { streamContent, reportProgress }) => {
    const total = args.datasetSize;

    for (let i = 0; i < total; i++) {
      // Report numeric progress
      await reportProgress({ progress: i, total });

      // Stream intermediate results
      if (i % 10 === 0) {
        await streamContent({
          type: "text",
          text: `Processed ${i} of ${total} items...\n`,
        });
      }

      await new Promise((resolve) => setTimeout(resolve, 50));
    }

    return "Processing complete!";
  },
});
```

#### Server Instructions

Provide hints to LLMs about your server:

```ts
const server = new FastMCP({
  name: "My Server",
  version: "1.0.0",
  instructions:
    "Instructions describing how to use the server and its features.\n\nThis can be added to the system prompt to improve the LLM's understanding.",
});
```

#### Ping Configuration

```ts
const server = new FastMCP({
  name: "My Server",
  version: "1.0.0",
  ping: {
    enabled: true, // Defaults vary by transport
    intervalMs: 10000, // Default: 5000ms
    logLevel: "debug", // Default: 'debug'
  },
});
```

Default behavior:

- Enabled for SSE and HTTP streaming
- Disabled for stdio

#### Health Check Endpoint

When using HTTP streaming, expose a health endpoint:

```ts
const server = new FastMCP({
  name: "My Server",
  version: "1.0.0",
  health: {
    enabled: true, // Default: true
    message: "healthy", // Default: 'ok'
    path: "/healthz", // Default: '/health'
    status: 200, // Default: 200
  },
});

await server.start({
  transportType: "httpStream",
  httpStream: { port: 8080 },
});
```

Returns: `HTTP/1.1 200 OK` with `healthy` body at `http://localhost:8080/healthz`

#### Roots Management

[Roots](https://modelcontextprotocol.io/docs/concepts/roots) allow clients to provide filesystem-like root locations:

```ts
const server = new FastMCP({
  name: "My Server",
  version: "1.0.0",
  roots: {
    enabled: true, // Default: true
  },
});
```

Listen for root changes:

```ts
server.on("connect", (event) => {
  const session = event.session;
  console.log("Initial roots:", session.roots);

  session.on("rootsChanged", (event) => {
    console.log("Roots changed:", event.roots);
  });
});
```

## Advanced Features

### Authentication

FastMCP supports session-based authentication with OAuth.

#### Basic Authentication

```ts
const server = new FastMCP({
  name: "My Server",
  version: "1.0.0",
  authenticate: (request) => {
    const apiKey = request.headers["x-api-key"];

    if (apiKey !== "123") {
      throw new Response(null, {
        status: 401,
        statusText: "Unauthorized",
      });
    }

    return { id: 1 };
  },
});
```

Access authenticated data in tools:

```ts
server.addTool({
  name: "sayHello",
  execute: async (args, { session }) => {
    return `Hello, ${session.id}!`;
  },
});
```

#### Tool Authorization

Control tool access with `canAccess`:

```typescript
const server = new FastMCP<{ role: "admin" | "user" }>({
  authenticate: async (request) => {
    const role = request.headers["x-role"] as string;
    return { role: role === "admin" ? "admin" : "user" };
  },
  name: "My Server",
  version: "1.0.0",
});

server.addTool({
  name: "admin-dashboard",
  description: "An admin-only tool",
  canAccess: (auth) => auth?.role === "admin",
  execute: async () => "Welcome to the admin dashboard!",
});
```

#### OAuth Support

FastMCP includes built-in OAuth discovery endpoints (RFC 8414, RFC 9470):

```ts
import { FastMCP, DiscoveryDocumentCache } from "fastmcp";
import { buildGetJwks } from "get-jwks";
import fastJwt from "fast-jwt";

const discoveryCache = new DiscoveryDocumentCache({
  ttl: 3600000, // 1 hour
});

const server = new FastMCP({
  name: "My Server",
  version: "1.0.0",
  oauth: {
    enabled: true,
    authorizationServer: {
      issuer: "https://auth.example.com",
      authorizationEndpoint: "https://auth.example.com/oauth/authorize",
      tokenEndpoint: "https://auth.example.com/oauth/token",
      jwksUri: "https://auth.example.com/.well-known/jwks.json",
      responseTypesSupported: ["code"],
    },
    protectedResource: {
      resource: "mcp://my-server",
      authorizationServers: ["https://auth.example.com"],
    },
  },
  authenticate: async (request) => {
    const authHeader = request.headers.authorization;

    if (!authHeader?.startsWith("Bearer ")) {
      throw new Response(null, {
        status: 401,
        statusText: "Missing or invalid authorization header",
      });
    }

    const token = authHeader.slice(7);

    try {
      const config = (await discoveryCache.get(
        "https://auth.example.com/.well-known/openid-configuration",
      )) as { jwks_uri: string; issuer: string };

      const getJwks = buildGetJwks({
        jwksUrl: config.jwks_uri,
        cache: true,
        rateLimit: true,
      });

      const verify = fastJwt.createVerifier({
        key: async (token) => {
          const { header } = fastJwt.decode(token, { complete: true });
          const jwk = await getJwks.getJwk({
            kid: header.kid,
            alg: header.alg,
          });
          return jwk;
        },
        algorithms: ["RS256", "ES256"],
        issuer: config.issuer,
        audience: "mcp://my-server",
      });

      const payload = await verify(token);

      return {
        userId: payload.sub,
        scope: payload.scope,
        email: payload.email,
      };
    } catch (error) {
      throw new Response(null, {
        status: 401,
        statusText: "Invalid OAuth token",
      });
    }
  },
});
```

Exposes:

- `/.well-known/oauth-authorization-server` - Authorization server metadata
- `/.well-known/oauth-protected-resource` - Protected resource metadata

### Sessions and Context

#### Passing Headers Through Context

Capture HTTP headers for API key passthrough:

```ts
import { FastMCP } from "fastmcp";
import { IncomingHttpHeaders } from "http";

interface SessionData {
  headers: IncomingHttpHeaders;
  [key: string]: unknown;
}

const server = new FastMCP({
  name: "My Server",
  version: "1.0.0",
  authenticate: async (request: any): Promise<SessionData> => {
    return {
      headers: request.headers,
    };
  },
});

server.addTool({
  name: "headerTool",
  description: "Reads HTTP headers from the request",
  execute: async (args: any, context: any) => {
    const session = context.session as SessionData;
    const headers = session?.headers ?? {};
    return `Authorization: ${headers["authorization"] ?? "N/A"}`;
  },
});
```

#### Session ID and Request ID Tracking

FastMCP exposes session and request IDs for state management:

```ts
import { FastMCP } from "fastmcp";
import { z } from "zod";

const server = new FastMCP({
  name: "Session Counter Server",
  version: "1.0.0",
});

const sessionCounters = new Map<string, number>();

server.addTool({
  name: "increment_counter",
  description: "Increment a per-session counter",
  parameters: z.object({}),
  execute: async (args, context) => {
    if (!context.sessionId) {
      return "Session ID not available (requires HTTP transport)";
    }

    const counter = sessionCounters.get(context.sessionId) || 0;
    const newCounter = counter + 1;
    sessionCounters.set(context.sessionId, newCounter);

    return `Counter for session ${context.sessionId}: ${newCounter}`;
  },
});
```

**Properties:**

- `context.sessionId`: Constant across requests from the same client (HTTP only)
- `context.requestId`: Unique per request

**Use Cases:**

- Per-session state management
- User authentication tracking
- Session-specific resource management
- Multi-tenant implementations
- Request tracing

See [`src/examples/session-id-counter.ts`](src/examples/session-id-counter.ts) for a complete example.

#### Session Management

The `sessions` property lists active client sessions:

```ts
server.sessions;
```

Each connection creates a new `FastMCPSession` instance for 1:1 communication.

#### Typed Server Events

```ts
server.on("connect", (event) => {
  console.log("Client connected:", event.session);
});

server.on("disconnect", (event) => {
  console.log("Client disconnected:", event.session);
});
```

### Advanced Tool Features

See [Core Concepts > Tools](#tools) for basic tool usage. This section covers advanced features.

For return types (string, list, image, audio, combinations), see [Return Types](#return-types).

For tool authorization, see [Authentication > Tool Authorization](#tool-authorization).

#### Tool Annotations

As of the MCP Specification (2025-03-26), tools can include annotations that provide richer context and control by adding metadata about a tool's behavior:

```typescript
server.addTool({
  name: "fetch-content",
  description: "Fetch content from a URL",
  parameters: z.object({
    url: z.string(),
  }),
  annotations: {
    title: "Web Content Fetcher", // Human-readable title for UI display
    readOnlyHint: true, // Tool doesn't modify its environment
    openWorldHint: true, // Tool interacts with external entities
  },
  execute: async (args) => {
    return await fetchWebpageContent(args.url);
  },
});
```

The available annotations are:

| Annotation        | Type      | Default | Description                                                                                                                              |
| :---------------- | :-------- | :------ | :--------------------------------------------------------------------------------------------------------------------------------------- |
| `title`           | `string`  | -       | A human-readable title for the tool, useful for UI display                                                                               |
| `readOnlyHint`    | `boolean` | `false` | If `true`, indicates the tool does not modify its environment                                                                            |
| `destructiveHint` | `boolean` | `true`  | The tool may perform destructive updates (only meaningful when `readOnlyHint` is `false`)                                                |
| `idempotentHint`  | `boolean` | `false` | If `true`, calling the tool repeatedly with the same arguments has no additional effect (only meaningful when `readOnlyHint` is `false`) |
| `openWorldHint`   | `boolean` | `true`  | The tool may interact with an "open world" of external entities                                                                          |
| `streamingHint`   | `boolean` | `false` | If `true`, the tool leverages incremental content streaming. Return `void` for tools that handle all their output via streaming          |

These annotations help clients and LLMs better understand how to use the tools and what to expect when calling them.

### FastMCPSession API

`FastMCPSession` represents a client session and provides methods to interact with the client.

Access sessions via:

```ts
server.sessions;
// or
server.on("connect", (event) => {
  const session = event.session;
});
```

#### `requestSampling`

Create a [sampling](https://modelcontextprotocol.io/docs/concepts/sampling) request:

```ts
await session.requestSampling({
  messages: [
    {
      role: "user",
      content: {
        type: "text",
        text: "What files are in the current directory?",
      },
    },
  ],
  systemPrompt: "You are a helpful file system assistant.",
  includeContext: "thisServer",
  maxTokens: 100,
});
```

**Options:**

```ts
await session.requestSampling(
  {
    messages: [...],
    systemPrompt: "...",
    includeContext: "thisServer",
    maxTokens: 100,
  },
  {
    onprogress: (progress) => {
      console.log(`Progress: ${progress.progress}/${progress.total}`);
    },
    signal: abortController.signal,
    timeout: 30000, // Default: DEFAULT_REQUEST_TIMEOUT_MSEC
    resetTimeoutOnProgress: true, // Default: false
    maxTotalTimeout: 60000,
  },
);
```

#### Properties

- `session.clientCapabilities` - Client capabilities
- `session.loggingLevel` - Logging level set by client
- `session.roots` - Roots set by client
- `session.server` - Associated MCP server instance

#### Typed Session Events

```ts
session.on("rootsChanged", (event) => {
  console.log("Roots changed:", event.roots);
});

session.on("error", (event) => {
  console.error("Session error:", event.error);
});
```

## Deployment & Testing

### Transport Options

#### stdio Transport

For local development and Claude Desktop integration:

```ts
server.start({
  transportType: "stdio",
});
```

#### HTTP Streaming

[HTTP streaming](https://www.cloudflare.com/learning/video/what-is-http-live-streaming/) provides efficient transport for remote servers:

```ts
server.start({
  transportType: "httpStream",
  httpStream: {
    port: 8080,
    endpoint: "/mcp", // Default
  },
});
```

Starts servers at:

- `http://localhost:8080/mcp` (HTTP streaming)
- `http://localhost:8080/sse` (SSE)

**Client Connection (HTTP Streaming):**

```ts
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const client = new Client(
  {
    name: "example-client",
    version: "1.0.0",
  },
  {
    capabilities: {},
  },
);

const transport = new StreamableHTTPClientTransport(
  new URL(`http://localhost:8080/mcp`),
);

await client.connect(transport);
```

**Client Connection (SSE):**

```ts
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";

const transport = new SSEClientTransport(new URL(`http://localhost:8080/sse`));
await client.connect(transport);
```

#### Stateless Mode

For serverless deployments without persistent sessions:

```ts
server.start({
  transportType: "httpStream",
  httpStream: {
    port: 8080,
    stateless: true,
  },
});
```

Benefits:

- No session tracking
- Reduced memory usage
- Better scalability
- Ideal for serverless environments

Enable via CLI:

```bash
# Via CLI argument
npx fastmcp dev src/server.ts --transport http-stream --port 8080 --stateless true

# Via environment variable
FASTMCP_STATELESS=true npx fastmcp dev src/server.ts
```

Health check response:

```json
{
  "mode": "stateless",
  "ready": 1,
  "status": "ready",
  "total": 1
}
```

### Testing and Debugging

#### Test with MCP CLI

```bash
npx fastmcp dev src/examples/addition.ts
```

#### Inspect with MCP Inspector

```bash
npx fastmcp inspect src/examples/addition.ts
```

### Claude Desktop Integration

Add to Claude Desktop configuration:

```json
{
  "mcpServers": {
    "my-mcp-server": {
      "command": "npx",
      "args": ["tsx", "/PATH/TO/YOUR_PROJECT/src/index.ts"],
      "env": {
        "YOUR_ENV_VAR": "value"
      }
    }
  }
}
```

Follow the [MCP quickstart guide](https://modelcontextprotocol.io/quickstart/user) for detailed setup instructions.

### Proxy Configuration

To run FastMCP behind a proxy with Express, see [this example](https://github.com/punkpeye/fastmcp/issues/25#issuecomment-3004568732) using `http-proxy-middleware`.

## Reference

### Showcase

> [!NOTE]
>
> If you've developed a server using FastMCP, please [submit a PR](https://github.com/punkpeye/fastmcp) to showcase it here!

- [apinetwork/piapi-mcp-server](https://github.com/apinetwork/piapi-mcp-server) - generate media using Midjourney/Flux/Kling/LumaLabs/Udio/Chrip/Trellis
- [domdomegg/computer-use-mcp](https://github.com/domdomegg/computer-use-mcp) - controls your computer
- [LiterallyBlah/Dradis-MCP](https://github.com/LiterallyBlah/Dradis-MCP) – manages projects and vulnerabilities in Dradis
- [Meeting-Baas/meeting-mcp](https://github.com/Meeting-Baas/meeting-mcp) - create meeting bots, search transcripts, and manage recording data
- [drumnation/unsplash-smart-mcp-server](https://github.com/drumnation/unsplash-smart-mcp-server) – enables AI agents to seamlessly search, recommend, and deliver professional stock photos from Unsplash
- [ssmanji89/halopsa-workflows-mcp](https://github.com/ssmanji89/halopsa-workflows-mcp) - HaloPSA Workflows integration with AI assistants
- [aiamblichus/mcp-chat-adapter](https://github.com/aiamblichus/mcp-chat-adapter) – provides a clean interface for LLMs to use chat completion
- [eyaltoledano/claude-task-master](https://github.com/eyaltoledano/claude-task-master) – advanced AI project/task manager powered by FastMCP
- [cswkim/discogs-mcp-server](https://github.com/cswkim/discogs-mcp-server) - connects to the Discogs API for interacting with your music collection
- [Panzer-Jack/feuse-mcp](https://github.com/Panzer-Jack/feuse-mcp) - Frontend Useful MCP Tools - Essential utilities for web developers to automate API integration and code generation
- [sunra-ai/sunra-clients](https://github.com/sunra-ai/sunra-clients/tree/main/mcp-server) - Sunra.ai is a generative media platform built for developers, providing high-performance AI model inference capabilities.
- [foxtrottwist/shortcuts-mcp](https://github.com/foxtrottwist/shortcuts-mcp) - connects Claude to macOS Shortcuts for system automation, app integration, and interactive workflows

### Acknowledgements

- FastMCP is inspired by the [Python implementation](https://github.com/jlowin/fastmcp) by [Jonathan Lowin](https://github.com/jlowin).
- Parts of codebase were adopted from [LiteMCP](https://github.com/wong2/litemcp).
- Parts of codebase were adopted from [Model Context protocolでSSEをやってみる](https://dev.classmethod.jp/articles/mcp-sse/).
