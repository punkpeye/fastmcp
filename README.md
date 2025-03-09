# FastMCP

A TypeScript framework for building [MCP](https://glama.ai/mcp) servers capable of handling client sessions.

> [!NOTE]
>
> For a Python implementation, see [FastMCP](https://github.com/jlowin/fastmcp).

## Features

- Simple Tool, Resource, Prompt definition
- [Authentication](#authentication)
- [Sessions](#sessions)
- [Image content](#returning-an-image)
- [Logging](#logging)
- [Error handling](#errors)
- [SSE](#sse)
- CORS (enabled by default)
- [Progress notifications](#progress)
- [Typed server events](#typed-server-events)
- [Prompt argument auto-completion](#prompt-argument-auto-completion)
- [Sampling](#requestsampling)
- Automated SSE pings
- Roots
- CLI for [testing](#test-with-mcp-cli) and [debugging](#inspect-with-mcp-inspector)

## Installation

```bash
npm install fastmcp
```

## Quickstart

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

You can test the server in terminal with:

```bash
git clone https://github.com/punkpeye/fastmcp.git
cd fastmcp

npm install

# Test the addition server example using CLI:
npx fastmcp dev src/examples/addition.ts
# Test the addition server example using MCP Inspector:
npx fastmcp inspect src/examples/addition.ts
```

### SSE

You can also run the server with SSE support:

```ts
server.start({
  transportType: "sse",
  sse: {
    endpoint: "/sse",
    port: 8080,
  },
});
```

This will start the server and listen for SSE connections on `http://localhost:8080/sse`.

You can then use `SSEClientTransport` to connect to the server:

```ts
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";

const client = new Client(
  {
    name: "example-client",
    version: "1.0.0",
  },
  {
    capabilities: {},
  },
);

const transport = new SSEClientTransport(new URL(`http://localhost:8080/sse`));

await client.connect(transport);
```

## Core Concepts

### Tools

[Tools](https://modelcontextprotocol.io/docs/concepts/tools) in MCP allow servers to expose executable functions that can be invoked by clients and used by LLMs to perform actions.

```js
server.addTool({
  name: "fetch",
  description: "Fetch the content of a url",
  parameters: z.object({
    url: z.string(),
  }),
  execute: async (args) => {
    return await fetchWebpageContent(args.url);
  },
});
```

#### Returning a string

`execute` can return a string:

```js
server.addTool({
  name: "download",
  description: "Download a file",
  parameters: z.object({
    url: z.string(),
  }),
  execute: async (args) => {
    return "Hello, world!";
  },
});
```

The latter is equivalent to:

```js
server.addTool({
  name: "download",
  description: "Download a file",
  parameters: z.object({
    url: z.string(),
  }),
  execute: async (args) => {
    return {
      content: [
        {
          type: "text",
          text: "Hello, world!",
        },
      ],
    };
  },
});
```

#### Returning a list

If you want to return a list of messages, you can return an object with a `content` property:

```js
server.addTool({
  name: "download",
  description: "Download a file",
  parameters: z.object({
    url: z.string(),
  }),
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

#### Returning an image

Use the `imageContent` to create a content object for an image:

```js
import { imageContent } from "fastmcp";

server.addTool({
  name: "download",
  description: "Download a file",
  parameters: z.object({
    url: z.string(),
  }),
  execute: async (args) => {
    return imageContent({
      url: "https://example.com/image.png",
    });

    // or...
    // return imageContent({
    //   path: "/path/to/image.png",
    // });

    // or...
    // return imageContent({
    //   buffer: Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=", "base64"),
    // });

    // or...
    // return {
    //   content: [
    //     await imageContent(...)
    //   ],
    // };
  },
});
```

The `imageContent` function takes the following options:

- `url`: The URL of the image.
- `path`: The path to the image file.
- `buffer`: The image data as a buffer.

Only one of `url`, `path`, or `buffer` must be specified.

The above example is equivalent to:

```js
server.addTool({
  name: "download",
  description: "Download a file",
  parameters: z.object({
    url: z.string(),
  }),
  execute: async (args) => {
    return {
      content: [
        {
          type: "image",
          data: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
          mimeType: "image/png",
        },
      ],
    };
  },
});
```

#### Logging

Tools can log messages to the client using the `log` object in the context object:

```js
server.addTool({
  name: "download",
  description: "Download a file",
  parameters: z.object({
    url: z.string(),
  }),
  execute: async (args, { log }) => {
    log.info("Downloading file...", {
      url,
    });

    // ...

    log.info("Downloaded file");

    return "done";
  },
});
```

The `log` object has the following methods:

- `debug(message: string, data?: SerializableValue)`
- `error(message: string, data?: SerializableValue)`
- `info(message: string, data?: SerializableValue)`
- `warn(message: string, data?: SerializableValue)`

#### Errors

The errors that are meant to be shown to the user should be thrown as `UserError` instances:

```js
import { UserError } from "fastmcp";

server.addTool({
  name: "download",
  description: "Download a file",
  parameters: z.object({
    url: z.string(),
  }),
  execute: async (args) => {
    if (args.url.startsWith("https://example.com")) {
      throw new UserError("This URL is not allowed");
    }

    return "done";
  },
});
```

#### Progress

Tools can report progress by calling `reportProgress` in the context object:

```js
server.addTool({
  name: "download",
  description: "Download a file",
  parameters: z.object({
    url: z.string(),
  }),
  execute: async (args, { reportProgress }) => {
    reportProgress({
      progress: 0,
      total: 100,
    });

    // ...

    reportProgress({
      progress: 100,
      total: 100,
    });

    return "done";
  },
});
```

### Resources

[Resources](https://modelcontextprotocol.io/docs/concepts/resources) represent any kind of data that an MCP server wants to make available to clients. This can include:

- File contents
- Screenshots and images
- Log files
- And more

Each resource is identified by a unique URI and can contain either text or binary data.

```ts
server.addResource({
  uri: "file:///logs/app.log",
  name: "Application Logs",
  mimeType: "text/plain",
  async load() {
    return {
      text: await readLogFile(),
    };
  },
});
```

> [!NOTE]
>
> `load` can return multiple resources. This could be used, for example, to return a list of files inside a directory when the directory is read.
>
> ```ts
> async load() {
>   return [
>     {
>       text: "First file content",
>     },
>     {
>       text: "Second file content",
>     },
>   ];
> }
> ```

You can also return binary contents in `load`:

```ts
async load() {
  return {
    blob: 'base64-encoded-data'
  };
}
```

### Resource templates

You can also define resource templates:

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

#### Resource template argument auto-completion

Provide `complete` functions for resource template arguments to enable automatic completion:

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
          return {
            values: ["Example Log"],
          };
        }

        return {
          values: [],
        };
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

### Prompts

[Prompts](https://modelcontextprotocol.io/docs/concepts/prompts) enable servers to define reusable prompt templates and workflows that clients can easily surface to users and LLMs. They provide a powerful way to standardize and share common LLM interactions.

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

#### Prompt argument auto-completion

Prompts can provide auto-completion for their arguments:

```js
server.addPrompt({
  name: "countryPoem",
  description: "Writes a poem about a country",
  load: async ({ name }) => {
    return `Hello, ${name}!`;
  },
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
});
```

#### Prompt argument auto-completion using `enum`

If you provide an `enum` array for an argument, the server will automatically provide completions for the argument.

```js
server.addPrompt({
  name: "countryPoem",
  description: "Writes a poem about a country",
  load: async ({ name }) => {
    return `Hello, ${name}!`;
  },
  arguments: [
    {
      name: "name",
      description: "Name of the country",
      required: true,
      enum: ["Germany", "France", "Italy"],
    },
  ],
});
```

### Authentication

FastMCP allows you to `authenticate` clients using a custom function:

```ts
import { AuthError } from "fastmcp";

const server = new FastMCP({
  name: "My Server",
  version: "1.0.0",
  authenticate: ({request}) => {
    const apiKey = request.headers["x-api-key"];

    if (apiKey !== '123') {
      throw new Response(null, {
        status: 401,
        statusText: "Unauthorized",
      });
    }

    // Whatever you return here will be accessible in the `context.session` object.
    return {
      id: 1,
    }
  },
});
```

Now you can access the authenticated session data in your tools:

```ts
server.addTool({
  name: "sayHello",
  execute: async (args, { session }) => {
    return `Hello, ${session.id}!`;
  },
});
```

### Sessions

The `session` object is an instance of `FastMCPSession` and it describes active client sessions.

```ts
server.sessions;
```

We allocate a new server instance for each client connection to enable 1:1 communication between a client and the server.

### Typed server events

You can listen to events emitted by the server using the `on` method:

```ts
server.on("connect", (event) => {
  console.log("Client connected:", event.session);
});

server.on("disconnect", (event) => {
  console.log("Client disconnected:", event.session);
});
```

## `FastMCPSession`

`FastMCPSession` represents a client session and provides methods to interact with the client.

Refer to [Sessions](#sessions) for examples of how to obtain a `FastMCPSession` instance.

### `requestSampling`

`requestSampling` creates a [sampling](https://modelcontextprotocol.io/docs/concepts/sampling) request and returns the response.

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

### `clientCapabilities`

The `clientCapabilities` property contains the client capabilities.

```ts
session.clientCapabilities;
```

### `loggingLevel`

The `loggingLevel` property describes the logging level as set by the client.

```ts
session.loggingLevel;
```

### `roots`

The `roots` property contains the roots as set by the client.

```ts
session.roots;
```

### `server`

The `server` property contains an instance of MCP server that is associated with the session.

```ts
session.server;
```

### Typed session events

You can listen to events emitted by the session using the `on` method:

```ts
session.on("rootsChanged", (event) => {
  console.log("Roots changed:", event.roots);
});

session.on("error", (event) => {
  console.error("Error:", event.error);
});
```

## Running Your Server

### Test with `mcp-cli`

The fastest way to test and debug your server is with `fastmcp dev`:

```bash
npx fastmcp dev server.js
npx fastmcp dev server.ts
```

This will run your server with [`mcp-cli`](https://github.com/wong2/mcp-cli) for testing and debugging your MCP server in the terminal.

### Inspect with `MCP Inspector`

Another way is to use the official [`MCP Inspector`](https://modelcontextprotocol.io/docs/tools/inspector) to inspect your server with a Web UI:

```bash
npx fastmcp inspect server.ts
```

## Showcase

> [!NOTE]
>
> If you've developed a server using FastMCP, please [submit a PR](https://github.com/punkpeye/fastmcp) to showcase it here!

- https://github.com/apinetwork/piapi-mcp-server
- https://github.com/Meeting-Baas/meeting-mcp - Meeting BaaS MCP server that enables AI assistants to create meeting bots, search transcripts, and manage recording data

## Acknowledgements

- FastMCP is inspired by the [Python implementation](https://github.com/jlowin/fastmcp) by [Jonathan Lowin](https://github.com/jlowin).
- Parts of codebase were adopted from [LiteMCP](https://github.com/wong2/litemcp).
- Parts of codebase were adopted from [Model Context protocolでSSEをやってみる](https://dev.classmethod.jp/articles/mcp-sse/).
