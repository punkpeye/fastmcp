import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  CallToolRequestSchema,
  ClientCapabilities,
  CompleteRequestSchema,
  CreateMessageRequestSchema,
  ErrorCode,
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ListToolsRequestSchema,
  McpError,
  ReadResourceRequestSchema,
  Root,
  RootsListChangedNotificationSchema,
  ServerCapabilities,
  SetLevelRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { StandardSchemaV1 } from "@standard-schema/spec";
import { EventEmitter } from "events";
import { fileTypeFromBuffer } from "file-type";
import { readFile } from "fs/promises";
import Fuse from "fuse.js";
import http from "http";
import { startHTTPServer } from "mcp-proxy";
import { StrictEventEmitter } from "strict-event-emitter-types";
import { setTimeout as delay } from "timers/promises";
import { fetch } from "undici";
import parseURITemplate from "uri-templates";
import { toJsonSchema } from "xsschema";
import { z } from "zod";

export type SSEServer = {
  close: () => Promise<void>;
};

type FastMCPEvents<T extends FastMCPSessionAuth> = {
  connect: (event: { session: FastMCPSession<T> }) => void;
  disconnect: (event: { session: FastMCPSession<T> }) => void;
};

type FastMCPSessionEvents = {
  error: (event: { error: Error }) => void;
  ready: () => void;
  rootsChanged: (event: { roots: Root[] }) => void;
};

export const imageContent = async (
  input: { buffer: Buffer } | { path: string } | { url: string },
): Promise<ImageContent> => {
  let rawData: Buffer;

  try {
    if ("url" in input) {
      try {
        const response = await fetch(input.url);

        if (!response.ok) {
          throw new Error(
            `Server responded with status: ${response.status} - ${response.statusText}`,
          );
        }

        rawData = Buffer.from(await response.arrayBuffer());
      } catch (error) {
        throw new Error(
          `Failed to fetch image from URL (${input.url}): ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    } else if ("path" in input) {
      try {
        rawData = await readFile(input.path);
      } catch (error) {
        throw new Error(
          `Failed to read image from path (${input.path}): ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    } else if ("buffer" in input) {
      rawData = input.buffer;
    } else {
      throw new Error(
        "Invalid input: Provide a valid 'url', 'path', or 'buffer'",
      );
    }

    const mimeType = await fileTypeFromBuffer(rawData);

    if (!mimeType || !mimeType.mime.startsWith("image/")) {
      console.warn(
        `Warning: Content may not be a valid image. Detected MIME: ${mimeType?.mime || "unknown"}`,
      );
    }

    const base64Data = rawData.toString("base64");

    return {
      data: base64Data,
      mimeType: mimeType?.mime ?? "image/png",
      type: "image",
    } as const;
  } catch (error) {
    if (error instanceof Error) {
      throw error;
    } else {
      throw new Error(`Unexpected error processing image: ${String(error)}`);
    }
  }
};

export const audioContent = async (
  input: { buffer: Buffer } | { path: string } | { url: string },
): Promise<AudioContent> => {
  let rawData: Buffer;

  try {
    if ("url" in input) {
      try {
        const response = await fetch(input.url);

        if (!response.ok) {
          throw new Error(
            `Server responded with status: ${response.status} - ${response.statusText}`,
          );
        }

        rawData = Buffer.from(await response.arrayBuffer());
      } catch (error) {
        throw new Error(
          `Failed to fetch audio from URL (${input.url}): ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    } else if ("path" in input) {
      try {
        rawData = await readFile(input.path);
      } catch (error) {
        throw new Error(
          `Failed to read audio from path (${input.path}): ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    } else if ("buffer" in input) {
      rawData = input.buffer;
    } else {
      throw new Error(
        "Invalid input: Provide a valid 'url', 'path', or 'buffer'",
      );
    }

    const mimeType = await fileTypeFromBuffer(rawData);

    if (!mimeType || !mimeType.mime.startsWith("audio/")) {
      console.warn(
        `Warning: Content may not be a valid audio file. Detected MIME: ${mimeType?.mime || "unknown"}`,
      );
    }

    const base64Data = rawData.toString("base64");

    return {
      data: base64Data,
      mimeType: mimeType?.mime ?? "audio/mpeg",
      type: "audio",
    } as const;
  } catch (error) {
    if (error instanceof Error) {
      throw error;
    } else {
      throw new Error(`Unexpected error processing audio: ${String(error)}`);
    }
  }
};

type Context<T extends FastMCPSessionAuth> = {
  log: {
    debug: (message: string, data?: SerializableValue) => void;
    error: (message: string, data?: SerializableValue) => void;
    info: (message: string, data?: SerializableValue) => void;
    warn: (message: string, data?: SerializableValue) => void;
  };
  reportProgress: (progress: Progress) => Promise<void>;
  session: T | undefined;
  streamContent: (content: Content | Content[]) => Promise<void>;
};

type Extra = unknown;

type Extras = Record<string, Extra>;

type Literal = boolean | null | number | string | undefined;

type Progress = {
  /**
   * The progress thus far. This should increase every time progress is made, even if the total is unknown.
   */
  progress: number;
  /**
   * Total number of items to process (or total progress required), if known.
   */
  total?: number;
};

type SerializableValue =
  | { [key: string]: SerializableValue }
  | Literal
  | SerializableValue[];

type TextContent = {
  text: string;
  type: "text";
};

type ToolParameters = StandardSchemaV1;

abstract class FastMCPError extends Error {
  public constructor(message?: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class UnexpectedStateError extends FastMCPError {
  public extras?: Extras;

  public constructor(message: string, extras?: Extras) {
    super(message);
    this.name = new.target.name;
    this.extras = extras;
  }
}

/**
 * An error that is meant to be surfaced to the user.
 */
export class UserError extends UnexpectedStateError {}

const TextContentZodSchema = z
  .object({
    /**
     * The text content of the message.
     */
    text: z.string(),
    type: z.literal("text"),
  })
  .strict() satisfies z.ZodType<TextContent>;

type ImageContent = {
  data: string;
  mimeType: string;
  type: "image";
};

const ImageContentZodSchema = z
  .object({
    /**
     * The base64-encoded image data.
     */
    data: z.string().base64(),
    /**
     * The MIME type of the image. Different providers may support different image types.
     */
    mimeType: z.string(),
    type: z.literal("image"),
  })
  .strict() satisfies z.ZodType<ImageContent>;

type AudioContent = {
  data: string;
  mimeType: string;
  type: "audio";
};

const AudioContentZodSchema = z
  .object({
    /**
     * The base64-encoded audio data.
     */
    data: z.string().base64(),
    mimeType: z.string(),
    type: z.literal("audio"),
  })
  .strict() satisfies z.ZodType<AudioContent>;

type ResourceContent = {
  resource: {
    blob?: string;
    mimeType?: string;
    text?: string;
    uri: string;
  };
  type: "resource";
};

const ResourceContentZodSchema = z
  .object({
    resource: z.object({
      blob: z.string().optional(),
      mimeType: z.string().optional(),
      text: z.string().optional(),
      uri: z.string(),
    }),
    type: z.literal("resource"),
  })
  .strict() satisfies z.ZodType<ResourceContent>;

type Content = AudioContent | ImageContent | ResourceContent | TextContent;

const ContentZodSchema = z.discriminatedUnion("type", [
  TextContentZodSchema,
  ImageContentZodSchema,
  AudioContentZodSchema,
  ResourceContentZodSchema,
]) satisfies z.ZodType<Content>;

type ContentResult = {
  content: Content[];
  isError?: boolean;
};

const ContentResultZodSchema = z
  .object({
    content: ContentZodSchema.array(),
    isError: z.boolean().optional(),
  })
  .strict() satisfies z.ZodType<ContentResult>;

type Completion = {
  hasMore?: boolean;
  total?: number;
  values: string[];
};

/**
 * https://github.com/modelcontextprotocol/typescript-sdk/blob/3164da64d085ec4e022ae881329eee7b72f208d4/src/types.ts#L983-L1003
 */
const CompletionZodSchema = z.object({
  /**
   * Indicates whether there are additional completion options beyond those provided in the current response, even if the exact total is unknown.
   */
  hasMore: z.optional(z.boolean()),
  /**
   * The total number of completion options available. This can exceed the number of values actually sent in the response.
   */
  total: z.optional(z.number().int()),
  /**
   * An array of completion values. Must not exceed 100 items.
   */
  values: z.array(z.string()).max(100),
}) satisfies z.ZodType<Completion>;

type ArgumentValueCompleter = (value: string) => Promise<Completion>;

type InputPrompt<
  Arguments extends InputPromptArgument[] = InputPromptArgument[],
  Args = PromptArgumentsToObject<Arguments>,
> = {
  arguments?: InputPromptArgument[];
  description?: string;
  load: (args: Args) => Promise<string>;
  name: string;
};

type InputPromptArgument = Readonly<{
  complete?: ArgumentValueCompleter;
  description?: string;
  enum?: string[];
  name: string;
  required?: boolean;
}>;

type InputResourceTemplate<
  Arguments extends ResourceTemplateArgument[] = ResourceTemplateArgument[],
> = {
  arguments: Arguments;
  description?: string;
  load: (
    args: ResourceTemplateArgumentsToObject<Arguments>,
  ) => Promise<ResourceResult>;
  mimeType?: string;
  name: string;
  uriTemplate: string;
};

type InputResourceTemplateArgument = Readonly<{
  complete?: ArgumentValueCompleter;
  description?: string;
  name: string;
  required?: boolean;
}>;

type LoggingLevel =
  | "alert"
  | "critical"
  | "debug"
  | "emergency"
  | "error"
  | "info"
  | "notice"
  | "warning";

type Prompt<
  Arguments extends PromptArgument[] = PromptArgument[],
  Args = PromptArgumentsToObject<Arguments>,
> = {
  arguments?: PromptArgument[];
  complete?: (name: string, value: string) => Promise<Completion>;
  description?: string;
  load: (args: Args) => Promise<string>;
  name: string;
};

type PromptArgument = Readonly<{
  complete?: ArgumentValueCompleter;
  description?: string;
  enum?: string[];
  name: string;
  required?: boolean;
}>;

type PromptArgumentsToObject<T extends { name: string; required?: boolean }[]> =
  {
    [K in T[number]["name"]]: Extract<
      T[number],
      { name: K }
    >["required"] extends true
      ? string
      : string | undefined;
  };

type Resource = {
  complete?: (name: string, value: string) => Promise<Completion>;
  description?: string;
  load: () => Promise<ResourceResult | ResourceResult[]>;
  mimeType?: string;
  name: string;
  uri: string;
};

type ResourceResult =
  | {
      blob: string;
    }
  | {
      text: string;
    };

type ResourceTemplate<
  Arguments extends ResourceTemplateArgument[] = ResourceTemplateArgument[],
> = {
  arguments: Arguments;
  complete?: (name: string, value: string) => Promise<Completion>;
  description?: string;
  load: (
    args: ResourceTemplateArgumentsToObject<Arguments>,
  ) => Promise<ResourceResult>;
  mimeType?: string;
  name: string;
  uriTemplate: string;
};

type ResourceTemplateArgument = Readonly<{
  complete?: ArgumentValueCompleter;
  description?: string;
  name: string;
  required?: boolean;
}>;

type ResourceTemplateArgumentsToObject<T extends { name: string }[]> = {
  [K in T[number]["name"]]: string;
};

type ServerOptions<T extends FastMCPSessionAuth> = {
  authenticate?: Authenticate<T>;
  /**
   * Configuration for the health-check endpoint that can be exposed when the
   * server is running using the HTTP Stream transport. When enabled, the
   * server will respond to an HTTP GET request with the configured path (by
   * default "/health") rendering a plain-text response (by default "ok") and
   * the configured status code (by default 200).
   *
   * The endpoint is only added when the server is started with
   * `transportType: "httpStream"` – it is ignored for the stdio transport.
   */
  health?: {
    /**
     * When set to `false` the health-check endpoint is disabled.
     * @default true
     */
    enabled?: boolean;

    /**
     * Plain-text body returned by the endpoint.
     * @default "ok"
     */
    message?: string;

    /**
     * HTTP path that should be handled.
     * @default "/health"
     */
    path?: string;

    /**
     * HTTP response status that will be returned.
     * @default 200
     */
    status?: number;
  };
  instructions?: string;
  name: string;

  ping?: {
    /**
     * Whether ping should be enabled by default.
     * - true for SSE or HTTP Stream
     * - false for stdio
     */
    enabled?: boolean;
    /**
     * Interval
     * @default 5000 (5s)
     */
    intervalMs?: number;
    /**
     * Logging level for ping-related messages.
     * @default 'debug'
     */
    logLevel?: LoggingLevel;
  };
  /**
   * Configuration for roots capability
   */
  roots?: {
    /**
     * Whether roots capability should be enabled
     * Set to false to completely disable roots support
     * @default true
     */
    enabled?: boolean;
  };
  version: `${number}.${number}.${number}`;
};

type Tool<
  T extends FastMCPSessionAuth,
  Params extends ToolParameters = ToolParameters,
> = {
  annotations?: {
    /**
     * When true, the tool leverages incremental content streaming
     * Return void for tools that handle all their output via streaming
     */
    streamingHint?: boolean;
  } & ToolAnnotations;
  description?: string;
  execute: (
    args: StandardSchemaV1.InferOutput<Params>,
    context: Context<T>,
  ) => Promise<
    | AudioContent
    | ContentResult
    | ImageContent
    | ResourceContent
    | string
    | TextContent
    | void
  >;
  name: string;
  parameters?: Params;
  timeoutMs?: number;
};

/**
 * Tool annotations as defined in MCP Specification (2025-03-26)
 * These provide hints about a tool's behavior.
 */
type ToolAnnotations = {
  /**
   * If true, the tool may perform destructive updates
   * Only meaningful when readOnlyHint is false
   * @default true
   */
  destructiveHint?: boolean;

  /**
   * If true, calling the tool repeatedly with the same arguments has no additional effect
   * Only meaningful when readOnlyHint is false
   * @default false
   */
  idempotentHint?: boolean;

  /**
   * If true, the tool may interact with an "open world" of external entities
   * @default true
   */
  openWorldHint?: boolean;

  /**
   * If true, indicates the tool does not modify its environment
   * @default false
   */
  readOnlyHint?: boolean;

  /**
   * A human-readable title for the tool, useful for UI display
   */
  title?: string;
};

const FastMCPSessionEventEmitterBase: {
  new (): StrictEventEmitter<EventEmitter, FastMCPSessionEvents>;
} = EventEmitter;

type FastMCPSessionAuth = Record<string, unknown> | undefined;

type SamplingResponse = {
  content: AudioContent | ImageContent | TextContent;
  model: string;
  role: "assistant" | "user";
  stopReason?: "endTurn" | "maxTokens" | "stopSequence" | string;
};

class FastMCPSessionEventEmitter extends FastMCPSessionEventEmitterBase {}

export class FastMCPSession<
  T extends FastMCPSessionAuth = FastMCPSessionAuth,
> extends FastMCPSessionEventEmitter {
  public get clientCapabilities(): ClientCapabilities | null {
    return this.#clientCapabilities ?? null;
  }
  public get isReady(): boolean {
    return this.#connectionState === "ready";
  }
  public get loggingLevel(): LoggingLevel {
    return this.#loggingLevel;
  }
  public get roots(): Root[] {
    return this.#roots;
  }
  public get server(): Server {
    return this.#server;
  }
  #auth: T | undefined;
  #capabilities: ServerCapabilities = {};
  #clientCapabilities?: ClientCapabilities;
  #connectionState: "closed" | "connecting" | "error" | "ready" = "connecting";
  #loggingLevel: LoggingLevel = "info";
  #needsEventLoopFlush: boolean = false;
  #pingConfig?: ServerOptions<T>["ping"];

  #pingInterval: null | ReturnType<typeof setInterval> = null;

  #prompts: Prompt[] = [];

  #resources: Resource[] = [];

  #resourceTemplates: ResourceTemplate[] = [];

  #roots: Root[] = [];

  #rootsConfig?: ServerOptions<T>["roots"];

  #server: Server;

  constructor({
    auth,
    instructions,
    name,
    ping,
    prompts,
    resources,
    resourcesTemplates,
    roots,
    tools,
    transportType,
    version,
  }: {
    auth?: T;
    instructions?: string;
    name: string;
    ping?: ServerOptions<T>["ping"];
    prompts: Prompt[];
    resources: Resource[];
    resourcesTemplates: InputResourceTemplate[];
    roots?: ServerOptions<T>["roots"];
    tools: Tool<T>[];
    transportType?: "httpStream" | "stdio";
    version: string;
  }) {
    super();

    this.#auth = auth;
    this.#pingConfig = ping;
    this.#rootsConfig = roots;
    this.#needsEventLoopFlush = transportType === "httpStream";

    if (tools.length) {
      this.#capabilities.tools = {};
    }

    if (resources.length || resourcesTemplates.length) {
      this.#capabilities.resources = {};
    }

    if (prompts.length) {
      for (const prompt of prompts) {
        this.addPrompt(prompt);
      }

      this.#capabilities.prompts = {};
    }

    this.#capabilities.logging = {};

    this.#server = new Server(
      { name: name, version: version },
      { capabilities: this.#capabilities, instructions: instructions },
    );

    this.setupErrorHandling();
    this.setupLoggingHandlers();
    this.setupRootsHandlers();
    this.setupCompleteHandlers();

    if (tools.length) {
      this.setupToolHandlers(tools);
    }

    if (resources.length || resourcesTemplates.length) {
      for (const resource of resources) {
        this.addResource(resource);
      }

      this.setupResourceHandlers(resources);

      if (resourcesTemplates.length) {
        for (const resourceTemplate of resourcesTemplates) {
          this.addResourceTemplate(resourceTemplate);
        }

        this.setupResourceTemplateHandlers(resourcesTemplates);
      }
    }

    if (prompts.length) {
      this.setupPromptHandlers(prompts);
    }
  }

  public async close() {
    this.#connectionState = "closed";

    if (this.#pingInterval) {
      clearInterval(this.#pingInterval);
    }

    try {
      await this.#server.close();
    } catch (error) {
      console.error("[FastMCP error]", "could not close server", error);
    }
  }

  public async connect(transport: Transport) {
    if (this.#server.transport) {
      throw new UnexpectedStateError("Server is already connected");
    }

    this.#connectionState = "connecting";

    try {
      await this.#server.connect(transport);

      let attempt = 0;

      while (attempt++ < 10) {
        const capabilities = this.#server.getClientCapabilities();

        if (capabilities) {
          this.#clientCapabilities = capabilities;

          break;
        }

        await delay(100);
      }

      if (!this.#clientCapabilities) {
        console.warn("[FastMCP warning] could not infer client capabilities");
      }

      if (
        this.#clientCapabilities?.roots?.listChanged &&
        typeof this.#server.listRoots === "function"
      ) {
        try {
          const roots = await this.#server.listRoots();
          this.#roots = roots.roots;
        } catch (e) {
          if (e instanceof McpError && e.code === ErrorCode.MethodNotFound) {
            console.debug(
              "[FastMCP debug] listRoots method not supported by client",
            );
          } else {
            console.error(
              `[FastMCP error] received error listing roots.\n\n${e instanceof Error ? e.stack : JSON.stringify(e)}`,
            );
          }
        }
      }

      if (this.#clientCapabilities) {
        const pingConfig = this.#getPingConfig(transport);

        if (pingConfig.enabled) {
          this.#pingInterval = setInterval(async () => {
            try {
              await this.#server.ping();
            } catch {
              // The reason we are not emitting an error here is because some clients
              // seem to not respond to the ping request, and we don't want to crash the server,
              // e.g., https://github.com/punkpeye/fastmcp/issues/38.
              const logLevel = pingConfig.logLevel;

              if (logLevel === "debug") {
                console.debug("[FastMCP debug] server ping failed");
              } else if (logLevel === "warning") {
                console.warn(
                  "[FastMCP warning] server is not responding to ping",
                );
              } else if (logLevel === "error") {
                console.error(
                  "[FastMCP error] server is not responding to ping",
                );
              } else {
                console.info("[FastMCP info] server ping failed");
              }
            }
          }, pingConfig.intervalMs);
        }
      }

      // Mark connection as ready and emit event
      this.#connectionState = "ready";
      this.emit("ready");
    } catch (error) {
      this.#connectionState = "error";
      const errorEvent = {
        error: error instanceof Error ? error : new Error(String(error)),
      };
      this.emit("error", errorEvent);
      throw error;
    }
  }

  public async requestSampling(
    message: z.infer<typeof CreateMessageRequestSchema>["params"],
  ): Promise<SamplingResponse> {
    return this.#server.createMessage(message);
  }

  public waitForReady(): Promise<void> {
    if (this.isReady) {
      return Promise.resolve();
    }

    if (
      this.#connectionState === "error" ||
      this.#connectionState === "closed"
    ) {
      return Promise.reject(
        new Error(`Connection is in ${this.#connectionState} state`),
      );
    }

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(
          new Error(
            "Connection timeout: Session failed to become ready within 5 seconds",
          ),
        );
      }, 5000);

      this.once("ready", () => {
        clearTimeout(timeout);
        resolve();
      });

      this.once("error", (event) => {
        clearTimeout(timeout);
        reject(event.error);
      });
    });
  }

  #getPingConfig(transport: Transport): {
    enabled: boolean;
    intervalMs: number;
    logLevel: LoggingLevel;
  } {
    const pingConfig = this.#pingConfig || {};

    let defaultEnabled = false;

    if ("type" in transport) {
      // Enable by default for SSE and HTTP streaming
      if (transport.type === "httpStream") {
        defaultEnabled = true;
      }
    }

    return {
      enabled:
        pingConfig.enabled !== undefined ? pingConfig.enabled : defaultEnabled,
      intervalMs: pingConfig.intervalMs || 5000,
      logLevel: pingConfig.logLevel || "debug",
    };
  }

  private addPrompt(inputPrompt: InputPrompt) {
    const completers: Record<string, ArgumentValueCompleter> = {};
    const enums: Record<string, string[]> = {};

    for (const argument of inputPrompt.arguments ?? []) {
      if (argument.complete) {
        completers[argument.name] = argument.complete;
      }

      if (argument.enum) {
        enums[argument.name] = argument.enum;
      }
    }

    const prompt = {
      ...inputPrompt,
      complete: async (name: string, value: string) => {
        if (completers[name]) {
          return await completers[name](value);
        }

        if (enums[name]) {
          const fuse = new Fuse(enums[name], {
            keys: ["value"],
          });

          const result = fuse.search(value);

          return {
            total: result.length,
            values: result.map((item) => item.item),
          };
        }

        return {
          values: [],
        };
      },
    };

    this.#prompts.push(prompt);
  }

  private addResource(inputResource: Resource) {
    this.#resources.push(inputResource);
  }

  private addResourceTemplate(inputResourceTemplate: InputResourceTemplate) {
    const completers: Record<string, ArgumentValueCompleter> = {};

    for (const argument of inputResourceTemplate.arguments ?? []) {
      if (argument.complete) {
        completers[argument.name] = argument.complete;
      }
    }

    const resourceTemplate = {
      ...inputResourceTemplate,
      complete: async (name: string, value: string) => {
        if (completers[name]) {
          return await completers[name](value);
        }

        return {
          values: [],
        };
      },
    };

    this.#resourceTemplates.push(resourceTemplate);
  }

  private setupCompleteHandlers() {
    this.#server.setRequestHandler(CompleteRequestSchema, async (request) => {
      if (request.params.ref.type === "ref/prompt") {
        const prompt = this.#prompts.find(
          (prompt) => prompt.name === request.params.ref.name,
        );

        if (!prompt) {
          throw new UnexpectedStateError("Unknown prompt", {
            request,
          });
        }

        if (!prompt.complete) {
          throw new UnexpectedStateError("Prompt does not support completion", {
            request,
          });
        }

        const completion = CompletionZodSchema.parse(
          await prompt.complete(
            request.params.argument.name,
            request.params.argument.value,
          ),
        );

        return {
          completion,
        };
      }

      if (request.params.ref.type === "ref/resource") {
        const resource = this.#resourceTemplates.find(
          (resource) => resource.uriTemplate === request.params.ref.uri,
        );

        if (!resource) {
          throw new UnexpectedStateError("Unknown resource", {
            request,
          });
        }

        if (!("uriTemplate" in resource)) {
          throw new UnexpectedStateError("Unexpected resource");
        }

        if (!resource.complete) {
          throw new UnexpectedStateError(
            "Resource does not support completion",
            {
              request,
            },
          );
        }

        const completion = CompletionZodSchema.parse(
          await resource.complete(
            request.params.argument.name,
            request.params.argument.value,
          ),
        );

        return {
          completion,
        };
      }

      throw new UnexpectedStateError("Unexpected completion request", {
        request,
      });
    });
  }

  private setupErrorHandling() {
    this.#server.onerror = (error) => {
      console.error("[FastMCP error]", error);
    };
  }

  private setupLoggingHandlers() {
    this.#server.setRequestHandler(SetLevelRequestSchema, (request) => {
      this.#loggingLevel = request.params.level;

      return {};
    });
  }

  private setupPromptHandlers(prompts: Prompt[]) {
    this.#server.setRequestHandler(ListPromptsRequestSchema, async () => {
      return {
        prompts: prompts.map((prompt) => {
          return {
            arguments: prompt.arguments,
            complete: prompt.complete,
            description: prompt.description,
            name: prompt.name,
          };
        }),
      };
    });

    this.#server.setRequestHandler(GetPromptRequestSchema, async (request) => {
      const prompt = prompts.find(
        (prompt) => prompt.name === request.params.name,
      );

      if (!prompt) {
        throw new McpError(
          ErrorCode.MethodNotFound,
          `Unknown prompt: ${request.params.name}`,
        );
      }

      const args = request.params.arguments;

      for (const arg of prompt.arguments ?? []) {
        if (arg.required && !(args && arg.name in args)) {
          throw new McpError(
            ErrorCode.InvalidRequest,
            `Prompt '${request.params.name}' requires argument '${arg.name}': ${arg.description || "No description provided"}`,
          );
        }
      }

      let result: Awaited<ReturnType<Prompt["load"]>>;

      try {
        result = await prompt.load(args as Record<string, string | undefined>);
      } catch (error) {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        throw new McpError(
          ErrorCode.InternalError,
          `Failed to load prompt '${request.params.name}': ${errorMessage}`,
        );
      }

      return {
        description: prompt.description,
        messages: [
          {
            content: { text: result, type: "text" },
            role: "user",
          },
        ],
      };
    });
  }

  private setupResourceHandlers(resources: Resource[]) {
    this.#server.setRequestHandler(ListResourcesRequestSchema, async () => {
      return {
        resources: resources.map((resource) => {
          return {
            mimeType: resource.mimeType,
            name: resource.name,
            uri: resource.uri,
          };
        }),
      };
    });

    this.#server.setRequestHandler(
      ReadResourceRequestSchema,
      async (request) => {
        if ("uri" in request.params) {
          const resource = resources.find(
            (resource) =>
              "uri" in resource && resource.uri === request.params.uri,
          );

          if (!resource) {
            for (const resourceTemplate of this.#resourceTemplates) {
              const uriTemplate = parseURITemplate(
                resourceTemplate.uriTemplate,
              );

              const match = uriTemplate.fromUri(request.params.uri);

              if (!match) {
                continue;
              }

              const uri = uriTemplate.fill(match);

              const result = await resourceTemplate.load(match);

              return {
                contents: [
                  {
                    mimeType: resourceTemplate.mimeType,
                    name: resourceTemplate.name,
                    uri: uri,
                    ...result,
                  },
                ],
              };
            }

            throw new McpError(
              ErrorCode.MethodNotFound,
              `Resource not found: '${request.params.uri}'. Available resources: ${resources.map((r) => r.uri).join(", ") || "none"}`,
            );
          }

          if (!("uri" in resource)) {
            throw new UnexpectedStateError("Resource does not support reading");
          }

          let maybeArrayResult: Awaited<ReturnType<Resource["load"]>>;

          try {
            maybeArrayResult = await resource.load();
          } catch (error) {
            const errorMessage =
              error instanceof Error ? error.message : String(error);
            throw new McpError(
              ErrorCode.InternalError,
              `Failed to load resource '${resource.name}' (${resource.uri}): ${errorMessage}`,
              {
                uri: resource.uri,
              },
            );
          }

          if (Array.isArray(maybeArrayResult)) {
            return {
              contents: maybeArrayResult.map((result) => ({
                mimeType: resource.mimeType,
                name: resource.name,
                uri: resource.uri,
                ...result,
              })),
            };
          } else {
            return {
              contents: [
                {
                  mimeType: resource.mimeType,
                  name: resource.name,
                  uri: resource.uri,
                  ...maybeArrayResult,
                },
              ],
            };
          }
        }

        throw new UnexpectedStateError("Unknown resource request", {
          request,
        });
      },
    );
  }

  private setupResourceTemplateHandlers(resourceTemplates: ResourceTemplate[]) {
    this.#server.setRequestHandler(
      ListResourceTemplatesRequestSchema,
      async () => {
        return {
          resourceTemplates: resourceTemplates.map((resourceTemplate) => {
            return {
              name: resourceTemplate.name,
              uriTemplate: resourceTemplate.uriTemplate,
            };
          }),
        };
      },
    );
  }

  private setupRootsHandlers() {
    if (this.#rootsConfig?.enabled === false) {
      console.debug(
        "[FastMCP debug] roots capability explicitly disabled via config",
      );
      return;
    }

    // Only set up roots notification handling if the server supports it
    if (typeof this.#server.listRoots === "function") {
      this.#server.setNotificationHandler(
        RootsListChangedNotificationSchema,
        () => {
          this.#server
            .listRoots()
            .then((roots) => {
              this.#roots = roots.roots;

              this.emit("rootsChanged", {
                roots: roots.roots,
              });
            })
            .catch((error) => {
              if (
                error instanceof McpError &&
                error.code === ErrorCode.MethodNotFound
              ) {
                console.debug(
                  "[FastMCP debug] listRoots method not supported by client",
                );
              } else {
                console.error("[FastMCP error] Error listing roots", error);
              }
            });
        },
      );
    } else {
      console.debug(
        "[FastMCP debug] roots capability not available, not setting up notification handler",
      );
    }
  }

  private setupToolHandlers(tools: Tool<T>[]) {
    this.#server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: await Promise.all(
          tools.map(async (tool) => {
            return {
              annotations: tool.annotations,
              description: tool.description,
              inputSchema: tool.parameters
                ? await toJsonSchema(tool.parameters)
                : {
                    additionalProperties: false,
                    properties: {},
                    type: "object",
                  }, // More complete schema for Cursor compatibility
              name: tool.name,
            };
          }),
        ),
      };
    });

    this.#server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const tool = tools.find((tool) => tool.name === request.params.name);

      if (!tool) {
        throw new McpError(
          ErrorCode.MethodNotFound,
          `Unknown tool: ${request.params.name}`,
        );
      }

      let args: unknown = undefined;

      if (tool.parameters) {
        const parsed = await tool.parameters["~standard"].validate(
          request.params.arguments,
        );

        if (parsed.issues) {
          const friendlyErrors = parsed.issues
            .map((issue) => {
              const path = issue.path?.join(".") || "root";
              return `${path}: ${issue.message}`;
            })
            .join(", ");

          throw new McpError(
            ErrorCode.InvalidParams,
            `Tool '${request.params.name}' parameter validation failed: ${friendlyErrors}`,
          );
        }

        args = parsed.value;
      }

      const progressToken = request.params?._meta?.progressToken;

      let result: ContentResult;

      try {
        const reportProgress = async (progress: Progress) => {
          await this.#server.notification({
            method: "notifications/progress",
            params: {
              ...progress,
              progressToken,
            },
          });

          if (this.#needsEventLoopFlush) {
            await new Promise((resolve) => setImmediate(resolve));
          }
        };

        const log = {
          debug: (message: string, context?: SerializableValue) => {
            this.#server.sendLoggingMessage({
              data: {
                context,
                message,
              },
              level: "debug",
            });
          },
          error: (message: string, context?: SerializableValue) => {
            this.#server.sendLoggingMessage({
              data: {
                context,
                message,
              },
              level: "error",
            });
          },
          info: (message: string, context?: SerializableValue) => {
            this.#server.sendLoggingMessage({
              data: {
                context,
                message,
              },
              level: "info",
            });
          },
          warn: (message: string, context?: SerializableValue) => {
            this.#server.sendLoggingMessage({
              data: {
                context,
                message,
              },
              level: "warning",
            });
          },
        };

        // Create a promise for tool execution
        // Streams partial results while a tool is still executing
        // Enables progressive rendering and real-time feedback
        const streamContent = async (content: Content | Content[]) => {
          const contentArray = Array.isArray(content) ? content : [content];

          await this.#server.notification({
            method: "notifications/tool/streamContent",
            params: {
              content: contentArray,
              toolName: request.params.name,
            },
          });

          if (this.#needsEventLoopFlush) {
            await new Promise((resolve) => setImmediate(resolve));
          }
        };

        const executeToolPromise = tool.execute(args, {
          log,
          reportProgress,
          session: this.#auth,
          streamContent,
        });

        // Handle timeout if specified
        const maybeStringResult = (await (tool.timeoutMs
          ? Promise.race([
              executeToolPromise,
              new Promise<never>((_, reject) => {
                setTimeout(() => {
                  reject(
                    new UserError(
                      `Tool '${request.params.name}' timed out after ${tool.timeoutMs}ms. Consider increasing timeoutMs or optimizing the tool implementation.`,
                    ),
                  );
                }, tool.timeoutMs);
              }),
            ])
          : executeToolPromise)) as
          | AudioContent
          | ContentResult
          | ImageContent
          | null
          | ResourceContent
          | string
          | TextContent
          | undefined;

        if (maybeStringResult === undefined || maybeStringResult === null) {
          result = ContentResultZodSchema.parse({
            content: [],
          });
        } else if (typeof maybeStringResult === "string") {
          result = ContentResultZodSchema.parse({
            content: [{ text: maybeStringResult, type: "text" }],
          });
        } else if ("type" in maybeStringResult) {
          result = ContentResultZodSchema.parse({
            content: [maybeStringResult],
          });
        } else {
          result = ContentResultZodSchema.parse(maybeStringResult);
        }
      } catch (error) {
        if (error instanceof UserError) {
          return {
            content: [{ text: error.message, type: "text" }],
            isError: true,
          };
        }

        const errorMessage =
          error instanceof Error ? error.message : String(error);
        return {
          content: [
            {
              text: `Tool '${request.params.name}' execution failed: ${errorMessage}`,
              type: "text",
            },
          ],
          isError: true,
        };
      }

      return result;
    });
  }
}

const FastMCPEventEmitterBase: {
  new (): StrictEventEmitter<EventEmitter, FastMCPEvents<FastMCPSessionAuth>>;
} = EventEmitter;

type Authenticate<T> = (request: http.IncomingMessage) => Promise<T>;

class FastMCPEventEmitter extends FastMCPEventEmitterBase {}

export class FastMCP<
  T extends Record<string, unknown> | undefined = undefined,
> extends FastMCPEventEmitter {
  public get sessions(): FastMCPSession<T>[] {
    return this.#sessions;
  }
  #authenticate: Authenticate<T> | undefined;
  #httpStreamServer: null | SSEServer = null;
  #options: ServerOptions<T>;
  #prompts: InputPrompt[] = [];
  #resources: Resource[] = [];
  #resourcesTemplates: InputResourceTemplate[] = [];
  #sessions: FastMCPSession<T>[] = [];

  #tools: Tool<T>[] = [];

  constructor(public options: ServerOptions<T>) {
    super();

    this.#options = options;
    this.#authenticate = options.authenticate;
  }

  /**
   * Adds a prompt to the server.
   */
  public addPrompt<const Args extends InputPromptArgument[]>(
    prompt: InputPrompt<Args>,
  ) {
    this.#prompts.push(prompt);
  }

  /**
   * Adds a resource to the server.
   */
  public addResource(resource: Resource) {
    this.#resources.push(resource);
  }

  /**
   * Adds a resource template to the server.
   */
  public addResourceTemplate<
    const Args extends InputResourceTemplateArgument[],
  >(resource: InputResourceTemplate<Args>) {
    this.#resourcesTemplates.push(resource);
  }

  /**
   * Adds a tool to the server.
   */
  public addTool<Params extends ToolParameters>(tool: Tool<T, Params>) {
    this.#tools.push(tool as unknown as Tool<T>);
  }

  /**
   * Embeds a resource by URI, making it easy to include resources in tool responses.
   *
   * @param uri - The URI of the resource to embed
   * @returns Promise<ResourceContent> - The embedded resource content
   */
  public async embedded(uri: string): Promise<ResourceContent["resource"]> {
    // First, try to find a direct resource match
    const directResource = this.#resources.find(
      (resource) => resource.uri === uri,
    );

    if (directResource) {
      const result = await directResource.load();
      const results = Array.isArray(result) ? result : [result];
      const firstResult = results[0];

      const resourceData: ResourceContent["resource"] = {
        mimeType: directResource.mimeType,
        uri,
      };

      if ("text" in firstResult) {
        resourceData.text = firstResult.text;
      }

      if ("blob" in firstResult) {
        resourceData.blob = firstResult.blob;
      }

      return resourceData;
    }

    // Try to match against resource templates
    for (const template of this.#resourcesTemplates) {
      // Check if the URI starts with the template base
      const templateBase = template.uriTemplate.split("{")[0];

      if (uri.startsWith(templateBase)) {
        const params: Record<string, string> = {};
        const templateParts = template.uriTemplate.split("/");
        const uriParts = uri.split("/");

        for (let i = 0; i < templateParts.length; i++) {
          const templatePart = templateParts[i];

          if (templatePart?.startsWith("{") && templatePart.endsWith("}")) {
            const paramName = templatePart.slice(1, -1);
            const paramValue = uriParts[i];

            if (paramValue) {
              params[paramName] = paramValue;
            }
          }
        }

        const result = await template.load(
          params as ResourceTemplateArgumentsToObject<
            typeof template.arguments
          >,
        );

        const resourceData: ResourceContent["resource"] = {
          mimeType: template.mimeType,
          uri,
        };

        if ("text" in result) {
          resourceData.text = result.text;
        }

        if ("blob" in result) {
          resourceData.blob = result.blob;
        }

        return resourceData; // The resource we're looking for
      }
    }

    throw new UnexpectedStateError(`Resource not found: ${uri}`, { uri });
  }

  /**
   * Starts the server.
   */
  public async start(
    options:
      | {
          httpStream: { port: number };
          transportType: "httpStream";
        }
      | { transportType: "stdio" } = {
      transportType: "stdio",
    },
  ) {
    if (options.transportType === "stdio") {
      const transport = new StdioServerTransport();

      const session = new FastMCPSession<T>({
        instructions: this.#options.instructions,
        name: this.#options.name,
        ping: this.#options.ping,
        prompts: this.#prompts,
        resources: this.#resources,
        resourcesTemplates: this.#resourcesTemplates,
        roots: this.#options.roots,
        tools: this.#tools,
        transportType: "stdio",
        version: this.#options.version,
      });

      await session.connect(transport);

      this.#sessions.push(session);

      this.emit("connect", {
        session,
      });
    } else if (options.transportType === "httpStream") {
      this.#httpStreamServer = await startHTTPServer<FastMCPSession<T>>({
        createServer: async (request) => {
          let auth: T | undefined;

          if (this.#authenticate) {
            auth = await this.#authenticate(request);
          }

          return new FastMCPSession<T>({
            auth,
            name: this.#options.name,
            ping: this.#options.ping,
            prompts: this.#prompts,
            resources: this.#resources,
            resourcesTemplates: this.#resourcesTemplates,
            roots: this.#options.roots,
            tools: this.#tools,
            transportType: "httpStream",
            version: this.#options.version,
          });
        },
        onClose: (session) => {
          this.emit("disconnect", {
            session,
          });
        },
        onConnect: async (session) => {
          this.#sessions.push(session);

          this.emit("connect", {
            session,
          });
        },
        onUnhandledRequest: async (req, res) => {
          const healthConfig = this.#options.health ?? {};

          const enabled =
            healthConfig.enabled === undefined ? true : healthConfig.enabled;

          if (enabled) {
            const path = healthConfig.path ?? "/health";
            const url = new URL(req.url || "", "http://localhost");

            try {
              if (req.method === "GET" && url.pathname === path) {
                res
                  .writeHead(healthConfig.status ?? 200, {
                    "Content-Type": "text/plain",
                  })
                  .end(healthConfig.message ?? "ok");

                return;
              }

              // Enhanced readiness check endpoint
              if (req.method === "GET" && url.pathname === "/ready") {
                const readySessions = this.#sessions.filter(
                  (s) => s.isReady,
                ).length;
                const totalSessions = this.#sessions.length;
                const allReady =
                  readySessions === totalSessions && totalSessions > 0;

                const response = {
                  ready: readySessions,
                  status: allReady
                    ? "ready"
                    : totalSessions === 0
                      ? "no_sessions"
                      : "initializing",
                  total: totalSessions,
                };

                res
                  .writeHead(allReady ? 200 : 503, {
                    "Content-Type": "application/json",
                  })
                  .end(JSON.stringify(response));

                return;
              }
            } catch (error) {
              console.error("[FastMCP error] health endpoint error", error);
            }
          }

          // If the request was not handled above, return 404
          res.writeHead(404).end();
        },
        port: options.httpStream.port,
      });

      console.info(
        `[FastMCP info] server is running on HTTP Stream at http://localhost:${options.httpStream.port}/stream`,
      );
    } else {
      throw new Error("Invalid transport type");
    }
  }

  /**
   * Stops the server.
   */
  public async stop() {
    if (this.#httpStreamServer) {
      await this.#httpStreamServer.close();
    }
  }
}

export type { Context };
export type { Tool, ToolParameters };
export type { Content, ContentResult, ImageContent, TextContent };
export type { Progress, SerializableValue };
export type { Resource, ResourceResult };
export type { ResourceTemplate, ResourceTemplateArgument };
export type { Prompt, PromptArgument };
export type { InputPrompt, InputPromptArgument };
export type { LoggingLevel, ServerOptions };
export type { FastMCPEvents, FastMCPSessionEvents };
