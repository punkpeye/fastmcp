import { StandardSchemaV1 } from "@standard-schema/spec";

/**
 * A plain JSON Schema object descriptor.
 */
export type JsonSchemaObject = {
  [key: string]: unknown;
  $schema?: string;
  additionalProperties?: boolean;
  properties?: Record<string, unknown>;
  required?: string[];
  type: string;
};

/**
 * A Standard Schema that also carries the JSON Schema it was built from.
 *
 * `~standard.jsonSchema` is the Standard JSON Schema extension. Anything that
 * knows about it — including the `xsschema` conversion FastMCP uses to build
 * `tools/list` — reads the schema straight off the object instead of trying to
 * derive one from a validation library it does not recognise.
 */
export interface JsonSchemaStandardSchema extends StandardSchemaV1 {
  readonly "~standard": {
    readonly jsonSchema: {
      readonly input: () => JsonSchemaObject;
      readonly output: () => JsonSchemaObject;
    };
  } & StandardSchemaV1.Props;
}

interface AjvErrorObject {
  instancePath: string;
  keyword: string;
  message?: string;
  params?: Record<string, unknown>;
}

type AjvValidateFunction = {
  errors?: AjvErrorObject[] | null;
  (data: unknown): boolean;
};

/**
 * Wraps a plain JSON Schema object so it can be used as a tool's `parameters`
 * or `outputSchema`, without pulling in Zod, Valibot, or another validation
 * library.
 *
 * Validation uses AJV, which is an optional peer dependency — install `ajv`
 * (and `ajv-formats` if you use `format` keywords) to use this. It is imported
 * on first validation, so servers that never call this pay nothing for it.
 *
 * Note that FastMCP applies the same strictness to every tool schema: objects
 * are advertised with `additionalProperties: false`, whatever the input schema
 * said.
 *
 * @example
 * ```ts
 * import { FastMCP, jsonSchemaAdapter } from "fastmcp";
 *
 * const server = new FastMCP({ name: "Example", version: "1.0.0" });
 *
 * server.addTool({
 *   name: "greet",
 *   description: "Greet a user",
 *   parameters: jsonSchemaAdapter({
 *     type: "object",
 *     properties: {
 *       name: { type: "string" },
 *     },
 *     required: ["name"],
 *   }),
 *   execute: async ({ name }) => `Hello, ${name}!`,
 * });
 * ```
 *
 * @param schema - A plain JSON Schema object
 * @returns A Standard Schema that validates against `schema`
 */
export function jsonSchemaAdapter(
  schema: JsonSchemaObject,
): JsonSchemaStandardSchema {
  // Compiling a schema makes AJV generate and evaluate JavaScript, so it has
  // to happen once rather than per call. The promise is memoised, not just the
  // result, so concurrent first calls share a single compilation.
  let compiled: Promise<AjvValidateFunction> | undefined;

  const getValidator = (): Promise<AjvValidateFunction> => {
    compiled ??= compileSchema(schema).catch((error: unknown) => {
      // Do not memoise a failure: a missing dependency should be reported on
      // every call, not swallowed after the first.
      compiled = undefined;
      throw error;
    });

    return compiled;
  };

  return {
    "~standard": {
      jsonSchema: {
        input: () => schema,
        output: () => schema,
      },
      validate: async (
        data: unknown,
      ): Promise<StandardSchemaV1.Result<unknown>> => {
        const validate = await getValidator();

        if (validate(data)) {
          return { value: data };
        }

        return { issues: (validate.errors ?? []).map(toIssue) };
      },
      vendor: "json-schema",
      version: 1,
    },
  };
}

async function compileSchema(
  schema: JsonSchemaObject,
): Promise<AjvValidateFunction> {
  let ajvModule;

  try {
    ajvModule = await import("ajv");
  } catch {
    throw new Error(
      'The "ajv" package is required to validate JSON Schema tool parameters. ' +
        "Install it with: npm install ajv",
    );
  }

  // ajv ships CommonJS, so depending on the loader the class arrives as the
  // module namespace, as `.default`, or as `.default.default`.
  const Ajv = unwrapDefault(unwrapDefault(ajvModule)) as unknown as new (
    options: Record<string, unknown>,
  ) => {
    compile: (schema: unknown) => AjvValidateFunction;
  };

  const ajv = new Ajv({ allErrors: true, strict: false });

  try {
    const formatsModule = await import("ajv-formats");
    const addFormats = unwrapDefault(
      unwrapDefault(formatsModule),
    ) as unknown as (ajv: unknown) => void;

    addFormats(ajv);
  } catch {
    // ajv-formats is optional; `format` keywords are simply not enforced.
  }

  return ajv.compile(schema);
}

function toIssue(error: AjvErrorObject): StandardSchemaV1.Issue {
  const path = error.instancePath
    .split("/")
    .filter(Boolean)
    // JSON Pointer escapes, per RFC 6901.
    .map((segment) => segment.replaceAll("~1", "/").replaceAll("~0", "~"))
    .map((segment): number | string => {
      const index = Number(segment);
      return Number.isInteger(index) && segment !== "" ? index : segment;
    });

  // AJV reports a missing property against its parent object, with the name in
  // `params`. Appending it points the issue at the field the user has to fix.
  const missingProperty = error.params?.missingProperty;

  if (error.keyword === "required" && typeof missingProperty === "string") {
    path.push(missingProperty);
  }

  return {
    message: error.message || "Validation error",
    path,
  };
}

function unwrapDefault(value: unknown): unknown {
  return typeof value === "object" && value !== null && "default" in value
    ? (value as { default: unknown }).default
    : value;
}
