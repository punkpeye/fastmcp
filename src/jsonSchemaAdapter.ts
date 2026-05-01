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
 * Wraps a plain JSON Schema object with a StandardSchemaV1-compatible adapter,
 * enabling it to be used directly as a tool parameter schema in FastMCP.
 *
 * Uses AJV for runtime validation, loaded dynamically so it remains an optional
 * peer dependency — the core FastMCP bundle stays lightweight.
 *
 * @example
 * ```ts
 * import { FastMCP } from "fastmcp";
 * import { jsonSchemaAdapter } from "fastmcp/json-schema-adapter";
 *
 * const server = new FastMCP({ name: "Example" });
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
 * @param schema - A plain JSON Schema object (should define an object-type schema)
 * @returns A StandardSchemaV1-compatible validator adapter
 */
export function jsonSchemaAdapter(
  schema: JsonSchemaObject,
): { __jsonSchema: JsonSchemaObject } & StandardSchemaV1 {
  return {
    __jsonSchema: schema,
    "~standard": {
      validate: async (
        data: unknown,
      ): Promise<StandardSchemaV1.Result<unknown>> => {
        let Ajv: unknown;

        try {
          // @ts-ignore ajv is an optional peer dependency
          const ajvModule = await import("ajv");
          Ajv =
            "default" in ajvModule
              ? (ajvModule as Record<string, unknown>).default
              : ajvModule;
        } catch {
          throw new Error(
            'The "ajv" package is required to use jsonSchemaAdapter. ' +
              "Install it with: npm install ajv",
          );
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const ajv = new (Ajv as any)({ allErrors: true, strict: false });

        try {
          // @ts-expect-error ajv-formats is an optional peer dependency
          const ajvFormatsModule = await import("ajv-formats");
          const addFormats =
            "default" in ajvFormatsModule
              ? (ajvFormatsModule as Record<string, unknown>).default
              : ajvFormatsModule;
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (addFormats as any)(ajv);
        } catch {
          // ajv-formats is optional — format validation is skipped if not installed
        }

        const validate = ajv.compile(schema);
        const valid = validate(data);

        if (valid) {
          return { value: data };
        }

        return {
          issues: (
            validate.errors as Array<{
              instancePath: string;
              keyword: string;
              message?: string;
            }>
          ).map((err) => ({
            message: err.message || "Validation error",
            path: err.instancePath
              .split("/")
              .filter(Boolean)
              .map((segment) => {
                // Try to parse as number for array indices
                const num = Number(segment);
                return Number.isNaN(num) ? segment : num;
              }) as [PropertyKey, ...PropertyKey[]],
          })),
        };
      },
      vendor: "json-schema",
      version: 1,
    },
  };
}
