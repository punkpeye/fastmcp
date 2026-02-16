/**
 * OpenAPI 3.x type definitions (minimal subset needed for MCP conversion).
 * We inline these to avoid adding an external dependency.
 */

type HttpMethod =
  | "delete"
  | "get"
  | "head"
  | "options"
  | "patch"
  | "post"
  | "put";

type OpenAPIDocument = {
  components?: {
    schemas?: Record<string, SchemaObject | ReferenceObject>;
  };
  info: { title: string; version: string };
  openapi: string;
  paths?: Record<string, PathItemObject | ReferenceObject>;
};

type ReferenceObject = {
  $ref: string;
};

type PathItemObject = {
  delete?: OperationObject;
  get?: OperationObject;
  head?: OperationObject;
  options?: OperationObject;
  parameters?: (ParameterObject | ReferenceObject)[];
  patch?: OperationObject;
  post?: OperationObject;
  put?: OperationObject;
};

type OperationObject = {
  description?: string;
  operationId?: string;
  parameters?: (ParameterObject | ReferenceObject)[];
  requestBody?: RequestBodyObject | ReferenceObject;
  responses?: Record<string, unknown>;
  summary?: string;
};

type ParameterObject = {
  description?: string;
  in: "cookie" | "header" | "path" | "query";
  name: string;
  required?: boolean;
  schema?: SchemaObject | ReferenceObject;
};

type RequestBodyObject = {
  content: Record<string, MediaTypeObject>;
  required?: boolean;
};

type MediaTypeObject = {
  schema?: SchemaObject | ReferenceObject;
};

type SchemaObject = {
  default?: unknown;
  description?: string;
  enum?: unknown[];
  format?: string;
  items?: SchemaObject | ReferenceObject;
  maximum?: number;
  minimum?: number;
  properties?: Record<string, SchemaObject | ReferenceObject>;
  required?: string[];
  type?: string;
};

type OpenAPIRoute = {
  description: string;
  method: HttpMethod;
  operationId: string;
  parameters: ParameterObject[];
  path: string;
  requestBody?: RequestBodyObject;
};

/**
 * Resolve a $ref to its target object within the spec.
 */
function resolveRef<T>(spec: OpenAPIDocument, ref: string): T {
  const parts = ref.replace(/^#\//, "").split("/");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let current: any = spec;
  for (const part of parts) {
    current = current[part];
    if (current === undefined) {
      throw new Error(`Could not resolve $ref: ${ref}`);
    }
  }
  return current as T;
}

/**
 * Dereference an object that might be a $ref.
 */
function deref<T>(spec: OpenAPIDocument, obj: T | ReferenceObject): T {
  if (obj && typeof obj === "object" && "$ref" in obj) {
    return resolveRef<T>(spec, (obj as ReferenceObject).$ref);
  }
  return obj as T;
}

/**
 * Convert an OpenAPI JSON Schema to a plain JSON Schema object
 * suitable for use as tool parameters.
 */
function openApiSchemaToJsonSchema(
  spec: OpenAPIDocument,
  schema: SchemaObject | ReferenceObject,
): Record<string, unknown> {
  const resolved = deref<SchemaObject>(spec, schema);
  const result: Record<string, unknown> = {};

  if (resolved.type) result.type = resolved.type;
  if (resolved.description) result.description = resolved.description;
  if (resolved.enum) result.enum = resolved.enum;
  if (resolved.default !== undefined) result.default = resolved.default;
  if (resolved.format) result.format = resolved.format;
  if (resolved.minimum !== undefined) result.minimum = resolved.minimum;
  if (resolved.maximum !== undefined) result.maximum = resolved.maximum;

  if (resolved.type === "object" && resolved.properties) {
    result.properties = {};
    for (const [key, value] of Object.entries(resolved.properties)) {
      (result.properties as Record<string, unknown>)[key] =
        openApiSchemaToJsonSchema(spec, value);
    }
    if (resolved.required) {
      result.required = resolved.required;
    }
  }

  if (resolved.type === "array" && resolved.items) {
    result.items = openApiSchemaToJsonSchema(spec, resolved.items);
  }

  return result;
}

/**
 * Extract all routes from an OpenAPI spec.
 */
export function extractRoutes(spec: OpenAPIDocument): OpenAPIRoute[] {
  const routes: OpenAPIRoute[] = [];
  const methods: HttpMethod[] = [
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
  ];

  for (const [path, pathItem] of Object.entries(spec.paths ?? {})) {
    if (!pathItem) continue;
    const resolvedPathItem = deref<PathItemObject>(spec, pathItem);

    for (const method of methods) {
      const operation = resolvedPathItem[method];
      if (!operation) continue;

      const operationId =
        operation.operationId ??
        `${method}_${path
          .replace(/[^a-zA-Z0-9]/g, "_")
          .replace(/_+/g, "_")
          .replace(/^_|_$/g, "")}`;

      const parameters = (
        operation.parameters ??
        resolvedPathItem.parameters ??
        []
      ).map((p) => deref<ParameterObject>(spec, p));

      const requestBody = operation.requestBody
        ? deref<RequestBodyObject>(spec, operation.requestBody)
        : undefined;

      const summary =
        operation.summary ??
        operation.description ??
        `${method.toUpperCase()} ${path}`;

      routes.push({
        description: summary,
        method,
        operationId,
        parameters,
        path,
        requestBody,
      });
    }
  }

  return routes;
}

/**
 * Build JSON Schema parameters for a tool from an OpenAPI route.
 */
export function buildToolParameters(
  spec: OpenAPIDocument,
  route: OpenAPIRoute,
): { jsonSchema: Record<string, unknown> } {
  const properties: Record<string, unknown> = {};
  const required: string[] = [];

  for (const param of route.parameters) {
    if (param.in === "path" || param.in === "query" || param.in === "header") {
      const schema = param.schema
        ? openApiSchemaToJsonSchema(spec, param.schema)
        : { type: "string" };
      properties[param.name] = {
        ...schema,
        description:
          param.description ?? (schema as Record<string, unknown>).description,
      };
      if (param.required) {
        required.push(param.name);
      }
    }
  }

  if (route.requestBody) {
    const content = route.requestBody.content;
    const jsonContent = content?.["application/json"];
    if (jsonContent?.schema) {
      const bodySchema = openApiSchemaToJsonSchema(spec, jsonContent.schema);
      if (bodySchema.type === "object" && bodySchema.properties) {
        for (const [key, value] of Object.entries(
          bodySchema.properties as Record<string, unknown>,
        )) {
          properties[`body_${key}`] = value;
        }
        if (Array.isArray(bodySchema.required)) {
          for (const r of bodySchema.required) {
            required.push(`body_${r}`);
          }
        }
      } else {
        properties["body"] = bodySchema;
        if (route.requestBody.required) {
          required.push("body");
        }
      }
    }
  }

  return {
    jsonSchema: {
      properties,
      required: required.length > 0 ? required : undefined,
      type: "object" as const,
    },
  };
}

/**
 * Classify an OpenAPI route:
 * - GET without path params -> resource
 * - GET with path params -> resource template
 * - Other HTTP methods -> tool
 */
export function classifyRoute(
  route: OpenAPIRoute,
): "resource" | "resourceTemplate" | "tool" {
  if (route.method !== "get") {
    return "tool";
  }
  const hasPathParams = route.parameters.some((p) => p.in === "path");
  return hasPathParams ? "resourceTemplate" : "resource";
}

export type {
  HttpMethod,
  OpenAPIDocument,
  OpenAPIRoute,
  ParameterObject,
  RequestBodyObject,
  SchemaObject,
};
