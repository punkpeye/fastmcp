import type { JsonSchema } from "xsschema";

import { z } from "zod";

const isNestedResource = (root: JsonSchema, value: object): boolean =>
  value !== root && typeof (value as Record<string, unknown>).$id === "string";

/** Resolve only document-local JSON Pointers; never fetch external schemas. */
const resolvePointer = (root: JsonSchema, ref: string): unknown => {
  if (!ref.startsWith("#")) {
    return undefined;
  }

  let pointer: string;
  try {
    pointer = decodeURIComponent(ref.slice(1));
  } catch {
    return undefined;
  }
  if (pointer !== "" && !pointer.startsWith("/")) {
    return undefined;
  }

  let value: unknown = root;
  for (const part of pointer === "" ? [] : pointer.slice(1).split("/")) {
    if (/~(?:[^01]|$)/.test(part)) {
      return undefined;
    }
    const key = part.replace(/~1/g, "/").replace(/~0/g, "~");
    if (
      typeof value !== "object" ||
      value === null ||
      isNestedResource(root, value) ||
      !Object.hasOwn(value, key)
    ) {
      return undefined;
    }
    value = (value as Record<string, unknown>)[key];
  }
  return value;
};

const isObjectUnion = (root: JsonSchema): boolean => {
  if (root.anyOf === undefined && root.oneOf === undefined) {
    return false;
  }

  // Draft-07 ignores $ref siblings. Later drafts apply them as constraints.
  // Treat an unspecified/unknown dialect conservatively as draft-07.
  const refSiblingsApply =
    root.$schema?.includes("/draft/2020-12/") === true ||
    root.$schema?.includes("/draft/2019-09/") === true;
  const visiting = new Set<object>();
  const provesObject = (candidate: unknown): boolean => {
    if (
      typeof candidate !== "object" ||
      candidate === null ||
      Array.isArray(candidate) ||
      isNestedResource(root, candidate) ||
      visiting.has(candidate)
    ) {
      return false;
    }

    visiting.add(candidate);
    try {
      const schema = candidate as Record<string, unknown>;
      let referencedObject = false;
      if (schema.$ref !== undefined) {
        if (typeof schema.$ref !== "string") {
          return false;
        }
        const referenced = resolvePointer(root, schema.$ref);
        if (referenced === undefined) {
          return false;
        }
        referencedObject = provesObject(referenced);
        if (!refSiblingsApply) {
          return referencedObject;
        }
      }

      if (schema.type !== undefined && schema.type !== "object") {
        return false;
      }
      return (
        schema.type === "object" ||
        referencedObject ||
        [schema.anyOf, schema.oneOf].some(
          (branches) =>
            Array.isArray(branches) &&
            branches.length > 0 &&
            branches.every(provesObject),
        )
      );
    } finally {
      visiting.delete(candidate);
    }
  };

  return provesObject(root);
};

/** MCP requires an explicit object root even when a union implies it. */
export function normalizeObjectUnion(schema: JsonSchema): JsonSchema {
  return isObjectUnion(schema) ? { ...schema, type: "object" } : schema;
}

/**
 * Closes tool input objects to undeclared keys, like xsschema's
 * `strictJsonSchema`, except for objects made only of additional properties.
 * Closing one of those advertises an object that accepts nothing but `{}`,
 * while the tool's own validation still takes any key, so it keeps whatever
 * `additionalProperties` it declared — or none:
 *
 * - a dictionary, whose `additionalProperties` is a schema (`z.record()`, an
 *   OpenAPI map), keeps its value schema;
 * - a free-form object, which declares `additionalProperties: true`, or, as an
 *   argument, is a bare `{ type: "object" }` (OpenAPI's usual spelling), stays
 *   open.
 *
 * An object that declares an empty `properties`, or a bare one at the top of
 * the input, is still closed: that is how a schema says "no keys" —
 * `z.object({})`, or a tool without arguments.
 *
 * Shared by both runtimes, so a tool's advertised input schema does not depend
 * on whether it is served by `FastMCP` or `EdgeFastMCP`.
 */
export function strictInputSchema(
  schema: JsonSchema,
  nested = false,
): JsonSchema {
  // Branches already describe their own properties and strictness. Closing
  // the union root without root properties would reject every branch's keys.
  if (isObjectUnion(schema)) {
    return { ...schema, type: "object" };
  }

  const { additionalProperties, properties } = schema;
  const keepsAdditionalProperties =
    Object.keys(properties ?? {}).length === 0 &&
    (typeof additionalProperties === "object" ||
      additionalProperties === true ||
      (nested && additionalProperties === undefined && !properties));

  return {
    ...schema,
    ...(keepsAdditionalProperties ? {} : { additionalProperties: false }),
    ...(properties && {
      properties: Object.fromEntries(
        Object.entries(properties).map(([key, value]) => [
          key,
          typeof value === "object" && value.type === "object"
            ? strictInputSchema(value, true)
            : value,
        ]),
      ),
    }),
  };
}

/**
 * Converts Zod 4 tool parameters by what a call may send (`io: "input"`), so a
 * transformed field advertises the type it parses and a defaulted one is
 * optional. Input-side conversion leaves a plain `z.object()` open, since it
 * strips undeclared keys rather than rejecting them; this closes it, as
 * output-side conversion did, at any depth — including inside arrays, unions
 * and record values, which `strictInputSchema` does not reach. Explicit
 * catchalls (`z.looseObject()`, `.catchall()`) keep what they declare.
 */
export function zodInputSchema(
  schema: z.ZodType,
  target?: "draft-7",
): JsonSchema {
  return z.toJSONSchema(schema, {
    io: "input",
    override: ({ jsonSchema, zodSchema }) => {
      const def = zodSchema._zod.def;
      if (
        def.type === "object" &&
        !def.catchall &&
        jsonSchema.additionalProperties === undefined
      ) {
        jsonSchema.additionalProperties = false;
      }
    },
    target,
  }) as JsonSchema;
}
