import type { JsonSchema } from "xsschema";

import { z } from "zod";

/**
 * Gives a tool's input or output schema the `type: "object"` MCP requires at
 * its root, unless it states a type of its own. A union of objects converts to
 * a bare `anyOf` or `oneOf`, and the SDK client rejects a whole `tools/list`
 * that contains one, so a single such tool would hide every other. Arguments
 * and structured content are always objects, so this only rules out values a
 * tool can never be sent or return.
 */
export function objectRootSchema(schema: JsonSchema): JsonSchema {
  return schema.type === undefined ? { ...schema, type: "object" } : schema;
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
 * A plain object that declares an empty `properties`, or a bare one at the
 * top of the input, is still closed: that is how a schema says "no keys" —
 * `z.object({})`, or a tool without arguments. Root schemas with `allOf`,
 * `anyOf`, `oneOf`, or `$ref` are left as declared, even with their own
 * `properties`: `additionalProperties` only sees adjacent properties, so
 * adding it would reject keys declared by a branch or reference target.
 *
 * The root is given an object type (see `objectRootSchema`).
 *
 * Shared by both runtimes, so a tool's advertised input schema does not depend
 * on whether it is served by `FastMCP` or `EdgeFastMCP`.
 */
export function strictInputSchema(
  schema: JsonSchema,
  nested = false,
): JsonSchema {
  const { $ref, additionalProperties, allOf, anyOf, oneOf, properties } =
    schema;

  if (!nested && ($ref || allOf || anyOf || oneOf)) {
    return objectRootSchema(schema);
  }

  const keepsAdditionalProperties =
    Object.keys(properties ?? {}).length === 0 &&
    (typeof additionalProperties === "object" ||
      additionalProperties === true ||
      (nested && additionalProperties === undefined && !properties));

  const strict = {
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

  return nested ? strict : objectRootSchema(strict);
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
