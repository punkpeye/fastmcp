import type { JsonSchema } from "xsschema";

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
