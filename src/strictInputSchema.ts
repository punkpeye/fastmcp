import type { JsonSchema } from "xsschema";

/**
 * Closes tool input objects to undeclared keys, like xsschema's
 * `strictJsonSchema`, except for dictionaries. An object with no `properties`
 * whose `additionalProperties` is a schema (`z.record()`, an OpenAPI map) is
 * made only of additional properties: replacing that schema with `false`
 * advertises an object that accepts nothing but `{}`, while the tool's own
 * validation still takes any key.
 *
 * Shared by both runtimes, so a tool's advertised input schema does not depend
 * on whether it is served by `FastMCP` or `EdgeFastMCP`.
 */
export function strictInputSchema(schema: JsonSchema): JsonSchema {
  const isDictionary =
    typeof schema.additionalProperties === "object" &&
    Object.keys(schema.properties ?? {}).length === 0;

  return {
    ...schema,
    additionalProperties: isDictionary ? schema.additionalProperties : false,
    ...(schema.properties && {
      properties: Object.fromEntries(
        Object.entries(schema.properties).map(([key, value]) => [
          key,
          typeof value === "object" && value.type === "object"
            ? strictInputSchema(value)
            : value,
        ]),
      ),
    }),
  };
}
