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
 * `z.object({})`, or a tool without arguments. An object with `allOf`,
 * `anyOf`, `oneOf`, `$ref`, or `if`, at the root or nested, keeps its own
 * `additionalProperties` as declared, as do the branches of a composition and
 * the `then` and `else` of a condition: `additionalProperties` only sees
 * adjacent properties, so adding it would reject keys declared by a branch,
 * reference target, or condition. The ordinary objects among their
 * `properties` are closed like any other.
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
  const strict = strictSchemaNode(schema, nested, false);
  return nested ? strict : objectRootSchema(strict);
}

/**
 * Converts Zod 4 tool parameters by what a call may send (`io: "input"`), so a
 * transformed field advertises the type it parses and a defaulted one is
 * optional. Close ordinary object occurrences after conversion, but leave
 * intersection operands open to each other's keys. Child values start a new
 * closure context; explicit catchalls, including .strict(), stay as declared.
 */
export function zodInputSchema(
  schema: z.ZodType,
  target?: "draft-7",
): JsonSchema {
  const jsonSchema = z.toJSONSchema(schema, {
    io: "input",
    target,
  }) as Record<string, unknown>;
  const definitionsKey = target === "draft-7" ? "definitions" : "$defs";
  const definitions: Record<string, unknown> = {};
  const operands = new Map<string, string>();

  const closeObjects = (value: unknown, operand = false): unknown => {
    if (!value || typeof value !== "object") return value;
    const result = { ...(value as Record<string, unknown>) };

    if (
      operand &&
      typeof result.$ref === "string" &&
      (result.$ref === "#" || result.$ref.startsWith("#/"))
    ) {
      const reference = result.$ref;
      let name = operands.get(reference);
      if (!name) {
        const path = decodeURIComponent(reference.slice(1)).split("/").slice(1);
        const referenced = path.reduce<unknown>(
          (node, key) =>
            node && typeof node === "object"
              ? (node as Record<string, unknown>)[
                  key.replace(/~1/g, "/").replace(/~0/g, "~")
                ]
              : undefined,
          jsonSchema,
        );
        if (referenced && typeof referenced === "object") {
          name = `__fastmcp_operand_${operands.size}`;
          const existing = jsonSchema[definitionsKey] as object | undefined;
          while (
            Object.hasOwn(existing ?? {}, name) ||
            Object.hasOwn(definitions, name)
          )
            name += "_";
          // Reserve the reference before descending, including through child values.
          operands.set(reference, name);
          const copy = { ...(referenced as Record<string, unknown>) };
          delete copy.$schema;
          delete copy.$defs;
          delete copy.definitions;
          definitions[name] = closeObjects(copy, true);
        }
      }
      if (name) result.$ref = `#/${definitionsKey}/${name}`;
    }

    if (
      !operand &&
      result.type === "object" &&
      result.properties !== undefined &&
      result.additionalProperties === undefined
    ) {
      result.additionalProperties = false;
    }

    for (const keyword of ["allOf", "anyOf", "oneOf"]) {
      const branches = result[keyword];
      if (Array.isArray(branches)) {
        // A single allOf branch is Zod's draft-7 reference wrapper, not
        // an intersection. Only intersections introduce a new exemption.
        result[keyword] = branches.map((branch) =>
          closeObjects(
            branch,
            operand || (keyword === "allOf" && branches.length > 1),
          ),
        );
      }
    }

    for (const keyword of [
      "$defs",
      "definitions",
      "patternProperties",
      "properties",
    ]) {
      const children = result[keyword];
      if (children && typeof children === "object") {
        result[keyword] = Object.fromEntries(
          Object.entries(children).map(([key, child]) => [
            key,
            closeObjects(child),
          ]),
        );
      }
    }
    for (const keyword of [
      "additionalItems",
      "additionalProperties",
      "items",
      "prefixItems",
      "propertyNames",
    ]) {
      const child = result[keyword];
      if (child !== undefined) {
        result[keyword] = Array.isArray(child)
          ? child.map((item) => closeObjects(item))
          : closeObjects(child);
      }
    }
    return result;
  };

  const closed = closeObjects(jsonSchema) as Record<string, unknown>;
  if (operands.size > 0) {
    closed[definitionsKey] = {
      ...(closed[definitionsKey] as Record<string, unknown>),
      ...definitions,
    };
  }
  return closed as JsonSchema;
}

function isSchemaRecord(value: unknown): value is JsonSchema {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function strictSchemaNode(
  schema: JsonSchema,
  nested: boolean,
  operand: boolean,
  preserve = false,
): JsonSchema {
  const { $ref, additionalProperties, allOf, anyOf, oneOf, properties } =
    schema;
  const hasConditional = "if" in schema && schema.if !== undefined;
  const hasComposition = Boolean(
    $ref || allOf || anyOf || oneOf || hasConditional,
  );
  const isObjectSchema = nested
    ? schema.type === "object"
    : schema.type === undefined || schema.type === "object";

  const keepsAdditionalProperties =
    Object.keys(properties ?? {}).length === 0 &&
    (typeof additionalProperties === "object" ||
      additionalProperties === true ||
      (nested && additionalProperties === undefined && !properties));

  // Child-value positions keep an `additionalProperties` the node declares:
  // a value schema's openness is part of what the collection means, while a
  // property's own openness is normalized like the root's.
  const closesNode =
    !operand &&
    !hasComposition &&
    isObjectSchema &&
    !keepsAdditionalProperties &&
    (!preserve || additionalProperties === undefined);

  const next: Record<string, unknown> = {
    ...schema,
    ...(closesNode ? { additionalProperties: false } : {}),
  };

  if (properties) {
    next.properties = Object.fromEntries(
      Object.entries(properties).map(([key, value]) => [
        key,
        isSchemaRecord(value) ? strictSchemaNode(value, true, false) : value,
      ]),
    );
  }

  // Value positions hold ordinary object occurrences, so their nested objects
  // are closed like any property. Matching positions (`if`, `not`, `contains`,
  // `propertyNames`, `unevaluated*`) stay as declared: closing them would
  // change what the constraint matches. `$defs` and `definitions` are also
  // left alone: a definition may be referenced from a composition operand,
  // which must keep its own `additionalProperties` to accept keys declared by
  // sibling branches.
  for (const keyword of ["items", "additionalItems", "prefixItems"] as const) {
    const child = (schema as Record<string, unknown>)[keyword];
    if (Array.isArray(child)) {
      next[keyword] = child.map((item) =>
        isSchemaRecord(item) ? strictSchemaNode(item, true, false, true) : item,
      );
    } else if (isSchemaRecord(child)) {
      next[keyword] = strictSchemaNode(child, true, false, true);
    }
  }

  const patternProperties = (schema as Record<string, unknown>)
    .patternProperties;
  if (isSchemaRecord(patternProperties)) {
    next.patternProperties = Object.fromEntries(
      Object.entries(patternProperties).map(([key, value]) => [
        key,
        isSchemaRecord(value)
          ? strictSchemaNode(value, true, false, true)
          : value,
      ]),
    );
  }

  if (isSchemaRecord(next.additionalProperties)) {
    next.additionalProperties = strictSchemaNode(
      next.additionalProperties,
      true,
      false,
      true,
    );
  }

  for (const keyword of ["allOf", "anyOf", "oneOf"] as const) {
    const branches = (schema as Record<string, unknown>)[keyword];
    if (Array.isArray(branches)) {
      next[keyword] = branches.map((branch) =>
        isSchemaRecord(branch) ? strictSchemaNode(branch, true, true) : branch,
      );
    }
  }

  for (const keyword of ["else", "then"] as const) {
    const branch = (schema as Record<string, unknown>)[keyword];
    if (isSchemaRecord(branch)) {
      next[keyword] = strictSchemaNode(branch, true, true);
    }
  }

  return next as JsonSchema;
}
