import { expect, test } from "vitest";

import type {
  BundledOpenApiDocument,
  HttpRoute,
  OpenApiSchema,
} from "./types.js";

import {
  buildFlatSchema,
  buildOutputSchema,
  buildSharedDefs,
} from "./schemas.js";

function route(overrides: Partial<HttpRoute>): HttpRoute {
  return {
    deprecated: false,
    method: "post",
    parameters: [],
    path: "/x",
    tags: [],
    ...overrides,
  };
}

test("a path param and a body property with the same name: path gets suffixed, body keeps its bare name", () => {
  const { flatSchema, parameterMap } = buildFlatSchema(
    route({
      parameters: [
        { in: "path", name: "id", required: true, schema: { type: "string" } },
      ],
      requestBody: {
        content: {
          "application/json": {
            schema: {
              properties: { id: { type: "integer" }, name: { type: "string" } },
              required: ["id"],
              type: "object",
            },
          },
        },
      },
    }),
    undefined,
  );

  expect(Object.keys(flatSchema.properties!).sort()).toEqual([
    "id",
    "id__path",
    "name",
  ]);
  expect(parameterMap["id__path"]).toEqual({ in: "path", name: "id" });
  expect(parameterMap.id).toEqual({ in: "body", name: "id" });
  expect(flatSchema.required).toContain("id__path");
  expect(flatSchema.required).toContain("id"); // body's own `required: ["id"]`
});

test("no collision: names are left bare", () => {
  const { parameterMap } = buildFlatSchema(
    route({
      parameters: [{ in: "query", name: "status", schema: { type: "string" } }],
    }),
    undefined,
  );

  expect(parameterMap.status).toEqual({ in: "query", name: "status" });
});

test("path parameters are always required, regardless of the `required` flag", () => {
  const { flatSchema } = buildFlatSchema(
    route({
      parameters: [
        { in: "path", name: "id", schema: { type: "string" } }, // no `required: true`
      ],
    }),
    undefined,
  );

  expect(flatSchema.required).toContain("id");
});

test("a non-object request body is exposed as a single `body` property", () => {
  const { flatSchema, parameterMap, wholeBodyKey } = buildFlatSchema(
    route({
      requestBody: {
        content: {
          "application/json": {
            schema: { items: { type: "string" }, type: "array" },
          },
        },
        required: true,
      },
    }),
    undefined,
  );

  expect(wholeBodyKey).toBe("body");
  expect(parameterMap.body).toEqual({ in: "body", name: "body" });
  expect(flatSchema.properties!.body).toEqual({
    items: { type: "string" },
    type: "array",
  });
  expect(flatSchema.required).toContain("body");
});

test("buildSharedDefs rewrites #/components/schemas refs to #/$defs, embedded per-tool", () => {
  const document: BundledOpenApiDocument = {
    components: {
      schemas: {
        Pet: {
          properties: { tag: { $ref: "#/components/schemas/Tag" } },
          type: "object",
        },
        Tag: { type: "string" },
      },
    },
  };

  const defs = buildSharedDefs(document);
  expect(defs!.Pet.properties).toEqual({ tag: { $ref: "#/$defs/Tag" } });

  const { flatSchema } = buildFlatSchema(
    route({
      requestBody: {
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/Pet" },
          },
        },
      },
    }),
    defs,
  );

  // The bare $ref body case: rewritten the same way, and $defs travels with
  // the tool's own schema so AJV can resolve it standalone.
  expect(flatSchema.properties!.body).toEqual({ $ref: "#/$defs/Pet" });
  // Both Pet (directly referenced) and Tag (transitively, via Pet) travel
  // with the tool — but as a filtered copy, not the whole shared map.
  expect(flatSchema.$defs).toEqual(defs);
});

test("$defs are filtered to what a tool's schema actually (transitively) references", () => {
  const document: BundledOpenApiDocument = {
    components: {
      schemas: {
        Pet: { type: "object" },
        Unrelated: { type: "string" },
      },
    },
  };

  const defs = buildSharedDefs(document);

  const { flatSchema } = buildFlatSchema(
    route({
      requestBody: {
        content: {
          "application/json": {
            schema: {
              properties: { pet: { $ref: "#/components/schemas/Pet" } },
              type: "object",
            },
          },
        },
      },
    }),
    defs,
  );

  expect(flatSchema.$defs).toEqual({ Pet: { type: "object" } });
});

test("no $defs key is added when a tool's schema references nothing shared", () => {
  const document: BundledOpenApiDocument = {
    components: { schemas: { Pet: { type: "object" } } },
  };

  const { flatSchema } = buildFlatSchema(
    route({
      parameters: [{ in: "query", name: "status", schema: { type: "string" } }],
    }),
    buildSharedDefs(document),
  );

  expect(flatSchema.$defs).toBeUndefined();
});

test("`nullable: true` alongside a `type` is folded into a type array", () => {
  const { flatSchema } = buildFlatSchema(
    route({
      parameters: [
        {
          in: "query",
          name: "status",
          schema: { nullable: true, type: "string" },
        },
      ],
    }),
    undefined,
  );

  expect(flatSchema.properties!.status).toEqual({ type: ["string", "null"] });
});

test("`nullable` with no sibling `type` (e.g. next to `oneOf`) is dropped rather than left for AJV to reject", () => {
  const { flatSchema } = buildFlatSchema(
    route({
      parameters: [
        {
          in: "query",
          name: "length",
          schema: {
            nullable: false,
            oneOf: [{ type: "string" }, { type: "integer" }],
          },
        },
      ],
    }),
    undefined,
  );

  expect(flatSchema.properties!.length).toEqual({
    oneOf: [{ type: "string" }, { type: "integer" }],
  });
});

test("GET never contributes a request body — fetch rejects a body on GET, so it would be permanently broken", () => {
  const { flatSchema, parameterMap, wholeBodyKey } = buildFlatSchema(
    route({
      method: "get",
      requestBody: {
        content: {
          "application/json": {
            schema: {
              properties: { q: { type: "string" } },
              type: "object",
            },
          },
        },
      },
    }),
    undefined,
  );

  expect(flatSchema.properties).toEqual({});
  expect(parameterMap).toEqual({});
  expect(wholeBodyKey).toBeUndefined();
});

test("GET's body skip happens before content-type inspection: a multipart-only body on a GET is not flagged unsupported", () => {
  const { bodyEncoding, unsupportedBodyContentType } = buildFlatSchema(
    route({
      method: "get",
      requestBody: {
        content: { "multipart/form-data": { schema: { type: "object" } } },
      },
    }),
    undefined,
  );

  expect(bodyEncoding).toBeUndefined();
  expect(unsupportedBodyContentType).toBeUndefined();
});

test("a form-urlencoded body is flattened like a JSON one, with bodyEncoding: 'form'", () => {
  const { bodyEncoding, flatSchema, parameterMap } = buildFlatSchema(
    route({
      requestBody: {
        content: {
          "application/x-www-form-urlencoded": {
            schema: {
              properties: {
                amount: { type: "integer" },
                currency: { type: "string" },
              },
              required: ["amount"],
              type: "object",
            },
          },
        },
      },
    }),
    undefined,
  );

  expect(bodyEncoding).toBe("form");
  expect(flatSchema.properties).toEqual({
    amount: { type: "integer" },
    currency: { type: "string" },
  });
  expect(parameterMap.amount).toEqual({ in: "body", name: "amount" });
  expect(flatSchema.required).toEqual(["amount"]);
});

test("application/json is preferred over form-urlencoded when a route declares both", () => {
  const { bodyEncoding, flatSchema } = buildFlatSchema(
    route({
      requestBody: {
        content: {
          "application/json": {
            schema: {
              properties: { fromJson: { type: "string" } },
              type: "object",
            },
          },
          "application/x-www-form-urlencoded": {
            schema: {
              properties: { fromForm: { type: "string" } },
              type: "object",
            },
          },
        },
      },
    }),
    undefined,
  );

  expect(bodyEncoding).toBe("json");
  expect(flatSchema.properties).toEqual({ fromJson: { type: "string" } });
});

test("a request body declared only in an unsupported content type is signaled for skipping, not silently emptied", () => {
  const { flatSchema, unsupportedBodyContentType } = buildFlatSchema(
    route({
      requestBody: {
        content: { "multipart/form-data": { schema: { type: "object" } } },
      },
    }),
    undefined,
  );

  expect(unsupportedBodyContentType).toBe("multipart/form-data");
  expect(flatSchema.properties).toEqual({});
});

test("a requestBody with no content types at all is treated as no body, not unsupported", () => {
  const { bodyEncoding, unsupportedBodyContentType } = buildFlatSchema(
    route({ requestBody: { content: {} } }),
    undefined,
  );

  expect(bodyEncoding).toBeUndefined();
  expect(unsupportedBodyContentType).toBeUndefined();
});

test("a supported content type declared with no schema at all (an unconstrained body) is not flagged unsupported", () => {
  const { bodyEncoding, flatSchema, unsupportedBodyContentType } =
    buildFlatSchema(
      route({ requestBody: { content: { "application/json": {} } } }),
      undefined,
    );

  expect(bodyEncoding).toBe("json");
  expect(unsupportedBodyContentType).toBeUndefined();
  expect(flatSchema.properties).toEqual({});
});

test("a non-object form-urlencoded body is reported unsupported, since form encoding can't represent it", () => {
  const { bodyEncoding, unsupportedBodyContentType, wholeBodyKey } =
    buildFlatSchema(
      route({
        requestBody: {
          content: {
            "application/x-www-form-urlencoded": {
              schema: { items: { type: "string" }, type: "array" },
            },
          },
        },
      }),
      undefined,
    );

  expect(unsupportedBodyContentType).toBe("application/x-www-form-urlencoded");
  expect(bodyEncoding).toBeUndefined();
  expect(wholeBodyKey).toBeUndefined();
});

test("a body property literally named `nullable` is a field name, not the OpenAPI keyword, and survives", () => {
  const { flatSchema } = buildFlatSchema(
    route({
      requestBody: {
        content: {
          "application/json": {
            schema: {
              properties: {
                column: {
                  properties: {
                    name: { type: "string" },
                    nullable: { type: "boolean" },
                  },
                  type: "object",
                },
              },
              type: "object",
            },
          },
        },
      },
    }),
    undefined,
  );

  expect(flatSchema.properties!.column).toEqual({
    properties: {
      name: { type: "string" },
      nullable: { type: "boolean" },
    },
    type: "object",
  });
});

test("a component schema named `nullable` survives, while a real `nullable: true` keyword still folds into `type`", () => {
  const document = {
    components: {
      schemas: {
        Column: {
          properties: { label: { nullable: true, type: "string" } },
          type: "object",
        },
        nullable: { type: "boolean" },
      },
    },
  } as unknown as BundledOpenApiDocument;

  expect(buildSharedDefs(document)).toEqual({
    Column: {
      properties: { label: { type: ["string", "null"] } },
      type: "object",
    },
    nullable: { type: "boolean" },
  });
});

test("`default` payload is instance data, not a schema, and is passed through verbatim", () => {
  const { flatSchema } = buildFlatSchema(
    route({
      requestBody: {
        content: {
          "application/json": {
            schema: {
              properties: {
                config: {
                  default: { $ref: "#/components/schemas/X", nullable: 1 },
                  type: "object",
                },
              },
              type: "object",
            },
          },
        },
      },
    }),
    undefined,
  );

  expect(flatSchema.properties!.config).toEqual({
    default: { $ref: "#/components/schemas/X", nullable: 1 },
    type: "object",
  });
});

test("`example`/`examples` are dropped entirely, not just left unwalked — a real sample payload can coincidentally contain JSON-Schema-keyword-shaped keys (e.g. Box's own `$id` field) that would otherwise confuse AJV's $id discovery", () => {
  const { flatSchema } = buildFlatSchema(
    route({
      parameters: [
        {
          in: "query",
          name: "metadata",
          schema: {
            example: { $id: "01234500-12f1-1234-aa12-b1d234cb567e" },
            examples: [{ $id: "01234500-12f1-1234-aa12-b1d234cb567e" }],
            type: "object",
          },
        },
      ],
    }),
    undefined,
  );

  expect(flatSchema.properties!.metadata).toEqual({ type: "object" });
});

test("a property literally named `example` (inside `properties`, a schemaMap) is a field name, not the annotation keyword, and survives", () => {
  const { flatSchema } = buildFlatSchema(
    route({
      requestBody: {
        content: {
          "application/json": {
            schema: {
              properties: { example: { type: "string" } },
              type: "object",
            },
          },
        },
      },
    }),
    undefined,
  );

  expect(flatSchema.properties!.example).toEqual({ type: "string" });
});

test("a form-urlencoded body declared as a `$ref` to a component object schema is resolved and flattened (FastAPI's `Body_<operation>` shape)", () => {
  const document: BundledOpenApiDocument = {
    components: {
      schemas: {
        Body_login: {
          properties: {
            grant_type: { $ref: "#/components/schemas/GrantType" },
            password: { type: "string" },
            username: { type: "string" },
          },
          required: ["username", "password"],
          type: "object",
        },
        GrantType: { enum: ["password"], type: "string" },
      },
    },
  };

  const { bodyEncoding, flatSchema, parameterMap, unsupportedBodyContentType } =
    buildFlatSchema(
      route({
        requestBody: {
          content: {
            "application/x-www-form-urlencoded": {
              schema: { $ref: "#/components/schemas/Body_login" },
            },
          },
          required: true,
        },
      }),
      buildSharedDefs(document),
    );

  expect(unsupportedBodyContentType).toBeUndefined();
  expect(bodyEncoding).toBe("form");
  expect(Object.keys(flatSchema.properties!).sort()).toEqual([
    "grant_type",
    "password",
    "username",
  ]);
  expect([...flatSchema.required!].sort()).toEqual(["password", "username"]);
  expect(parameterMap.username).toEqual({ in: "body", name: "username" });
  // A property that itself references a shared schema still travels with
  // the tool as a filtered $defs entry, exactly as an inline body would —
  // while the resolved body schema itself is inlined, not carried as a def.
  expect(flatSchema.properties!.grant_type).toEqual({
    $ref: "#/$defs/GrantType",
  });
  expect(flatSchema.$defs).toEqual({
    GrantType: { enum: ["password"], type: "string" },
  });
});

test("a form-urlencoded `$ref` is followed through an alias chain to the object it ends at", () => {
  const document: BundledOpenApiDocument = {
    components: {
      schemas: {
        Credentials: { $ref: "#/components/schemas/LoginForm" },
        LoginForm: {
          properties: { username: { type: "string" } },
          type: "object",
        },
      },
    },
  };

  const { bodyEncoding, flatSchema } = buildFlatSchema(
    route({
      requestBody: {
        content: {
          "application/x-www-form-urlencoded": {
            schema: { $ref: "#/components/schemas/Credentials" },
          },
        },
      },
    }),
    buildSharedDefs(document),
  );

  expect(bodyEncoding).toBe("form");
  expect(flatSchema.properties).toEqual({ username: { type: "string" } });
});

test("a form-urlencoded `$ref` that resolves to a non-object schema is still reported unsupported", () => {
  const document: BundledOpenApiDocument = {
    components: {
      schemas: { Ids: { items: { type: "string" }, type: "array" } },
    },
  };

  const { bodyEncoding, unsupportedBodyContentType, wholeBodyKey } =
    buildFlatSchema(
      route({
        requestBody: {
          content: {
            "application/x-www-form-urlencoded": {
              schema: { $ref: "#/components/schemas/Ids" },
            },
          },
        },
      }),
      buildSharedDefs(document),
    );

  expect(unsupportedBodyContentType).toBe("application/x-www-form-urlencoded");
  expect(bodyEncoding).toBeUndefined();
  expect(wholeBodyKey).toBeUndefined();
});

test("a form-urlencoded `$ref` that can't be resolved is reported unsupported rather than throwing", () => {
  const { unsupportedBodyContentType } = buildFlatSchema(
    route({
      requestBody: {
        content: {
          "application/x-www-form-urlencoded": {
            schema: { $ref: "#/components/schemas/Missing" },
          },
        },
      },
    }),
    undefined,
  );

  expect(unsupportedBodyContentType).toBe("application/x-www-form-urlencoded");
});

test("a query parameter's `style` is threaded into its parameterMap entry", () => {
  const { parameterMap } = buildFlatSchema(
    route({
      parameters: [
        {
          in: "query",
          name: "created",
          schema: { type: "object" },
          style: "deepObject",
        },
      ],
    }),
    undefined,
  );

  expect(parameterMap.created).toEqual({
    in: "query",
    name: "created",
    style: "deepObject",
  });
});

test("buildOutputSchema picks the first 2xx application/json response schema", () => {
  const schema = buildOutputSchema(
    route({
      responses: {
        "200": {
          content: {
            "application/json": {
              schema: {
                properties: { id: { type: "integer" } },
                type: "object",
              },
            },
          },
        },
        "400": {
          content: {
            "application/json": { schema: { type: "object" } },
          },
        },
      },
    }),
    undefined,
  );

  expect(schema).toEqual({
    properties: { id: { type: "integer" } },
    type: "object",
  });
});

test("buildOutputSchema skips a response that's explicitly non-object (e.g. an array)", () => {
  const schema = buildOutputSchema(
    route({
      responses: {
        "200": {
          content: {
            "application/json": {
              schema: { items: { type: "string" }, type: "array" },
            },
          },
        },
      },
    }),
    undefined,
  );

  expect(schema).toBeUndefined();
});

test("buildOutputSchema resolves a bare $ref to the object it points to, rather than advertising an unresolved $ref", () => {
  // The MCP SDK's client-side tools/list validation requires an advertised
  // outputSchema.type to literally be "object" — an unresolved bare $ref
  // (no top-level type) fails that check and breaks tools/list for every
  // tool in the response, not just this one. A response schema being a
  // bare $ref (e.g. `{ $ref: "#/components/schemas/Pet" }`) is extremely
  // common, so this has to resolve it, not just accept or reject it as-is.
  const document: BundledOpenApiDocument = {
    components: { schemas: { Pet: { type: "object" } } },
  };

  const schema = buildOutputSchema(
    route({
      responses: {
        "200": {
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/Pet" },
            },
          },
        },
      },
    }),
    buildSharedDefs(document),
  );

  expect(schema).toEqual({ type: "object" });
});

test("buildOutputSchema still attaches $defs when the resolved object itself references another component", () => {
  const document: BundledOpenApiDocument = {
    components: {
      schemas: {
        Pet: {
          properties: { tag: { $ref: "#/components/schemas/Tag" } },
          type: "object",
        },
        Tag: { type: "string" },
      },
    },
  };

  const schema = buildOutputSchema(
    route({
      responses: {
        "200": {
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/Pet" },
            },
          },
        },
      },
    }),
    buildSharedDefs(document),
  );

  expect(schema).toEqual({
    $defs: { Tag: { type: "string" } },
    properties: { tag: { $ref: "#/$defs/Tag" } },
    type: "object",
  });
});

test("buildOutputSchema skips a response whose $ref doesn't resolve to an object (or doesn't resolve at all)", () => {
  const document: BundledOpenApiDocument = {
    components: {
      schemas: { PetIds: { items: { type: "integer" }, type: "array" } },
    },
  };

  const arraySchema = buildOutputSchema(
    route({
      responses: {
        "200": {
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/PetIds" },
            },
          },
        },
      },
    }),
    buildSharedDefs(document),
  );

  expect(arraySchema).toBeUndefined();

  const danglingSchema = buildOutputSchema(
    route({
      responses: {
        "200": {
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/Missing" },
            },
          },
        },
      },
    }),
    buildSharedDefs(document),
  );

  expect(danglingSchema).toBeUndefined();
});

test("buildOutputSchema does not set additionalProperties: false — an undocumented extra field is the most common form of drift", () => {
  const schema = buildOutputSchema(
    route({
      responses: {
        "200": {
          content: {
            "application/json": {
              schema: {
                properties: { id: { type: "integer" } },
                type: "object",
              },
            },
          },
        },
      },
    }),
    undefined,
  );

  expect(schema?.additionalProperties).toBeUndefined();
});

test("buildOutputSchema returns undefined when there's no 2xx response with a JSON schema", () => {
  const schema = buildOutputSchema(
    route({ responses: { "204": { content: {} } } }),
    undefined,
  );

  expect(schema).toBeUndefined();
});

test("buildOutputSchema normalizes an inline nullable object response to the literal type 'object', not an array", () => {
  // The MCP SDK's tools/list validation requires outputSchema.type to be
  // literally the string "object" — rewriteComponentRefs folds `nullable:
  // true` into `type: ["object", "null"]`, which would fail that check
  // (breaking tools/list for every tool, not just this one) if the
  // object-shape check ran before normalization instead of after.
  const schema = buildOutputSchema(
    route({
      responses: {
        "200": {
          content: {
            "application/json": {
              schema: {
                nullable: true,
                properties: { id: { type: "string" } },
                type: "object",
              },
            },
          },
        },
      },
    }),
    undefined,
  );

  expect(schema?.type).toBe("object");
});

test("buildOutputSchema normalizes a $ref to an already-nullable shared def to the literal type 'object'", () => {
  // buildSharedDefs already normalizes nullable when building $defs, so a
  // $ref target arrives with type: ["object", "null"] rather than a
  // `nullable` keyword to fold — the same normalization has to apply here
  // too, not just to inline schemas.
  const document: BundledOpenApiDocument = {
    components: {
      schemas: {
        Pet: {
          nullable: true,
          properties: { id: { type: "string" } },
          type: "object",
        },
      },
    },
  };

  const schema = buildOutputSchema(
    route({
      responses: {
        "200": {
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/Pet" },
            },
          },
        },
      },
    }),
    buildSharedDefs(document),
  );

  expect(schema?.type).toBe("object");
});

test("buildOutputSchema skips wiring when the schema transitively references too many definitions", () => {
  // Real "core" response objects (Stripe's Charge/Customer/PaymentIntent)
  // routinely reference hundreds of other types this way — measured
  // directly, the median Stripe operation's output schema pulled in 868
  // definitions, and the full tools/list response across all 588
  // operations would have been ~320MB. A schema built from a document with
  // 60 mutually-independent, transitively-reachable defs exercises the cap
  // without needing a fixture that large.
  const schemas: Record<string, OpenApiSchema> = {
    Root: {
      properties: { child: { $ref: "#/components/schemas/Def0" } },
      type: "object",
    },
  };

  for (let i = 0; i < 60; i++) {
    schemas[`Def${i}`] = {
      properties:
        i < 59 ? { next: { $ref: `#/components/schemas/Def${i + 1}` } } : {},
      type: "object",
    };
  }

  const document: BundledOpenApiDocument = { components: { schemas } };

  const schema = buildOutputSchema(
    route({
      responses: {
        "200": {
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/Root" },
            },
          },
        },
      },
    }),
    buildSharedDefs(document),
  );

  expect(schema).toBeUndefined();
});
