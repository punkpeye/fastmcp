import { expect, test } from "vitest";

import type { BundledOpenApiDocument, HttpRoute } from "./types.js";

import { buildFlatSchema, buildSharedDefs } from "./schemas.js";

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

test("`example`/`default` payloads are instance data, not schemas, and are passed through verbatim", () => {
  const { flatSchema } = buildFlatSchema(
    route({
      requestBody: {
        content: {
          "application/json": {
            schema: {
              properties: {
                config: {
                  default: { $ref: "#/components/schemas/X", nullable: 1 },
                  example: { nullable: "yes" },
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
    example: { nullable: "yes" },
    type: "object",
  });
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
