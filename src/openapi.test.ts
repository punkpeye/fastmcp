import { describe, expect, test } from "vitest";

import type { OpenAPIDocument } from "./openapi.js";

import {
  buildToolParameters,
  classifyRoute,
  extractRoutes,
} from "./openapi.js";

const petStoreSpec: OpenAPIDocument = {
  info: { title: "Pet Store", version: "1.0.0" },
  openapi: "3.0.0",
  paths: {
    "/pets": {
      get: {
        operationId: "listPets",
        parameters: [
          {
            description: "Max number of pets to return",
            in: "query",
            name: "limit",
            schema: { maximum: 100, minimum: 1, type: "integer" },
          },
        ],
        responses: { "200": { description: "A list of pets" } },
        summary: "List all pets",
      },
      post: {
        operationId: "createPet",
        requestBody: {
          content: {
            "application/json": {
              schema: {
                properties: {
                  name: { description: "Pet name", type: "string" },
                  tag: { type: "string" },
                },
                required: ["name"],
                type: "object",
              },
            },
          },
          required: true,
        },
        responses: { "201": { description: "Pet created" } },
        summary: "Create a pet",
      },
    },
    "/pets/{petId}": {
      delete: {
        operationId: "deletePet",
        parameters: [
          {
            in: "path",
            name: "petId",
            required: true,
            schema: { type: "string" },
          },
        ],
        responses: { "204": { description: "Pet deleted" } },
        summary: "Delete a pet",
      },
      get: {
        operationId: "getPet",
        parameters: [
          {
            description: "The pet ID",
            in: "path",
            name: "petId",
            required: true,
            schema: { type: "string" },
          },
        ],
        responses: { "200": { description: "A pet" } },
        summary: "Get a pet by ID",
      },
    },
  },
};

describe("extractRoutes", () => {
  test("extracts all routes from a spec", () => {
    const routes = extractRoutes(petStoreSpec);
    expect(routes).toHaveLength(4);
    expect(routes.map((r) => r.operationId).sort()).toEqual([
      "createPet",
      "deletePet",
      "getPet",
      "listPets",
    ]);
  });

  test("extracts parameters correctly", () => {
    const routes = extractRoutes(petStoreSpec);
    const listPets = routes.find((r) => r.operationId === "listPets")!;
    expect(listPets.parameters).toHaveLength(1);
    expect(listPets.parameters[0].name).toBe("limit");
    expect(listPets.parameters[0].in).toBe("query");
  });

  test("extracts request body", () => {
    const routes = extractRoutes(petStoreSpec);
    const createPet = routes.find((r) => r.operationId === "createPet")!;
    expect(createPet.requestBody).toBeDefined();
  });
});

describe("classifyRoute", () => {
  test("classifies GET without path params as resource", () => {
    const routes = extractRoutes(petStoreSpec);
    const listPets = routes.find((r) => r.operationId === "listPets")!;
    expect(classifyRoute(listPets)).toBe("resource");
  });

  test("classifies GET with path params as resourceTemplate", () => {
    const routes = extractRoutes(petStoreSpec);
    const getPet = routes.find((r) => r.operationId === "getPet")!;
    expect(classifyRoute(getPet)).toBe("resourceTemplate");
  });

  test("classifies POST as tool", () => {
    const routes = extractRoutes(petStoreSpec);
    const createPet = routes.find((r) => r.operationId === "createPet")!;
    expect(classifyRoute(createPet)).toBe("tool");
  });

  test("classifies DELETE as tool", () => {
    const routes = extractRoutes(petStoreSpec);
    const deletePet = routes.find((r) => r.operationId === "deletePet")!;
    expect(classifyRoute(deletePet)).toBe("tool");
  });
});

describe("buildToolParameters", () => {
  test("builds parameters for a route with query params", () => {
    const routes = extractRoutes(petStoreSpec);
    const listPets = routes.find((r) => r.operationId === "listPets")!;
    const params = buildToolParameters(petStoreSpec, listPets);

    expect(params.jsonSchema).toEqual({
      properties: {
        limit: {
          description: "Max number of pets to return",
          maximum: 100,
          minimum: 1,
          type: "integer",
        },
      },
      required: undefined,
      type: "object",
    });
  });

  test("builds parameters for a route with path params", () => {
    const routes = extractRoutes(petStoreSpec);
    const getPet = routes.find((r) => r.operationId === "getPet")!;
    const params = buildToolParameters(petStoreSpec, getPet);

    expect(params.jsonSchema.properties).toHaveProperty("petId");
    expect(params.jsonSchema.required).toContain("petId");
  });

  test("builds parameters for a route with request body", () => {
    const routes = extractRoutes(petStoreSpec);
    const createPet = routes.find((r) => r.operationId === "createPet")!;
    const params = buildToolParameters(petStoreSpec, createPet);

    expect(params.jsonSchema.properties).toHaveProperty("body_name");
    expect(params.jsonSchema.properties).toHaveProperty("body_tag");
    expect(params.jsonSchema.required).toContain("body_name");
  });
});

describe("$ref resolution", () => {
  test("resolves $ref in schemas", () => {
    const specWithRefs: OpenAPIDocument = {
      components: {
        schemas: {
          Item: {
            properties: {
              name: { type: "string" },
              value: { type: "number" },
            },
            required: ["name"],
            type: "object",
          },
        },
      },
      info: { title: "Ref Test", version: "1.0.0" },
      openapi: "3.0.0",
      paths: {
        "/items": {
          post: {
            operationId: "createItem",
            requestBody: {
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/Item" },
                },
              },
              required: true,
            },
            responses: { "201": { description: "Created" } },
            summary: "Create an item",
          },
        },
      },
    };

    const routes = extractRoutes(specWithRefs);
    expect(routes).toHaveLength(1);

    const params = buildToolParameters(specWithRefs, routes[0]);
    expect(params.jsonSchema.properties).toHaveProperty("body_name");
    expect(params.jsonSchema.properties).toHaveProperty("body_value");
  });
});
