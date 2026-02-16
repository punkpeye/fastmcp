import { expect, test, describe } from "vitest";
import { buildToolParameters, classifyRoute, extractRoutes } from "./openapi.js";
import type { OpenAPIDocument } from "./openapi.js";

const petStoreSpec: OpenAPIDocument = {
  openapi: "3.0.0",
  info: { title: "Pet Store", version: "1.0.0" },
  paths: {
    "/pets": {
      get: {
        operationId: "listPets",
        summary: "List all pets",
        parameters: [
          {
            name: "limit",
            in: "query",
            schema: { type: "integer", minimum: 1, maximum: 100 },
            description: "Max number of pets to return",
          },
        ],
        responses: { "200": { description: "A list of pets" } },
      },
      post: {
        operationId: "createPet",
        summary: "Create a pet",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  name: { type: "string", description: "Pet name" },
                  tag: { type: "string" },
                },
                required: ["name"],
              },
            },
          },
        },
        responses: { "201": { description: "Pet created" } },
      },
    },
    "/pets/{petId}": {
      get: {
        operationId: "getPet",
        summary: "Get a pet by ID",
        parameters: [
          {
            name: "petId",
            in: "path",
            required: true,
            schema: { type: "string" },
            description: "The pet ID",
          },
        ],
        responses: { "200": { description: "A pet" } },
      },
      delete: {
        operationId: "deletePet",
        summary: "Delete a pet",
        parameters: [
          {
            name: "petId",
            in: "path",
            required: true,
            schema: { type: "string" },
          },
        ],
        responses: { "204": { description: "Pet deleted" } },
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
      type: "object",
      properties: {
        limit: {
          type: "integer",
          minimum: 1,
          maximum: 100,
          description: "Max number of pets to return",
        },
      },
      required: undefined,
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
      openapi: "3.0.0",
      info: { title: "Ref Test", version: "1.0.0" },
      paths: {
        "/items": {
          post: {
            operationId: "createItem",
            summary: "Create an item",
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/Item" },
                },
              },
            },
            responses: { "201": { description: "Created" } },
          },
        },
      },
      components: {
        schemas: {
          Item: {
            type: "object",
            properties: {
              name: { type: "string" },
              value: { type: "number" },
            },
            required: ["name"],
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
