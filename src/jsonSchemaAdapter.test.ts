import { expect, test } from "vitest";
import { jsonSchemaAdapter } from "./jsonSchemaAdapter.js";

test("jsonSchemaAdapter validates valid input", async () => {
  const schema = jsonSchemaAdapter({
    type: "object",
    properties: {
      name: { type: "string" },
      age: { type: "number" },
    },
    required: ["name"],
  });

  const result = await schema["~standard"].validate({ name: "Alice", age: 30 });
  expect(result.issues).toBeUndefined();
  expect(result.value).toEqual({ name: "Alice", age: 30 });
});

test("jsonSchemaAdapter returns issues for invalid input", async () => {
  const schema = jsonSchemaAdapter({
    type: "object",
    properties: {
      name: { type: "string" },
      age: { type: "number" },
    },
    required: ["name"],
  });

  const result = await schema["~standard"].validate({ age: "not a number" });
  expect(result.issues).toBeDefined();
  expect(result.issues!.length).toBeGreaterThan(0);
});

test("jsonSchemaAdapter exposes __jsonSchema for fast-path", () => {
  const raw = {
    type: "object",
    properties: {
      x: { type: "string" },
    },
    required: ["x"],
  };
  const schema = jsonSchemaAdapter(raw);
  expect(schema.__jsonSchema).toBe(raw);
});

test("jsonSchemaAdapter sets vendor to json-schema", () => {
  const schema = jsonSchemaAdapter({
    type: "object",
    properties: {},
  });
  expect(schema["~standard"].vendor).toBe("json-schema");
  expect(schema["~standard"].version).toBe(1);
});

test("jsonSchemaAdapter validates nested objects", async () => {
  const schema = jsonSchemaAdapter({
    type: "object",
    properties: {
      address: {
        type: "object",
        properties: {
          street: { type: "string" },
          zip: { type: "string" },
        },
        required: ["street"],
      },
    },
    required: ["address"],
  });

  const valid = await schema["~standard"].validate({
    address: { street: "123 Main St", zip: "12345" },
  });
  expect(valid.issues).toBeUndefined();

  const invalid = await schema["~standard"].validate({
    address: { zip: "12345" },
  });
  expect(invalid.issues).toBeDefined();
  expect(invalid.issues!.length).toBeGreaterThan(0);
});
