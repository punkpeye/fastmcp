import { expect, test } from "vitest";

import { jsonSchemaAdapter } from "./jsonSchemaAdapter.js";

test("jsonSchemaAdapter validates valid input", async () => {
  const schema = jsonSchemaAdapter({
    properties: {
      age: { type: "number" },
      name: { type: "string" },
    },
    required: ["name"],
    type: "object",
  });

  const result = await schema["~standard"].validate({ age: 30, name: "Alice" });
  expect(result.issues).toBeUndefined();
  if (result.issues === undefined) {
    expect(result.value).toEqual({ age: 30, name: "Alice" });
  }
});

test("jsonSchemaAdapter returns issues for invalid input", async () => {
  const schema = jsonSchemaAdapter({
    properties: {
      age: { type: "number" },
      name: { type: "string" },
    },
    required: ["name"],
    type: "object",
  });

  const result = await schema["~standard"].validate({ age: "not a number" });
  expect(result.issues).toBeDefined();
  expect(result.issues!.length).toBeGreaterThan(0);
});

test("jsonSchemaAdapter exposes __jsonSchema for fast-path", () => {
  const raw = {
    properties: {
      x: { type: "string" },
    },
    required: ["x"],
    type: "object",
  };
  const schema = jsonSchemaAdapter(raw);
  expect(schema.__jsonSchema).toBe(raw);
});

test("jsonSchemaAdapter sets vendor to json-schema", () => {
  const schema = jsonSchemaAdapter({
    properties: {},
    type: "object",
  });
  expect(schema["~standard"].vendor).toBe("json-schema");
  expect(schema["~standard"].version).toBe(1);
});

test("jsonSchemaAdapter validates nested objects", async () => {
  const schema = jsonSchemaAdapter({
    properties: {
      address: {
        properties: {
          street: { type: "string" },
          zip: { type: "string" },
        },
        required: ["street"],
        type: "object",
      },
    },
    required: ["address"],
    type: "object",
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
