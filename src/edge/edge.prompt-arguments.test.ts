import { ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it, vi } from "vitest";

import { EdgeFastMCP } from "./index.js";

const getPrompt = async (server: EdgeFastMCP, params: unknown) => {
  const response = await server.fetch(
    new Request("http://localhost/mcp", {
      body: JSON.stringify({
        id: 1,
        jsonrpc: "2.0",
        method: "prompts/get",
        params,
      }),
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      method: "POST",
    }),
  );
  expect(response.status).toBe(200);
  return (await response.json()) as unknown;
};

describe("EdgeFastMCP prompt parameters", () => {
  it.each([
    { args: null, label: "null" },
    { args: [], label: "an empty array" },
    { args: ["value"], label: "an array" },
    { args: "", label: "an empty string" },
    { args: "value", label: "a string" },
    { args: 42, label: "a number" },
    { args: false, label: "a boolean" },
    { args: { changes: null }, label: "a null member" },
    { args: { changes: false }, label: "a boolean member" },
    { args: { changes: [] }, label: "an array member" },
    { args: { changes: {} }, label: "an object member" },
    {
      args: Object.fromEntries([["__proto__", 42]]),
      label: "a non-string __proto__ member",
    },
  ])("rejects $label before calling an optional prompt", async ({ args }) => {
    const server = new EdgeFastMCP({ name: "Test", version: "1.0.0" });
    const load = vi.fn(async () => "loaded");
    server.addPrompt({ load, name: "optional" });

    expect(
      await getPrompt(server, { arguments: args, name: "optional" }),
    ).toMatchObject({
      error: { code: ErrorCode.InvalidParams },
      id: 1,
      jsonrpc: "2.0",
    });
    expect(load).not.toHaveBeenCalled();
  });

  it.each([
    { args: undefined, expected: {}, label: "omitted arguments" },
    { args: {}, expected: {}, label: "an empty map" },
    {
      args: { changes: "", extra: "value" },
      expected: { changes: "", extra: "value" },
      label: "empty strings and undeclared arguments",
    },
    {
      args: { constructor: "value", toString: "text" },
      expected: { constructor: "value", toString: "text" },
      label: "Object.prototype property names",
    },
  ])("preserves $label", async ({ args, expected }) => {
    const server = new EdgeFastMCP({ name: "Test", version: "1.0.0" });
    const load = vi.fn(async () => "loaded");
    server.addPrompt({ load, name: "optional" });

    expect(
      await getPrompt(server, { arguments: args, name: "optional" }),
    ).toMatchObject({
      result: {
        messages: [{ content: { text: "loaded", type: "text" }, role: "user" }],
      },
    });
    expect(load).toHaveBeenCalledExactlyOnceWith(expected);
  });

  it("preserves an own __proto__ argument", async () => {
    const server = new EdgeFastMCP({ name: "Test", version: "1.0.0" });
    const load = vi.fn(
      async (args: Record<string, string>) => args["__proto__"],
    );
    server.addPrompt({
      arguments: [{ name: "__proto__", required: true }],
      load,
      name: "special",
    });

    expect(
      await getPrompt(server, {
        arguments: Object.fromEntries([["__proto__", "value"]]),
        name: "special",
      }),
    ).toMatchObject({
      result: {
        messages: [{ content: { text: "value", type: "text" }, role: "user" }],
      },
    });
    expect(load).toHaveBeenCalledOnce();
  });

  it("rejects non-string argument values before calling load", async () => {
    const server = new EdgeFastMCP({ name: "Test", version: "1.0.0" });
    const load = vi.fn(async (args: Record<string, string>) =>
      args.changes.toUpperCase(),
    );
    server.addPrompt({
      arguments: [{ name: "changes", required: true }],
      load,
      name: "commit",
    });

    expect(
      await getPrompt(server, { arguments: { changes: 42 }, name: "commit" }),
    ).toMatchObject({
      error: { code: ErrorCode.InvalidParams },
      id: 1,
      jsonrpc: "2.0",
    });
    expect(load).not.toHaveBeenCalled();
  });
});
