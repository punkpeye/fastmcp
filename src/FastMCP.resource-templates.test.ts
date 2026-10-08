import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it, vi } from "vitest";

import { FastMCP } from "./FastMCP.js";

async function connect(server: FastMCP) {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "c", version: "0.0.0" });
  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);
  return client;
}

// RFC 6570 simple expansion ({name}) percent-encodes "/", "?" and "#", so no
// value of a simple variable can expand to a URI with an extra path segment,
// a query or a fragment.
describe("resource template matching", () => {
  it("does not let a {name} expression match across path segments", async () => {
    const server = new FastMCP({ name: "T", version: "1.0.0" });
    const load = vi.fn(async ({ name }: { name: string }) => ({
      text: `log ${name}`,
    }));
    server.addResourceTemplate({
      arguments: [{ name: "name", required: true }],
      load,
      mimeType: "text/plain",
      name: "Logs",
      uriTemplate: "file:///logs/{name}.log",
    });
    const client = await connect(server);
    try {
      await expect(
        client.readResource({ uri: "file:///logs/../../etc/passwd.log" }),
      ).rejects.toEqual(
        expect.objectContaining({ code: ErrorCode.InvalidParams }),
      );
      expect(load).not.toHaveBeenCalled();

      const result = await client.readResource({
        uri: "file:///logs/app.log",
      });
      expect(result.contents[0]).toMatchObject({ text: "log app" });
    } finally {
      await client.close();
      await server.stop();
    }
  });

  it("does not let a {name} expression take a query or a fragment", async () => {
    const server = new FastMCP({ name: "T", version: "1.0.0" });
    const load = vi.fn(async ({ id }: { id: string }) => ({
      text: `doc ${id}`,
    }));
    server.addResourceTemplate({
      arguments: [{ name: "id", required: true }],
      load,
      mimeType: "text/plain",
      name: "Docs",
      uriTemplate: "docs://{id}",
    });
    const client = await connect(server);
    try {
      for (const uri of ["docs://x?inject=1", "docs://x#frag"]) {
        await expect(client.readResource({ uri })).rejects.toEqual(
          expect.objectContaining({ code: ErrorCode.InvalidParams }),
        );
      }
      expect(load).not.toHaveBeenCalled();

      const encoded = await client.readResource({
        uri: "docs://x%3Finject%3D1",
      });
      expect(encoded.contents[0]).toMatchObject({ text: "doc x?inject=1" });
    } finally {
      await client.close();
      await server.stop();
    }
  });

  it("still matches a query expression given parameters it doesn't declare", async () => {
    const server = new FastMCP({ name: "T", version: "1.0.0" });
    const load = vi.fn(async ({ id }: { id: string }) => ({
      text: `doc ${id}`,
    }));
    server.addResourceTemplate({
      arguments: [{ name: "id", required: true }],
      load,
      mimeType: "text/plain",
      name: "Docs",
      uriTemplate: "docs://{id}{?q}",
    });
    const client = await connect(server);
    try {
      const result = await client.readResource({ uri: "docs://x?z=2" });
      expect(result.contents[0]).toMatchObject({ text: "doc x" });
    } finally {
      await client.close();
      await server.stop();
    }
  });

  it("does not let a broader template shadow a more specific one", async () => {
    const server = new FastMCP({ name: "T", version: "1.0.0" });
    server.addResourceTemplate({
      arguments: [{ name: "id", required: true }],
      load: async ({ id }) => ({ text: `doc ${id}` }),
      name: "Doc",
      uriTemplate: "docs://{id}",
    });
    server.addResourceTemplate({
      arguments: [{ name: "id", required: true }],
      load: async ({ id }) => ({ text: `history of ${id}` }),
      name: "History",
      uriTemplate: "docs://{id}/history",
    });
    const client = await connect(server);
    try {
      const history = await client.readResource({ uri: "docs://x/history" });
      expect(history.contents[0]).toMatchObject({
        text: "history of x",
        uri: "docs://x/history",
      });

      const doc = await client.readResource({ uri: "docs://x" });
      expect(doc.contents[0]).toMatchObject({ text: "doc x" });
    } finally {
      await client.close();
      await server.stop();
    }
  });

  it("still lets a reserved expansion ({+path}) span path segments", async () => {
    const server = new FastMCP({ name: "T", version: "1.0.0" });
    server.addResourceTemplate({
      arguments: [{ name: "path", required: true }],
      load: async ({ path }) => ({ text: `file ${path}` }),
      name: "Files",
      uriTemplate: "file:///{+path}",
    });
    const client = await connect(server);
    try {
      const result = await client.readResource({ uri: "file:///a/b/c.txt" });
      expect(result.contents[0]).toMatchObject({ text: "file a/b/c.txt" });
    } finally {
      await client.close();
      await server.stop();
    }
  });

  it("applies the same matching in embedded()", async () => {
    const server = new FastMCP({ name: "T", version: "1.0.0" });
    const load = vi.fn(async ({ name }: { name: string }) => ({
      text: `log ${name}`,
    }));
    server.addResourceTemplate({
      arguments: [{ name: "name", required: true }],
      load,
      mimeType: "text/plain",
      name: "Logs",
      uriTemplate: "file:///logs/{name}.log",
    });

    await expect(server.embedded("file:///logs/x/y.log")).rejects.toThrow();
    expect(load).not.toHaveBeenCalled();

    await expect(server.embedded("file:///logs/x.log")).resolves.toMatchObject({
      text: "log x",
    });
  });
});
