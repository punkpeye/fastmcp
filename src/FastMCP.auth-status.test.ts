/**
 * Test that authentication errors return 401 instead of 400
 */

import { FastMCP } from "./FastMCP.js";
import { expect, test, describe, afterEach } from "vitest";
import { getPort } from "get-port-please";

describe("Authentication Status Codes", () => {
  let server: FastMCP<{ userId: string }> | null = null;
  let port: number;

  afterEach(async () => {
    if (server) {
      await server.stop();
      server = null;
    }
  });

  test("should return 401 for missing session when auth is enabled", async () => {
    port = await getPort();
    
    // Create server WITH authentication
    server = new FastMCP<{ userId: string }>({
      name: "test-auth-server",
      version: "1.0.0",
      // Authentication function that always succeeds
      authenticate: async () => ({ userId: "test-user" }),
    });

    await server.start({
      transportType: "httpStream",
      httpStream: {
        port,
        host: "127.0.0.1",
        endpoint: "/mcp",
      },
    });

    // Make a request without session ID (should get 401, not 400)
    const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "tools/list",
        id: 1,
      }),
    });

    // Should return 401 Unauthorized, not 400 Bad Request
    expect(response.status).toBe(401);
    
    const json = await response.json();
    expect(json.error).toBeDefined();
    expect(json.error.message).toMatch(/Unauthorized/i);
    expect(json.error.message).not.toMatch(/Bad Request/i);
  });

  test("should return 400 for missing session when auth is NOT enabled", async () => {
    port = await getPort();
    
    // Create server WITHOUT authentication
    server = new FastMCP({
      name: "test-no-auth-server",
      version: "1.0.0",
      // No authenticate function
    });

    await server.start({
      transportType: "httpStream",
      httpStream: {
        port,
        host: "127.0.0.1",
        endpoint: "/mcp",
      },
    });

    // Make a request without session ID (should get 400)
    const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "tools/list",
        id: 1,
      }),
    });

    // Should return 400 Bad Request (no auth configured)
    expect(response.status).toBe(400);
    
    const json = await response.json();
    expect(json.error).toBeDefined();
    expect(json.error.message).toMatch(/Bad Request/i);
  });
});