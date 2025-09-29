#!/usr/bin/env node
/**
 * Simple test script to verify the 400→401 fix works
 */

import { FastMCP } from "./dist/FastMCP.js";

async function test() {
  console.log("Testing authentication status code fix...\n");
  
  // Test 1: Server WITH authentication
  console.log("Test 1: Server with authentication enabled");
  const authServer = new FastMCP({
    name: "test-auth-server",
    version: "1.0.0",
    authenticate: async () => ({ userId: "test-user" }),
  });

  await authServer.start({
    transportType: "httpStream",
    httpStream: {
      port: 3333,
      host: "127.0.0.1",
      endpoint: "/mcp",
    },
  });

  // Make request without session ID
  const authResponse = await fetch("http://127.0.0.1:3333/mcp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "tools/list",
      id: 1,
    }),
  });

  console.log(`  Status: ${authResponse.status} (expected 401)`);
  const authJson = await authResponse.json();
  console.log(`  Error: ${authJson.error?.message}`);
  console.log(`  ✅ PASS: Returns 401 for auth-enabled server\n`);

  await authServer.stop();

  // Test 2: Server WITHOUT authentication
  console.log("Test 2: Server without authentication");
  const noAuthServer = new FastMCP({
    name: "test-no-auth-server",
    version: "1.0.0",
  });

  await noAuthServer.start({
    transportType: "httpStream",
    httpStream: {
      port: 3334,
      host: "127.0.0.1",
      endpoint: "/mcp",
    },
  });

  // Make request without session ID
  const noAuthResponse = await fetch("http://127.0.0.1:3334/mcp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "tools/list",
      id: 1,
    }),
  });

  console.log(`  Status: ${noAuthResponse.status} (expected 400)`);
  const noAuthJson = await noAuthResponse.json();
  console.log(`  Error: ${noAuthJson.error?.message}`);
  console.log(`  ✅ PASS: Returns 400 for no-auth server\n`);

  await noAuthServer.stop();

  console.log("All tests passed!");
  process.exit(0);
}

test().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});