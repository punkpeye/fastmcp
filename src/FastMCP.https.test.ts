import https from "https";
import path from "path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

describe("HTTPS support", () => {
  let server: FastMCP;
  let port: number;

  beforeEach(() => {
    port = Math.floor(Math.random() * 10000) + 50000;
    server = new FastMCP({
      name: "HTTPS Test Server",
      version: "1.0.0",
    });

    server.addTool({
      description: "Test tool",
      execute: async ({ message }) => {
        return `Received: ${message}`;
      },
      name: "test",
      parameters: z.object({
        message: z.string(),
      }),
    });
  });

  afterEach(async () => {
    await server.stop();
  });

  test("starts server with HTTPS when SSL options provided", async () => {
    const certPath = path.join(
      process.cwd(),
      "src/fixtures/certs/server-cert.pem",
    );
    const keyPath = path.join(
      process.cwd(),
      "src/fixtures/certs/server-key.pem",
    );

    await server.start({
      httpStream: {
        port,
        sslCert: certPath,
        sslKey: keyPath,
      },
      transportType: "httpStream",
    });

    // Test that the server responds to HTTPS requests
    const response = await new Promise<{ statusCode?: number; text: string }>(
      (resolve, reject) => {
        https
          .get(
            {
              hostname: "localhost",
              path: "/ping",
              port,
              rejectUnauthorized: false, // Accept self-signed cert
            },
            (res) => {
              let data = "";
              res.on("data", (chunk) => {
                data += chunk;
              });
              res.on("end", () => {
                resolve({ statusCode: res.statusCode, text: data });
              });
              res.on("error", reject);
            },
          )
          .on("error", reject);
      },
    );

    expect(response.statusCode).toBe(200);
    expect(response.text).toBe("pong");
  });

  test("starts server with HTTP when no SSL options provided", async () => {
    await server.start({
      httpStream: {
        port,
      },
      transportType: "httpStream",
    });

    // Test that the server responds to HTTP requests
    const response = await fetch(`http://localhost:${port}/ping`);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("pong");
  });
});
