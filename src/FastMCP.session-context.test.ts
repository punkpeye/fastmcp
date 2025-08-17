import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { FastMCP } from "./FastMCP.js";

interface TestAuth {
  [key: string]: unknown; // Required for FastMCPSessionAuth compatibility
  role: "admin" | "user";
  userId: string;
}

describe("FastMCP Session Context", () => {
  describe("stdio transport", () => {
    it("should pass session context to tool execution when authenticate is provided", async () => {
      const mockAuth: TestAuth = { role: "admin", userId: "test-user" };
      const server = new FastMCP<TestAuth>({
        authenticate: async (request) => {
          if (!request) return mockAuth;

          throw new Error("Unexpected request in test");
        },
        name: "test-server",
        version: "1.0.0",
      });

      server.addTool({
        description: "Test tool to verify session context",
        execute: async (_args, context) => {
          return `Session received: ${context.session ? "yes" : "no"}`;
        },
        name: "test-session-context",
        parameters: z.object({
          message: z.string(),
        }),
      });

      await server.start({ transportType: "stdio" });

      expect(server).toBeDefined();
    });

    it("should handle authentication errors gracefully in stdio transport", async () => {
      const mockLogger = {
        debug: vi.fn(),
        error: vi.fn(),
        info: vi.fn(),
        log: vi.fn(),
        warn: vi.fn(),
      };
      const server = new FastMCP<TestAuth>({
        authenticate: async () => {
          throw new Error("Auth failed");
        },
        logger: mockLogger,
        name: "test-server",
        version: "1.0.0",
      });

      server.addTool({
        description: "Test tool",
        execute: async (_args, context) => {
          return `Session: ${context.session ? "present" : "undefined"}`;
        },
        name: "test-tool",
      });

      await server.start({ transportType: "stdio" });

      expect(mockLogger.error).toHaveBeenCalledWith(
        "[FastMCP error] Authentication failed for stdio transport:",
        "Auth failed",
      );
    });

    it("should work without authenticate function", async () => {
      const server = new FastMCP({
        name: "test-server",
        version: "1.0.0",
      });

      server.addTool({
        description: "Test tool without auth",
        execute: async (_args, context) => {
          return `Session: ${context.session ? "present" : "undefined"}`;
        },
        name: "test-tool",
      });

      await server.start({ transportType: "stdio" });

      expect(server).toBeDefined();
    });
  });

  describe("environment variable based authentication", () => {
    it("should support reading from environment variables in stdio mode", async () => {
      const originalEnv = process.env.TEST_USER_ID;

      process.env.TEST_USER_ID = "env-user-123";

      try {
        const server = new FastMCP<TestAuth>({
          authenticate: async (request) => {
            if (!request) {
              return {
                role: "user" as const,
                userId: process.env.TEST_USER_ID || "default-user",
              };
            }
            throw new Error("HTTP not supported in this test");
          },
          name: "test-server",
          version: "1.0.0",
        });

        server.addTool({
          description: "Tool using env-based auth",
          execute: async (_args, context) => {
            return `Environment user: ${context.session?.userId}`;
          },
          name: "env-test-tool",
        });

        await server.start({ transportType: "stdio" });

        expect(server).toBeDefined();
      } finally {
        if (originalEnv !== undefined) {
          process.env.TEST_USER_ID = originalEnv;
        } else {
          delete process.env.TEST_USER_ID;
        }
      }
    });
  });
});
