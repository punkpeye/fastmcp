import { expect, test, vi } from "vitest";

import { FastMCPSession } from "./FastMCP.js";

const mockLogger = {
  debug: vi.fn(),
  error: vi.fn(),
  info: vi.fn(),
  log: vi.fn(),
  warn: vi.fn(),
};

test("FastMCPSession internal storage prevents duplicates for prompts", async () => {
  const session = new FastMCPSession({
    logger: mockLogger,
    name: "Test",
    prompts: [
      {
        description: "Version 1",
        load: async () => "v1",
        name: "my-prompt",
      },
      {
        description: "Version 2",
        load: async () => "v2",
        name: "my-prompt",
      },
    ],
    resources: [],
    resourcesTemplates: [],
    tools: [],
    version: "1.0.0",
  });

  const server = session.server;
  // @ts-expect-error - accessing internal request handlers for testing
  const listPromptsHandler = server._requestHandlers.get("prompts/list");
  const result = await listPromptsHandler({ method: "prompts/list" });

  expect(result.prompts).toHaveLength(1);
  expect(result.prompts[0].description).toBe("Version 2");

  // @ts-expect-error - accessing internal request handlers for testing
  const getPromptHandler = server._requestHandlers.get("prompts/get");
  const promptResult = await getPromptHandler({
    method: "prompts/get",
    params: { name: "my-prompt" },
  });

  expect(promptResult.messages[0].content.text).toBe("v2");
});

test("FastMCPSession internal storage prevents duplicates for resources", async () => {
  const session = new FastMCPSession({
    logger: mockLogger,
    name: "Test",
    prompts: [],
    resources: [
      {
        description: "Version 1",
        load: async () => ({ text: "v1" }),
        name: "Test Resource",
        uri: "file://test.txt",
      },
      {
        description: "Version 2",
        load: async () => ({ text: "v2" }),
        name: "Test Resource",
        uri: "file://test.txt",
      },
    ],
    resourcesTemplates: [],
    tools: [],
    version: "1.0.0",
  });

  const server = session.server;
  // @ts-expect-error - accessing internal request handlers for testing
  const listResourcesHandler = server._requestHandlers.get("resources/list");
  const result = await listResourcesHandler({ method: "resources/list" });

  expect(result.resources).toHaveLength(1);
  expect(result.resources[0].description).toBe("Version 2");

  // @ts-expect-error - accessing internal request handlers for testing
  const readResourceHandler = server._requestHandlers.get("resources/read");
  const resourceResult = await readResourceHandler({
    method: "resources/read",
    params: { uri: "file://test.txt" },
  });

  expect(resourceResult.contents[0].text).toBe("v2");
});

test("FastMCPSession handles list changes correctly by clearing old state", async () => {
  const session = new FastMCPSession({
    logger: mockLogger,
    name: "Test",
    prompts: [{ load: async () => "", name: "old-prompt" }],
    resources: [],
    resourcesTemplates: [],
    tools: [],
    version: "1.0.0",
  });

  session.promptsListChanged([
    {
      load: async () => "new",
      name: "new-prompt",
    },
  ]);

  const server = session.server;
  // @ts-expect-error - accessing internal request handlers for testing
  const listPromptsHandler = server._requestHandlers.get("prompts/list");
  const result = await listPromptsHandler({ method: "prompts/list" });

  expect(result.prompts).toHaveLength(1);
  expect(result.prompts[0].name).toBe("new-prompt");
});
