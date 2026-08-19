/**
 * Regression tests for how imageContent/audioContent fetch a tool-author URL.
 *
 * Two failures are covered here, both of which leaked a resource:
 *
 * - Neither helper bounded the fetch, so a server that never answers stalled
 *   the tool call indefinitely (the only ceiling was the platform default).
 *   Both fetches now carry an AbortSignal bounded by MEDIA_FETCH_TIMEOUT_MS
 *   (30s) and a timeout surfaces as a clear "timed out after ...ms" error,
 *   while non-timeout failures keep their original error message.
 * - On a non-2xx response both helpers threw without reading the body, which
 *   strands the socket behind it until GC. The body is now cancelled first,
 *   and the HTTP status still reaches the caller.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { audioContent, imageContent } from "./FastMCP.js";

// FastMCP.ts calls the global fetch, so spying on it here intercepts both
// media helpers. Installed per-test in beforeEach because the afterEach
// restore puts the real implementation back.
const mediaFetchMock = vi.fn();

const realAbortTimeout = AbortSignal.timeout;

// Same 1x1 PNG used by the imageContent tests in FastMCP.test.ts
const PNG_BUFFER = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
  "base64",
);

// Minimal RIFF/WAVE header
const WAV_BUFFER = Buffer.from(
  "UklGRiQAAABXQVZFZm10IBAAAAABAAEAIAAgAAAAZGF0YQAAAAA=",
  "base64",
);

/**
 * Simulates a server that never answers: the returned promise only rejects
 * when the caller's AbortSignal fires, mirroring how an in-flight fetch is
 * rejected on abort.
 */
const mockHungServer = () => {
  mediaFetchMock.mockImplementation(
    (_input: unknown, init?: { signal?: AbortSignal }) =>
      new Promise<never>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new DOMException("The operation timed out.", "TimeoutError"));
        });
      }),
  );
};

describe("imageContent/audioContent fetch timeout", () => {
  beforeEach(() => {
    mediaFetchMock.mockReset();
    vi.spyOn(globalThis, "fetch").mockImplementation(
      mediaFetchMock as unknown as typeof globalThis.fetch,
    );
    // MEDIA_FETCH_TIMEOUT_MS is 30s of wall-clock time; compress every
    // AbortSignal.timeout() to 10ms so the hung-server tests stay fast.
    // The mapped error still reports the real constant.
    vi.spyOn(AbortSignal, "timeout").mockImplementation((ms: number) =>
      realAbortTimeout(Math.min(ms, 10)),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("imageContent rejects with a timeout error when the server never responds", async () => {
    mockHungServer();

    await expect(
      imageContent({ url: "https://media.example.com/hung.png" }),
    ).rejects.toThrow(
      "Failed to fetch image from URL (https://media.example.com/hung.png): timed out after 30000ms",
    );
  });

  it("audioContent rejects with a timeout error when the server never responds", async () => {
    mockHungServer();

    await expect(
      audioContent({ url: "https://media.example.com/hung.mp3" }),
    ).rejects.toThrow(
      "Failed to fetch audio from URL (https://media.example.com/hung.mp3): timed out after 30000ms",
    );
  });

  it("imageContent passes an AbortSignal to the fetch", async () => {
    mediaFetchMock.mockResolvedValue({
      arrayBuffer: async () => new Uint8Array(PNG_BUFFER).buffer,
      ok: true,
    });

    await imageContent({ url: "https://media.example.com/pixel.png" });

    const init = mediaFetchMock.mock.calls[0]?.[1] as
      | { signal?: unknown }
      | undefined;

    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("imageContent uses the caller's timeoutMs for URL fetches", async () => {
    mediaFetchMock.mockResolvedValue({
      arrayBuffer: async () => new Uint8Array(PNG_BUFFER).buffer,
      ok: true,
    });

    await imageContent({
      timeoutMs: 125,
      url: "https://media.example.com/pixel.png",
    });

    expect(AbortSignal.timeout).toHaveBeenCalledWith(125);
  });

  it("audioContent passes an AbortSignal to the fetch", async () => {
    mediaFetchMock.mockResolvedValue({
      arrayBuffer: async () => new Uint8Array(WAV_BUFFER).buffer,
      ok: true,
    });

    await audioContent({ url: "https://media.example.com/beep.wav" });

    const init = mediaFetchMock.mock.calls[0]?.[1] as
      | { signal?: unknown }
      | undefined;

    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("audioContent uses the caller's timeoutMs for URL fetches", async () => {
    mediaFetchMock.mockResolvedValue({
      arrayBuffer: async () => new Uint8Array(WAV_BUFFER).buffer,
      ok: true,
    });

    await audioContent({
      timeoutMs: 250,
      url: "https://media.example.com/beep.wav",
    });

    expect(AbortSignal.timeout).toHaveBeenCalledWith(250);
  });

  it("imageContent keeps the original error message for non-timeout failures", async () => {
    mediaFetchMock.mockRejectedValue(new TypeError("fetch failed"));

    await expect(
      imageContent({ url: "https://media.example.com/missing.png" }),
    ).rejects.toThrow(
      "Failed to fetch image from URL (https://media.example.com/missing.png): fetch failed",
    );
  });

  it("audioContent keeps the original error message for non-timeout failures", async () => {
    mediaFetchMock.mockRejectedValue(new TypeError("fetch failed"));

    await expect(
      audioContent({ url: "https://media.example.com/missing.mp3" }),
    ).rejects.toThrow(
      "Failed to fetch audio from URL (https://media.example.com/missing.mp3): fetch failed",
    );
  });
});

describe("imageContent/audioContent HTTP errors", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  /**
   * A non-2xx response whose body records whether it was cancelled. Only the
   * members the helpers touch are present, so an unexpected read shows up as a
   * type error rather than silently passing.
   */
  const mockErrorResponse = () => {
    const cancel = vi.fn(async () => undefined);

    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      body: { cancel },
      ok: false,
      status: 503,
      statusText: "Service Unavailable",
    } as unknown as Response);

    return cancel;
  };

  it("imageContent reports the status and cancels the unread body", async () => {
    const cancel = mockErrorResponse();

    await expect(
      imageContent({ url: "https://media.example.com/broken.png" }),
    ).rejects.toThrow(
      "Failed to fetch image from URL (https://media.example.com/broken.png): Server responded with status: 503 - Service Unavailable",
    );

    expect(cancel).toHaveBeenCalledOnce();
  });

  it("audioContent reports the status and cancels the unread body", async () => {
    const cancel = mockErrorResponse();

    await expect(
      audioContent({ url: "https://media.example.com/broken.mp3" }),
    ).rejects.toThrow(
      "Failed to fetch audio from URL (https://media.example.com/broken.mp3): Server responded with status: 503 - Service Unavailable",
    );

    expect(cancel).toHaveBeenCalledOnce();
  });

  it("keeps the HTTP error when the body cannot be cancelled", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      body: {
        cancel: async () => {
          throw new Error("stream already errored");
        },
      },
      ok: false,
      status: 404,
      statusText: "Not Found",
    } as unknown as Response);

    // The cancellation failure must not displace the status the caller needs.
    await expect(
      imageContent({ url: "https://media.example.com/missing.png" }),
    ).rejects.toThrow(
      "Failed to fetch image from URL (https://media.example.com/missing.png): Server responded with status: 404 - Not Found",
    );
  });
});
