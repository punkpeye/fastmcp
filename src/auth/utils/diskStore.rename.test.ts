import { mkdtemp, readdir, readFile, rename, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { DiskStore } from "./diskStore.js";

vi.mock("fs/promises", async (importOriginal) => {
  const fs = await importOriginal<typeof import("fs/promises")>();
  return { ...fs, rename: vi.fn(fs.rename) };
});

const renameError = (code: string) =>
  Object.assign(new Error(`Synthetic rename failure: ${code}`), { code });

describe("DiskStore atomic replacement retries", () => {
  let directory: string;
  let store: DiskStore;

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "fastmcp-diskstore-rename-"));
    store = new DiskStore({ directory });
    const fs =
      await vi.importActual<typeof import("fs/promises")>("fs/promises");
    vi.mocked(rename).mockReset().mockImplementation(fs.rename);
    vi.stubGlobal("process", { ...process, platform: "win32" });
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(async () => {
    store.destroy();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    await rm(directory, { force: true, recursive: true });
  });

  it.each(["EPERM", "EACCES", "EBUSY"])(
    "retries transient %s without removing the previous value",
    async (code) => {
      await store.save("key", "previous");
      vi.mocked(rename).mockClear();
      const failWhileReading = async (source: Parameters<typeof rename>[0]) => {
        expect(await store.get("key")).toBe("previous");
        expect(JSON.parse(await readFile(source, "utf-8"))).toMatchObject({
          value: "replacement",
        });
        throw renameError(code);
      };
      vi.mocked(rename)
        .mockImplementationOnce(failWhileReading)
        .mockImplementationOnce(failWhileReading);

      await store.save("key", "replacement");

      expect(await store.get("key")).toBe("replacement");
      expect(rename).toHaveBeenCalledTimes(3);
      const [first, ...retries] = vi.mocked(rename).mock.calls;
      expect(retries).toEqual([first, first]);
      expect(await readdir(directory)).toEqual(["key.json"]);
    },
  );

  it("bounds retries and preserves the previous value on persistent failure", async () => {
    await store.save("key", "previous");
    const error = renameError("EPERM");
    vi.mocked(rename).mockReset().mockRejectedValue(error);

    await expect(store.save("key", "replacement")).rejects.toBe(error);

    expect(rename).toHaveBeenCalledTimes(6);
    expect(await store.get("key")).toBe("previous");
    expect(await readdir(directory)).toEqual(["key.json"]);
  });

  it("does not extend the entry's TTL when retrying", async () => {
    const now = 1_800_000_000_000;
    vi.spyOn(Date, "now").mockReturnValue(now);
    vi.mocked(rename).mockImplementationOnce(async () => {
      vi.mocked(Date.now).mockReturnValue(now + 30_000);
      throw renameError("EPERM");
    });

    await store.save("key", "replacement", 60);

    const entry = JSON.parse(
      await readFile(join(directory, "key.json"), "utf-8"),
    );
    expect(entry.expiresAt).toBe(now + 60_000);
    expect(await store.get("key")).toBe("replacement");
    vi.mocked(Date.now).mockReturnValue(now + 60_001);
    expect(await store.get("key")).toBeNull();
  });

  it.each(["ENOENT", "EIO", "ENOSPC"])(
    "does not retry unrelated Windows error %s",
    async (code) => {
      await store.save("key", "previous");
      const error = renameError(code);
      vi.mocked(rename).mockReset().mockRejectedValue(error);

      await expect(store.save("key", "replacement")).rejects.toBe(error);

      expect(rename).toHaveBeenCalledTimes(1);
      expect(await store.get("key")).toBe("previous");
      expect(await readdir(directory)).toEqual(["key.json"]);
    },
  );

  it.each([
    ["linux", "EPERM"],
    ["linux", "EACCES"],
    ["linux", "EBUSY"],
    ["darwin", "EPERM"],
    ["darwin", "EACCES"],
    ["darwin", "EBUSY"],
  ])("does not retry %s error %s", async (platform, code) => {
    vi.stubGlobal("process", { ...process, platform });
    await store.save("key", "previous");
    const error = renameError(code);
    vi.mocked(rename).mockReset().mockRejectedValue(error);

    await expect(store.save("key", "replacement")).rejects.toBe(error);

    expect(rename).toHaveBeenCalledTimes(1);
    expect(await store.get("key")).toBe("previous");
    expect(await readdir(directory)).toEqual(["key.json"]);
  });

  it("stops retrying if a later attempt fails for an unrelated reason", async () => {
    await store.save("key", "previous");
    const error = renameError("EIO");
    vi.mocked(rename)
      .mockReset()
      .mockRejectedValueOnce(renameError("EPERM"))
      .mockRejectedValue(error);

    await expect(store.save("key", "replacement")).rejects.toBe(error);

    expect(rename).toHaveBeenCalledTimes(2);
    expect(await store.get("key")).toBe("previous");
    expect(await readdir(directory)).toEqual(["key.json"]);
  });
});
