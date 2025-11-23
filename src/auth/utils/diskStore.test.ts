import { readdir, rm } from "fs/promises";
import { join } from "path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { DiskStore } from "./diskStore.js";

const TEST_DIR = join(process.cwd(), ".test-disk-store");

describe("DiskStore", () => {
  beforeAll(async () => {
    // Clean up any leftover test directory
    try {
      await rm(TEST_DIR, { force: true, recursive: true });
    } catch {
      // Ignore errors
    }
  });

  afterEach(async () => {
    // Clean up after each test
    try {
      await rm(TEST_DIR, { force: true, recursive: true });
    } catch {
      // Ignore errors
    }
  });

  afterAll(async () => {
    // Final cleanup
    try {
      await rm(TEST_DIR, { force: true, recursive: true });
    } catch {
      // Ignore errors
    }
  });

  it("should create directory if it doesn't exist", async () => {
    const store = new DiskStore({ directory: TEST_DIR });

    // Save a value to trigger directory creation
    await store.save("test", "value");

    const files = await readdir(TEST_DIR);
    expect(files.length).toBe(1);

    store.destroy();
  });

  it("should save and retrieve values", async () => {
    const store = new DiskStore({ directory: TEST_DIR });

    await store.save("key1", { data: "value1" });
    await store.save("key2", "value2");

    const value1 = await store.get("key1");
    const value2 = await store.get("key2");

    expect(value1).toEqual({ data: "value1" });
    expect(value2).toBe("value2");

    store.destroy();
  });

  it("should return null for non-existent keys", async () => {
    const store = new DiskStore({ directory: TEST_DIR });

    const value = await store.get("nonexistent");

    expect(value).toBeNull();

    store.destroy();
  });

  it("should delete values", async () => {
    const store = new DiskStore({ directory: TEST_DIR });

    await store.save("key", "value");
    let value = await store.get("key");
    expect(value).toBe("value");

    await store.delete("key");
    value = await store.get("key");
    expect(value).toBeNull();

    store.destroy();
  });

  it("should handle TTL expiration", async () => {
    const store = new DiskStore({ directory: TEST_DIR });

    // Save with 1 second TTL
    await store.save("key", "value", 1);

    // Should exist immediately
    let value = await store.get("key");
    expect(value).toBe("value");

    // Wait for expiration
    await new Promise((resolve) => setTimeout(resolve, 1100));

    // Should be null after expiration
    value = await store.get("key");
    expect(value).toBeNull();

    store.destroy();
  });

  it("should clean up expired entries", async () => {
    const store = new DiskStore({ directory: TEST_DIR });

    // Save items with short TTL
    await store.save("key1", "value1", 1);
    await store.save("key2", "value2", 1);
    await store.save("key3", "value3", 3600); // 1 hour

    // Wait for expiration
    await new Promise((resolve) => setTimeout(resolve, 1100));

    // Run cleanup
    await store.cleanup();

    // Only key3 should remain
    const size = await store.size();
    expect(size).toBe(1);

    const value3 = await store.get("key3");
    expect(value3).toBe("value3");

    store.destroy();
  });

  it("should sanitize keys to prevent directory traversal", async () => {
    const store = new DiskStore({ directory: TEST_DIR });

    await store.save("../../../malicious", "value");
    const value = await store.get("../../../malicious");

    expect(value).toBe("value");

    // Verify file was created in the correct directory
    const files = await readdir(TEST_DIR);
    expect(files.length).toBe(1);
    expect(files[0]).toMatch(/^_________malicious\.json$/);

    store.destroy();
  });

  it("should handle concurrent operations", async () => {
    const store = new DiskStore({ directory: TEST_DIR });

    // Run multiple save operations concurrently
    await Promise.all([
      store.save("key1", "value1"),
      store.save("key2", "value2"),
      store.save("key3", "value3"),
      store.save("key4", "value4"),
      store.save("key5", "value5"),
    ]);

    // Verify all values
    const values = await Promise.all([
      store.get("key1"),
      store.get("key2"),
      store.get("key3"),
      store.get("key4"),
      store.get("key5"),
    ]);

    expect(values).toEqual(["value1", "value2", "value3", "value4", "value5"]);

    store.destroy();
  });

  it("should count stored items", async () => {
    const store = new DiskStore({ directory: TEST_DIR });

    expect(await store.size()).toBe(0);

    await store.save("key1", "value1");
    expect(await store.size()).toBe(1);

    await store.save("key2", "value2");
    expect(await store.size()).toBe(2);

    await store.delete("key1");
    expect(await store.size()).toBe(1);

    store.destroy();
  });

  it("should use custom file extension", async () => {
    const store = new DiskStore({
      directory: TEST_DIR,
      fileExtension: ".dat",
    });

    await store.save("key", "value");

    const files = await readdir(TEST_DIR);
    expect(files[0]).toMatch(/\.dat$/);

    store.destroy();
  });
});
