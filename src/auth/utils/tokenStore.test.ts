/**
 * Token Storage Tests
 */

import { setTimeout as delay } from "timers/promises";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { TokenStorage } from "../types.js";

import { EncryptedTokenStorage, MemoryTokenStorage } from "./tokenStore.js";

describe("MemoryTokenStorage", () => {
  let storage: MemoryTokenStorage;

  beforeEach(() => {
    storage = new MemoryTokenStorage(100); // Short cleanup interval for testing
  });

  afterEach(() => {
    storage.destroy();
  });

  describe("save and get", () => {
    it("should save and retrieve a value", async () => {
      await storage.save("key1", "value1");
      const value = await storage.get("key1");
      expect(value).toBe("value1");
    });

    it("should save and retrieve complex objects", async () => {
      const obj = { foo: "bar", nested: { value: 123 } };
      await storage.save("key2", obj);
      const value = await storage.get("key2");
      expect(value).toEqual(obj);
    });

    it("should return null for non-existent key", async () => {
      const value = await storage.get("nonexistent");
      expect(value).toBeNull();
    });
  });

  describe("TTL expiration", () => {
    it("should expire values after TTL", async () => {
      await storage.save("key3", "value3", 0.1); // 100ms TTL
      let value = await storage.get("key3");
      expect(value).toBe("value3");

      await delay(150);
      value = await storage.get("key3");
      expect(value).toBeNull();
    });

    it("should not expire values without TTL", async () => {
      await storage.save("key4", "value4");
      await delay(200);
      const value = await storage.get("key4");
      expect(value).toBe("value4");
    });
  });

  describe("delete", () => {
    it("should delete a key", async () => {
      await storage.save("key5", "value5");
      await storage.delete("key5");
      const value = await storage.get("key5");
      expect(value).toBeNull();
    });
  });

  describe("cleanup", () => {
    it("should clean up expired entries", async () => {
      await storage.save("key6", "value6", 0.1);
      await storage.save("key7", "value7");

      expect(storage.size()).toBe(2);

      await delay(150);
      await storage.cleanup();

      expect(storage.size()).toBe(1);
      expect(await storage.get("key7")).toBe("value7");
    });
  });

  describe("take", () => {
    it("should return the value and remove it", async () => {
      await storage.save("take-key", "value");

      expect(await storage.take("take-key")).toBe("value");
      expect(await storage.get("take-key")).toBeNull();
    });

    it("should return null for a missing key", async () => {
      expect(await storage.take("no-such-key")).toBeNull();
    });

    it("should return null for an expired entry", async () => {
      await storage.save("expired-key", "value", 0.1);
      await delay(150);

      expect(await storage.take("expired-key")).toBeNull();
    });

    it("should hand the value to exactly one of several concurrent callers", async () => {
      await storage.save("contended-key", "value");

      const results = await Promise.all([
        storage.take("contended-key"),
        storage.take("contended-key"),
        storage.take("contended-key"),
      ]);

      expect(results.filter((result) => result !== null)).toEqual(["value"]);
    });
  });
});

describe("EncryptedTokenStorage", () => {
  let backend: MemoryTokenStorage;
  let storage: EncryptedTokenStorage;

  beforeEach(() => {
    backend = new MemoryTokenStorage();
    storage = new EncryptedTokenStorage(backend, "test-encryption-key-123");
  });

  afterEach(() => {
    backend.destroy();
  });

  describe("encryption", () => {
    it("should encrypt and decrypt values", async () => {
      const value = { number: 42, secret: "sensitive-data" };
      await storage.save("encrypted-key", value);

      // Check that backend has encrypted data
      const backendValue = await backend.get("encrypted-key");
      expect(typeof backendValue).toBe("string");
      expect(backendValue).not.toContain("sensitive-data");

      // Decrypt and verify
      const decrypted = await storage.get("encrypted-key");
      expect(decrypted).toEqual(value);
    });

    it("should handle strings", async () => {
      await storage.save("string-key", "plain-string");
      const value = await storage.get("string-key");
      expect(value).toBe("plain-string");
    });

    it("should handle numbers", async () => {
      await storage.save("number-key", 12345);
      const value = await storage.get("number-key");
      expect(value).toBe(12345);
    });

    it("should return null for non-existent key", async () => {
      const value = await storage.get("nonexistent");
      expect(value).toBeNull();
    });
  });

  describe("TTL support", () => {
    it("should respect TTL from backend", async () => {
      await storage.save("ttl-key", "value", 0.1);
      let value = await storage.get("ttl-key");
      expect(value).toBe("value");

      await delay(150);
      value = await storage.get("ttl-key");
      expect(value).toBeNull();
    });
  });

  describe("GCM auth tag length security fix", () => {
    it("should encrypt and decrypt with correct GCM authentication tag length (regression test for #268)", async () => {
      const value = { sensitive: "data-requiring-gcm-integrity" };
      await storage.save("gcm-key", value);

      const encrypted = await backend.get("gcm-key");
      expect(typeof encrypted).toBe("string");

      // Verify format: iv:authTag:encrypted (3 parts)
      const parts = (encrypted as string).split(":");
      expect(parts.length).toBe(3);

      // Auth tag should be 32 hex chars = 16 bytes = 128 bits
      const authTagHex = parts[1];
      expect(authTagHex.length).toBe(32);

      // Should decrypt correctly
      const decrypted = await storage.get("gcm-key");
      expect(decrypted).toEqual(value);
    });

    it("should produce consistent 128-bit auth tags across multiple encryptions", async () => {
      const values = ["a", "b", "c"];
      const tagLengths: number[] = [];

      for (const val of values) {
        await storage.save(`tag-test-${val}`, val);
        const encrypted = (await backend.get(`tag-test-${val}`)) as string;
        const parts = encrypted.split(":");
        tagLengths.push(parts[1].length);
      }

      // All auth tags should be exactly 32 hex chars (16 bytes / 128 bits)
      expect(tagLengths.every((len) => len === 32)).toBe(true);
    });
  });

  describe("delete", () => {
    it("should delete encrypted values", async () => {
      await storage.save("delete-key", "value");
      await storage.delete("delete-key");
      const value = await storage.get("delete-key");
      expect(value).toBeNull();
    });
  });

  describe("take", () => {
    it("should decrypt the value and remove it", async () => {
      const value = { nested: { token: "secret" } };
      await storage.save("take-key", value);

      expect(await storage.take("take-key")).toEqual(value);
      expect(await storage.get("take-key")).toBeNull();
      expect(await backend.get("take-key")).toBeNull();
    });

    it("should return null for a missing key", async () => {
      expect(await storage.take("no-such-key")).toBeNull();
    });

    it("should delegate to a backend that cannot take atomically", async () => {
      const calls: string[] = [];
      const backendWithoutTake: TokenStorage = {
        cleanup: async () => {},
        delete: async (key) => {
          calls.push(`delete:${key}`);
          await backend.delete(key);
        },
        get: async (key) => {
          calls.push(`get:${key}`);
          return backend.get(key);
        },
        save: async (key, value, ttl) => backend.save(key, value, ttl),
      };
      const wrapper = new EncryptedTokenStorage(
        backendWithoutTake,
        "test-encryption-key",
      );

      await wrapper.save("fallback-key", "value");

      expect(await wrapper.take("fallback-key")).toBe("value");
      expect(calls).toEqual(["get:fallback-key", "delete:fallback-key"]);
      expect(await wrapper.get("fallback-key")).toBeNull();
    });
  });
});
