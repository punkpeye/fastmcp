/**
 * Token Storage Implementations
 * Secure storage for OAuth tokens and transaction state
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "crypto";

import type { TokenStorage } from "../types.js";

interface StorageEntry {
  expiresAt: number;
  value: unknown;
}

/**
 * Encrypted token storage wrapper
 * Encrypts values using AES-256-GCM before storing
 */
export class EncryptedTokenStorage implements TokenStorage {
  private algorithm: import("crypto").CipherGCMTypes = "aes-256-gcm";
  private backend: TokenStorage;
  private encryptionKey: Buffer;

  constructor(backend: TokenStorage, encryptionKey: string) {
    this.backend = backend;
    // Synchronously derive key using scrypt
    const salt = Buffer.from("fastmcp-oauth-proxy-salt");
    this.encryptionKey = scryptSync(encryptionKey, salt, 32);
  }

  async cleanup(): Promise<void> {
    await this.backend.cleanup();
  }

  async delete(key: string): Promise<void> {
    await this.backend.delete(key);
  }

  async get(key: string): Promise<null | unknown> {
    return this.decryptStored(await this.backend.get(key));
  }

  async save(key: string, value: unknown, ttl?: number): Promise<void> {
    const encrypted = await this.encrypt(
      JSON.stringify(value),
      this.encryptionKey,
    );
    await this.backend.save(key, encrypted, ttl);
  }

  /**
   * Delegates to the backend so that the atomicity of the underlying store is
   * preserved; falls back to get + delete when the backend cannot do better.
   */
  async take(key: string): Promise<null | unknown> {
    if (this.backend.take) {
      return this.decryptStored(await this.backend.take(key));
    }

    const value = await this.get(key);

    if (value === null) {
      return null;
    }

    await this.backend.delete(key);

    return value;
  }

  private async decrypt(ciphertext: string, key: Buffer): Promise<string> {
    const parts = ciphertext.split(":");
    if (parts.length !== 3) {
      throw new Error("Invalid encrypted data format");
    }

    const [ivHex, authTagHex, encrypted] = parts;
    const iv = Buffer.from(ivHex, "hex");
    const authTag = Buffer.from(authTagHex, "hex");

    const decipher = createDecipheriv(this.algorithm, key, iv, {
      authTagLength: 16,
    });
    // Use type assertion for GCM-specific method
    (decipher as unknown as { setAuthTag(buffer: Buffer): void }).setAuthTag(
      authTag,
    );

    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
  }

  private async decryptStored(encrypted: unknown): Promise<null | unknown> {
    if (!encrypted) {
      return null;
    }

    try {
      const decrypted = await this.decrypt(
        encrypted as string,
        this.encryptionKey,
      );
      return JSON.parse(decrypted);
    } catch (error) {
      console.error("Failed to decrypt value:", error);
      return null;
    }
  }

  private async encrypt(plaintext: string, key: Buffer): Promise<string> {
    const iv = randomBytes(16);
    const cipher = createCipheriv(this.algorithm, key, iv, {
      authTagLength: 16,
    });

    let encrypted = cipher.update(plaintext, "utf8", "hex");
    encrypted += cipher.final("hex");

    // Use type assertion for GCM-specific method
    const authTag = (
      cipher as unknown as { getAuthTag(): Buffer }
    ).getAuthTag();

    // Return format: iv:authTag:encrypted
    return `${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted}`;
  }
}

/**
 * In-memory token storage with TTL support
 */
export class MemoryTokenStorage implements TokenStorage {
  private cleanupInterval: NodeJS.Timeout | null = null;
  private store: Map<string, StorageEntry> = new Map();

  constructor(cleanupIntervalMs: number = 60000) {
    // Run cleanup every minute by default
    this.cleanupInterval = setInterval(
      () => void this.cleanup(),
      cleanupIntervalMs,
    );
  }

  async cleanup(): Promise<void> {
    const now = Date.now();
    const keysToDelete: string[] = [];

    for (const [key, entry] of this.store.entries()) {
      if (entry.expiresAt < now) {
        keysToDelete.push(key);
      }
    }

    for (const key of keysToDelete) {
      this.store.delete(key);
    }
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  /**
   * Destroy the storage and clear cleanup interval
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.store.clear();
  }

  async get(key: string): Promise<null | unknown> {
    const entry = this.store.get(key);

    if (!entry) {
      return null;
    }

    if (entry.expiresAt < Date.now()) {
      this.store.delete(key);
      return null;
    }

    return entry.value;
  }

  async save(key: string, value: unknown, ttl?: number): Promise<void> {
    const expiresAt = ttl ? Date.now() + ttl * 1000 : Number.MAX_SAFE_INTEGER;

    this.store.set(key, {
      expiresAt,
      value,
    });
  }

  /**
   * Get the number of stored items
   */
  size(): number {
    return this.store.size;
  }

  /**
   * Atomic by construction: the read and the delete happen in a single
   * synchronous block, so no other task can observe the value in between.
   */
  async take(key: string): Promise<null | unknown> {
    const entry = this.store.get(key);
    this.store.delete(key);

    if (!entry || entry.expiresAt < Date.now()) {
      return null;
    }

    return entry.value;
  }
}
