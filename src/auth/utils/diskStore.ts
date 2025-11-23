/**
 * Disk-based Token Storage Implementation
 * Provides persistent file-based storage for OAuth tokens and transaction state
 */

import { mkdir, readFile, readdir, rm, stat, writeFile } from "fs/promises";
import { join } from "path";

import type { TokenStorage } from "../types.js";

interface StorageEntry {
  expiresAt: number;
  value: unknown;
}

export interface DiskStoreOptions {
  /**
   * Directory path for storing data
   */
  directory: string;

  /**
   * How often to run cleanup (in milliseconds)
   * @default 60000 (1 minute)
   */
  cleanupIntervalMs?: number;

  /**
   * File extension for stored files
   * @default ".json"
   */
  fileExtension?: string;
}

/**
 * Disk-based token storage with TTL support
 * Persists tokens to filesystem for survival across server restarts
 */
export class DiskStore implements TokenStorage {
  private cleanupInterval: NodeJS.Timeout | null = null;
  private directory: string;
  private fileExtension: string;

  constructor(options: DiskStoreOptions) {
    this.directory = options.directory;
    this.fileExtension = options.fileExtension || ".json";

    // Ensure directory exists
    void this.ensureDirectory();

    // Start periodic cleanup
    const cleanupIntervalMs = options.cleanupIntervalMs || 60000;
    this.cleanupInterval = setInterval(() => {
      void this.cleanup();
    }, cleanupIntervalMs);
  }

  /**
   * Clean up expired entries
   */
  async cleanup(): Promise<void> {
    try {
      await this.ensureDirectory();
      const files = await readdir(this.directory);
      const now = Date.now();

      for (const file of files) {
        if (!file.endsWith(this.fileExtension)) {
          continue;
        }

        try {
          const filePath = join(this.directory, file);
          const content = await readFile(filePath, "utf-8");
          const entry: StorageEntry = JSON.parse(content);

          if (entry.expiresAt < now) {
            await rm(filePath);
          }
        } catch (error) {
          // If file is corrupted or can't be read, delete it
          console.warn(`Failed to read/parse file ${file}, deleting:`, error);
          try {
            await rm(join(this.directory, file));
          } catch {
            // Ignore deletion errors
          }
        }
      }
    } catch (error) {
      console.error("Cleanup failed:", error);
    }
  }

  /**
   * Delete a value
   */
  async delete(key: string): Promise<void> {
    const filePath = this.getFilePath(key);
    try {
      await rm(filePath);
    } catch (error) {
      // File might not exist, which is fine
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        console.error(`Failed to delete key ${key}:`, error);
      }
    }
  }

  /**
   * Destroy the storage and clear cleanup interval
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  /**
   * Retrieve a value
   */
  async get(key: string): Promise<null | unknown> {
    const filePath = this.getFilePath(key);

    try {
      const content = await readFile(filePath, "utf-8");
      const entry: StorageEntry = JSON.parse(content);

      // Check if expired
      if (entry.expiresAt < Date.now()) {
        await rm(filePath);
        return null;
      }

      return entry.value;
    } catch (error) {
      // File doesn't exist or is corrupted
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return null;
      }
      console.error(`Failed to read key ${key}:`, error);
      return null;
    }
  }

  /**
   * Save a value with optional TTL
   */
  async save(key: string, value: unknown, ttl?: number): Promise<void> {
    await this.ensureDirectory();

    const filePath = this.getFilePath(key);
    const expiresAt = ttl ? Date.now() + ttl * 1000 : Number.MAX_SAFE_INTEGER;

    const entry: StorageEntry = {
      expiresAt,
      value,
    };

    try {
      await writeFile(filePath, JSON.stringify(entry, null, 2), "utf-8");
    } catch (error) {
      console.error(`Failed to save key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Get the number of stored items
   */
  async size(): Promise<number> {
    try {
      await this.ensureDirectory();
      const files = await readdir(this.directory);
      return files.filter((f) => f.endsWith(this.fileExtension)).length;
    } catch {
      return 0;
    }
  }

  /**
   * Ensure storage directory exists
   */
  private async ensureDirectory(): Promise<void> {
    try {
      const stats = await stat(this.directory);
      if (!stats.isDirectory()) {
        throw new Error(
          `Path ${this.directory} exists but is not a directory`,
        );
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        await mkdir(this.directory, { recursive: true });
      } else {
        throw error;
      }
    }
  }

  /**
   * Get file path for a key
   */
  private getFilePath(key: string): string {
    // Sanitize key to prevent directory traversal
    const sanitizedKey = key.replace(/[^a-zA-Z0-9_-]/g, "_");
    return join(this.directory, `${sanitizedKey}${this.fileExtension}`);
  }
}
