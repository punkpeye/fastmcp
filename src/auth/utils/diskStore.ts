/**
 * Disk-based Token Storage Implementation
 * Provides persistent file-based storage for OAuth tokens and transaction state
 */

import { createHash, randomUUID } from "crypto";
import {
  mkdir,
  readdir,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from "fs/promises";
import { join } from "path";
import { setTimeout as delay } from "timers/promises";

import type { TokenStorage } from "../types.js";

export interface DiskStoreOptions {
  /**
   * How often to run cleanup (in milliseconds)
   * @default 60000 (1 minute)
   */
  cleanupIntervalMs?: number;

  /**
   * Directory path for storing data
   */
  directory: string;

  /**
   * File extension for stored files
   * @default ".json"
   */
  fileExtension?: string;
}

/**
 * Longest encoded key used verbatim as a file name. Leaves room within the
 * common 255-byte limit for the extension and the temporary and claim
 * suffixes added to it.
 */
const MAX_ENCODED_KEY_LENGTH = 180;

/** The file name length limit of common filesystems. */
const MAX_FILE_NAME_BYTES = 255;

interface StorageEntry {
  expiresAt: number;
  value: unknown;
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
    this.cleanupInterval.unref?.();
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
    for (const filePath of this.getFilePaths(key)) {
      try {
        await rm(filePath);
      } catch (error) {
        // File might not exist, which is fine
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
          console.error(`Failed to delete key ${key}:`, error);
        }
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
    for (const filePath of this.getFilePaths(key)) {
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
        // File doesn't exist: try the next candidate path
        if ((error as NodeJS.ErrnoException).code === "ENOENT") {
          continue;
        }
        // File is corrupted
        console.error(`Failed to read key ${key}:`, error);
        return null;
      }
    }

    return null;
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

    // Write to a temporary file and rename it into place. rename() is atomic
    // on POSIX filesystems, so a concurrent get(), take() or cleanup() sees
    // either the old entry or the new one, never a truncated file. The
    // temporary name does not end in the extension, so cleanup() and size()
    // never pick it up.
    const tempPath = `${filePath}.${randomUUID()}.tmp`;

    try {
      // 0o600: these files hold authorization codes, access/refresh tokens
      // and PKCE verifiers, so nothing outside the owning user should read
      // them. Every save creates a new file, so the mode always applies.
      await writeFile(tempPath, JSON.stringify(entry, null, 2), {
        encoding: "utf-8",
        mode: 0o600,
      });
      await this.renameWithRetry(tempPath, filePath);
    } catch (error) {
      await rm(tempPath, { force: true });
      console.error(`Failed to save key ${key}:`, error);
      throw error;
    }

    // An entry written under the legacy file name would otherwise be read
    // again once this one is taken or deleted.
    const legacyPath = this.getLegacyFilePath(key);
    if (legacyPath !== undefined && legacyPath !== filePath) {
      await rm(legacyPath, { force: true });
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
   * Atomically retrieve a value and delete it.
   *
   * rename() is atomic on POSIX filesystems, so when several processes race
   * for the same key exactly one rename succeeds and the losers see ENOENT.
   * That is what makes single-use authorization codes safe when more than one
   * process shares the directory.
   */
  async take(key: string): Promise<null | unknown> {
    let claimPath: string | undefined;

    for (const filePath of this.getFilePaths(key)) {
      // Keep the configured extension on the claim file so that if the
      // process dies between the rename and the unlink, cleanup() still reaps
      // it once the entry expires rather than leaving it on disk forever.
      const candidate = `${filePath}.${randomUUID()}.claim${this.fileExtension}`;

      try {
        await rename(filePath, candidate);
        claimPath = candidate;
        break;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
          console.error(`Failed to take key ${key}:`, error);
          return null;
        }
      }
    }

    if (claimPath === undefined) {
      return null;
    }

    try {
      const content = await readFile(claimPath, "utf-8");
      const entry: StorageEntry = JSON.parse(content);

      return entry.expiresAt < Date.now() ? null : entry.value;
    } catch (error) {
      console.error(`Failed to read key ${key}:`, error);
      return null;
    } finally {
      await rm(claimPath, { force: true });
    }
  }

  /**
   * Ensure storage directory exists
   */
  private async ensureDirectory(): Promise<void> {
    try {
      const stats = await stat(this.directory);
      if (!stats.isDirectory()) {
        throw new Error(`Path ${this.directory} exists but is not a directory`);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        // 0o700 so the credential filenames are not even listable by
        // other users on the host.
        await mkdir(this.directory, { mode: 0o700, recursive: true });
      } else {
        throw error;
      }
    }
  }

  /**
   * Get file path for a key.
   *
   * The file name must not let a key escape the directory, and distinct keys
   * must get distinct files, also on case-insensitive filesystems (the macOS
   * and Windows defaults). Lowercase letters, digits and `-` are kept; every
   * other UTF-8 byte, uppercase letters and `_` included, becomes `_` and two
   * lowercase hex digits, so neither `client:a.b` and `client:a_b` nor
   * `code:A` and `code:a` share a file. Names that would get too long for
   * common filesystems are replaced by a SHA-256 digest, under a prefix the
   * escaping above never produces.
   */
  private getFilePath(key: string): string {
    let name = "";
    for (const byte of Buffer.from(key, "utf8")) {
      const char = String.fromCharCode(byte);
      name += /[a-z0-9-]/.test(char)
        ? char
        : `_${byte.toString(16).padStart(2, "0")}`;
    }

    if (name.length > MAX_ENCODED_KEY_LENGTH) {
      name = `_sha256_${createHash("sha256").update(key, "utf8").digest("hex")}`;
    }

    return join(this.directory, `${name}${this.fileExtension}`);
  }

  /**
   * The paths a key's entry may be stored at: its current file, then the
   * file name earlier versions used. The earlier scheme replaced every other
   * character with `_`, so distinct keys could share a file; it is still read
   * so that entries persisted before an upgrade survive it.
   */
  private getFilePaths(key: string): string[] {
    const filePath = this.getFilePath(key);
    const legacyPath = this.getLegacyFilePath(key);
    return legacyPath === undefined || legacyPath === filePath
      ? [filePath]
      : [filePath, legacyPath];
  }

  /**
   * The file name earlier versions stored a key under, or `undefined` when
   * that name is too long to have ever been written.
   */
  private getLegacyFilePath(key: string): string | undefined {
    const name = `${key.replace(/[^a-zA-Z0-9_-]/g, "_")}${this.fileExtension}`;
    return Buffer.byteLength(name) > MAX_FILE_NAME_BYTES
      ? undefined
      : join(this.directory, name);
  }

  /**
   * Windows can temporarily deny replacing a file that is being read. Retry
   * the atomic rename, never deleting the previous entry to make room. Five
   * retries wait 310 ms in total; persistent and unrelated errors still fail.
   */
  private async renameWithRetry(
    source: string,
    destination: string,
  ): Promise<void> {
    for (let attempt = 0; ; attempt++) {
      try {
        await rename(source, destination);
        return;
      } catch (error) {
        const code = (error as NodeJS.ErrnoException | undefined)?.code;
        if (
          process.platform !== "win32" ||
          attempt >= 5 ||
          !["EACCES", "EBUSY", "EPERM"].includes(code ?? "")
        ) {
          throw error;
        }

        await delay(10 * 2 ** attempt);
      }
    }
  }
}
