/**
 * Persistent token store — manages Personal Server session tokens on disk.
 *
 * Tokens are stored in a JSON file (tokens.json) in the PS data directory
 * so they survive restarts. Supports multiple concurrent tokens.
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { Logger } from "pino";

export interface AddTokenOptions {
  expiresAt?: string | Date | null;
}

export interface TokenStore {
  /** All currently valid tokens. */
  getTokens(): Promise<string[]>;
  /** Check if a token is valid. */
  isValid(token: string): Promise<boolean>;
  /** Add a new token and persist to disk. */
  addToken(token: string, options?: AddTokenOptions): Promise<void>;
  /** Remove a token and persist to disk. */
  removeToken(token: string): Promise<void>;
}

interface TokensFile {
  tokens: Array<string | { token: string; expiresAt?: string | null }>;
}

export function createTokenStore(filePath: string, logger: Logger): TokenStore {
  const tokens = new Map<string, string | null>();
  let loaded = false;

  function normalizeExpiresAt(
    value: string | Date | null | undefined,
  ): string | null {
    if (value == null) return null;
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) {
      throw new Error("Invalid token expiry");
    }
    return date.toISOString();
  }

  function isExpired(expiresAt: string | null | undefined): boolean {
    if (!expiresAt) return false;
    return new Date(expiresAt).getTime() <= Date.now();
  }

  function purgeExpired(): boolean {
    let removed = false;
    for (const [token, expiresAt] of tokens.entries()) {
      if (isExpired(expiresAt)) {
        tokens.delete(token);
        removed = true;
      }
    }
    return removed;
  }

  async function loadFromDisk(): Promise<void> {
    if (loaded) return;
    try {
      const raw = await readFile(filePath, "utf-8");
      const data = JSON.parse(raw) as TokensFile;
      if (Array.isArray(data.tokens)) {
        for (const entry of data.tokens) {
          if (typeof entry === "string" && entry.length > 0) {
            tokens.set(entry, null);
            continue;
          }

          if (
            typeof entry === "object" &&
            entry !== null &&
            typeof entry.token === "string" &&
            entry.token.length > 0
          ) {
            const expiresAt = normalizeExpiresAt(entry.expiresAt);
            if (!isExpired(expiresAt)) {
              tokens.set(entry.token, expiresAt);
            }
          }
        }
      }
      purgeExpired();
      logger.info(
        { count: tokens.size },
        "Loaded Personal Server session tokens from disk",
      );
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        logger.warn({ err }, "Failed to read tokens file");
      }
    }
    loaded = true;
  }

  async function saveToDisk(): Promise<void> {
    purgeExpired();
    const data: TokensFile = {
      tokens: Array.from(tokens.entries()).map(([token, expiresAt]) =>
        expiresAt ? { token, expiresAt } : token,
      ),
    };
    try {
      await mkdir(dirname(filePath), { recursive: true });
      await writeFile(filePath, JSON.stringify(data, null, 2), {
        mode: 0o600,
      });
    } catch (err) {
      logger.error({ err }, "Failed to persist tokens file");
    }
  }

  // Load eagerly on first access
  const ready = loadFromDisk();

  return {
    async getTokens(): Promise<string[]> {
      await ready;
      if (purgeExpired()) {
        await saveToDisk();
      }
      return Array.from(tokens.keys());
    },

    async isValid(token: string): Promise<boolean> {
      await ready;
      const expiresAt = tokens.get(token);
      if (expiresAt === undefined) {
        return false;
      }
      if (isExpired(expiresAt)) {
        tokens.delete(token);
        await saveToDisk();
        return false;
      }
      return true;
    },

    async addToken(token: string, options?: AddTokenOptions): Promise<void> {
      await ready;
      tokens.set(token, normalizeExpiresAt(options?.expiresAt));
      await saveToDisk();
    },

    async removeToken(token: string): Promise<void> {
      await ready;
      tokens.delete(token);
      await saveToDisk();
    },
  };
}
