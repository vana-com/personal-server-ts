/**
 * Persistent token store — manages PS access tokens on disk.
 *
 * Tokens are stored in a JSON file (tokens.json) in the PS data directory
 * so they survive restarts. Supports multiple concurrent tokens.
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { Logger } from "pino";

export interface TokenStore {
  /** All currently valid tokens. */
  getTokens(): string[];
  /** Check if a token is valid. */
  isValid(token: string): boolean;
  /** Add a new token and persist to disk. */
  addToken(token: string): Promise<void>;
  /** Remove a token and persist to disk. */
  removeToken(token: string): Promise<void>;
}

interface TokensFile {
  tokens: string[];
}

export function createTokenStore(filePath: string, logger: Logger): TokenStore {
  const tokens = new Set<string>();
  let loaded = false;

  async function loadFromDisk(): Promise<void> {
    if (loaded) return;
    try {
      const raw = await readFile(filePath, "utf-8");
      const data = JSON.parse(raw) as TokensFile;
      if (Array.isArray(data.tokens)) {
        for (const t of data.tokens) {
          if (typeof t === "string" && t.length > 0) {
            tokens.add(t);
          }
        }
      }
      logger.info({ count: tokens.size }, "Loaded access tokens from disk");
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        logger.warn({ err }, "Failed to read tokens file");
      }
    }
    loaded = true;
  }

  async function saveToDisk(): Promise<void> {
    const data: TokensFile = { tokens: Array.from(tokens) };
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
    getTokens(): string[] {
      return Array.from(tokens);
    },

    isValid(token: string): boolean {
      return tokens.has(token);
    },

    async addToken(token: string): Promise<void> {
      await ready;
      tokens.add(token);
      await saveToDisk();
    },

    async removeToken(token: string): Promise<void> {
      await ready;
      tokens.delete(token);
      await saveToDisk();
    },
  };
}
