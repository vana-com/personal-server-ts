import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, basename } from "node:path";
import { loadConfig, saveConfig } from "./config/index.js";

export interface SyncCursor {
  /** Read the lastProcessedTimestamp from cursor state */
  read(): Promise<string | null>;

  /** Write the lastProcessedTimestamp to cursor state */
  write(timestamp: string): Promise<void>;
}

export interface SyncCursorOptions {
  legacyConfigPath?: string;
}

interface SyncCursorState {
  version: 1;
  lastProcessedTimestamp: string | null;
}

async function readCursorFile(cursorPath: string): Promise<string | null> {
  try {
    const raw = await readFile(cursorPath, "utf8");
    const parsed = JSON.parse(raw) as Partial<SyncCursorState>;
    return typeof parsed.lastProcessedTimestamp === "string"
      ? parsed.lastProcessedTimestamp
      : null;
  } catch (err) {
    if (
      err instanceof Error &&
      "code" in err &&
      (err as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      return null;
    }
    throw err;
  }
}

async function writeCursorFile(
  cursorPath: string,
  timestamp: string,
): Promise<void> {
  await mkdir(dirname(cursorPath), { recursive: true });
  const tmpPath = `${cursorPath}.tmp`;
  const state: SyncCursorState = {
    version: 1,
    lastProcessedTimestamp: timestamp,
  };
  await writeFile(tmpPath, `${JSON.stringify(state, null, 2)}\n`);
  await rename(tmpPath, cursorPath);
}

function createLegacyConfigCursor(configPath: string): SyncCursor {
  return {
    async read() {
      const config = await loadConfig({ configPath });
      return config.sync.lastProcessedTimestamp;
    },

    async write(timestamp) {
      const config = await loadConfig({ configPath });
      config.sync.lastProcessedTimestamp = timestamp;
      await saveConfig(config, { configPath });
    },
  };
}

/**
 * Creates a cursor backed by a separate JSON state file.
 * Passing config.json without options preserves the legacy config-backed API.
 */
export function createSyncCursor(
  cursorPath: string,
  options: SyncCursorOptions = {},
): SyncCursor {
  if (!options.legacyConfigPath && basename(cursorPath) === "config.json") {
    return createLegacyConfigCursor(cursorPath);
  }

  return {
    async read() {
      const cursor = await readCursorFile(cursorPath);
      if (cursor !== null) {
        return cursor;
      }
      if (options.legacyConfigPath) {
        const config = await loadConfig({
          configPath: options.legacyConfigPath,
        });
        return config.sync.lastProcessedTimestamp;
      }
      return null;
    },

    async write(timestamp) {
      await writeCursorFile(cursorPath, timestamp);
    },
  };
}
