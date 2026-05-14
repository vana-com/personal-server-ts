import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

export const LOCAL_STATE_VERSION = 1;
export const INDEX_STATE_VERSION = 1;
export const TOKEN_STORE_VERSION = 1;
export const SYNC_CURSOR_VERSION = 1;
export const DATA_HIERARCHY_VERSION = 1;
export const CONFIG_STATE_VERSION = 1;

export interface LocalStateMigrationOptions {
  storageRoot: string;
  dataDir: string;
  configPath: string;
  syncCursorPath: string;
  tokensPath: string;
  statePath?: string;
}

export interface LocalStateMigrationResult {
  statePath: string;
  syncCursorCreated: boolean;
  tokensFileVersioned: boolean;
}

interface LocalStateFile {
  version: typeof LOCAL_STATE_VERSION;
  migratedAt: string;
  components: {
    config: typeof CONFIG_STATE_VERSION;
    index: typeof INDEX_STATE_VERSION;
    dataHierarchy: typeof DATA_HIERARCHY_VERSION;
    tokenStore: typeof TOKEN_STORE_VERSION;
    tokensFile: typeof TOKEN_STORE_VERSION;
    syncCursor: typeof SYNC_CURSOR_VERSION;
  };
}

interface LegacyConfigShape {
  sync?: {
    lastProcessedTimestamp?: unknown;
  };
}

interface SyncCursorState {
  version: typeof SYNC_CURSOR_VERSION;
  lastProcessedTimestamp: string | null;
}

interface TokensFile {
  version?: typeof TOKEN_STORE_VERSION;
  tokens?: unknown;
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await readFile(path);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw err;
  }
}

async function writeJsonFile(
  path: string,
  value: unknown,
  mode?: number,
): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmpPath = `${path}.tmp`;
  await writeFile(tmpPath, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf-8",
    mode,
  });
  await rename(tmpPath, path);
}

async function migrateSyncCursor(
  configPath: string,
  syncCursorPath: string,
): Promise<boolean> {
  if (await fileExists(syncCursorPath)) {
    return false;
  }

  let legacyTimestamp: string | null = null;
  try {
    const raw = await readFile(configPath, "utf-8");
    const parsed = JSON.parse(raw) as LegacyConfigShape;
    if (typeof parsed.sync?.lastProcessedTimestamp === "string") {
      legacyTimestamp = parsed.sync.lastProcessedTimestamp;
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      throw err;
    }
  }

  if (legacyTimestamp === null) {
    return false;
  }

  const state: SyncCursorState = {
    version: SYNC_CURSOR_VERSION,
    lastProcessedTimestamp: legacyTimestamp,
  };
  await writeJsonFile(syncCursorPath, state);
  return true;
}

async function migrateTokensFile(tokensPath: string): Promise<boolean> {
  let parsed: TokensFile;
  try {
    const raw = await readFile(tokensPath, "utf-8");
    parsed = JSON.parse(raw) as TokensFile;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw err;
  }

  if (parsed.version === TOKEN_STORE_VERSION) {
    return false;
  }
  if (!Array.isArray(parsed.tokens)) {
    return false;
  }

  await writeJsonFile(
    tokensPath,
    {
      version: TOKEN_STORE_VERSION,
      tokens: parsed.tokens,
    },
    0o600,
  );
  return true;
}

export async function migrateLocalState(
  options: LocalStateMigrationOptions,
): Promise<LocalStateMigrationResult> {
  const statePath =
    options.statePath ?? join(options.storageRoot, "state.json");

  await mkdir(options.storageRoot, { recursive: true });
  await mkdir(options.dataDir, { recursive: true });

  const syncCursorCreated = await migrateSyncCursor(
    options.configPath,
    options.syncCursorPath,
  );
  const tokensFileVersioned = await migrateTokensFile(options.tokensPath);

  const state: LocalStateFile = {
    version: LOCAL_STATE_VERSION,
    migratedAt: new Date().toISOString(),
    components: {
      config: CONFIG_STATE_VERSION,
      index: INDEX_STATE_VERSION,
      dataHierarchy: DATA_HIERARCHY_VERSION,
      tokenStore: TOKEN_STORE_VERSION,
      tokensFile: TOKEN_STORE_VERSION,
      syncCursor: SYNC_CURSOR_VERSION,
    },
  };
  await writeJsonFile(statePath, state);

  return {
    statePath,
    syncCursorCreated,
    tokensFileVersioned,
  };
}
