import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { createSyncCursor } from "./sync-cursor.js";
import { loadConfig, saveConfig } from "./config/index.js";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";

async function withTempDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "sync-cursor-test-"));
  try {
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true });
  }
}

describe("SyncCursor", () => {
  it("preserves legacy config-backed reads for config.json callers", async () => {
    await withTempDir(async (dir) => {
      const configPath = join(dir, "config.json");
      const config = ServerConfigSchema.parse({});
      await saveConfig(config, { configPath });

      const cursor = createSyncCursor(configPath);
      const result = await cursor.read();

      expect(result).toBeNull();
    });
  });

  it("preserves legacy config-backed writes for config.json callers", async () => {
    await withTempDir(async (dir) => {
      const configPath = join(dir, "config.json");
      const config = ServerConfigSchema.parse({});
      await saveConfig(config, { configPath });

      const cursor = createSyncCursor(configPath);
      await cursor.write("2026-01-21T10:00:00Z");

      const result = await cursor.read();
      expect(result).toBe("2026-01-21T10:00:00Z");
    });
  });

  it("legacy config-backed write preserves other config fields", async () => {
    await withTempDir(async (dir) => {
      const configPath = join(dir, "config.json");
      const config = ServerConfigSchema.parse({
        server: { port: 9090 },
        logging: { level: "debug" },
        sync: { enabled: true },
      });
      await saveConfig(config, { configPath });

      const cursor = createSyncCursor(configPath);
      await cursor.write("2026-01-21T10:00:00Z");

      const reloaded = await loadConfig({ configPath });
      expect(reloaded.server.port).toBe(9090);
      expect(reloaded.logging.level).toBe("debug");
      expect(reloaded.sync.enabled).toBe(true);
      expect(reloaded.sync.lastProcessedTimestamp).toBe("2026-01-21T10:00:00Z");
    });
  });

  it("legacy config-backed write does not overwrite non-default storage backend with schema defaults", async () => {
    // Regression: createLegacyConfigCursor.write previously round-tripped the
    // config through loadConfig + saveConfig, which fills in zod schema
    // defaults (notably storage.backend = "local"). That silently clobbered
    // runtime overrides such as storage.backend = "vana" injected via
    // startPersonalServer({ configDefaults }), after the first sync tick.
    await withTempDir(async (dir) => {
      const configPath = join(dir, "config.json");
      // Write a config on disk where storage.backend = "vana", as if the
      // host process had injected it via configDefaults at boot.
      await writeFile(
        configPath,
        JSON.stringify(
          {
            storage: { backend: "vana", config: {} },
            sync: { enabled: true, lastProcessedTimestamp: null },
          },
          null,
          2,
        ),
      );

      const cursor = createSyncCursor(configPath);
      await cursor.write("2026-01-21T10:00:00Z");

      const raw = JSON.parse(await readFile(configPath, "utf8"));
      expect(raw.storage.backend).toBe("vana");
      expect(raw.sync.lastProcessedTimestamp).toBe("2026-01-21T10:00:00Z");
    });
  });

  it("legacy config-backed write preserves unknown / forward-compat fields", async () => {
    await withTempDir(async (dir) => {
      const configPath = join(dir, "config.json");
      await writeFile(
        configPath,
        JSON.stringify(
          {
            sync: { enabled: true, lastProcessedTimestamp: null },
            // Pretend a future config field landed in the file; the cursor
            // writer must not strip it just because the current schema
            // doesn't know about it.
            experimental: { newFeature: { enabled: true } },
          },
          null,
          2,
        ),
      );

      const cursor = createSyncCursor(configPath);
      await cursor.write("2026-01-21T10:00:00Z");

      const raw = JSON.parse(await readFile(configPath, "utf8"));
      expect(raw.experimental?.newFeature?.enabled).toBe(true);
      expect(raw.sync.lastProcessedTimestamp).toBe("2026-01-21T10:00:00Z");
    });
  });

  it("legacy config-backed write creates config file if it doesn't exist", async () => {
    await withTempDir(async (dir) => {
      const configPath = join(dir, "nonexistent", "config.json");

      const cursor = createSyncCursor(configPath);
      await cursor.write("2026-01-21T10:00:00Z");

      const result = await cursor.read();
      expect(result).toBe("2026-01-21T10:00:00Z");
    });
  });

  it("writes new cursor state outside config.json", async () => {
    await withTempDir(async (dir) => {
      const configPath = join(dir, "config.json");
      const cursorPath = join(dir, "sync-cursor.json");
      const config = ServerConfigSchema.parse({
        sync: {
          enabled: true,
          lastProcessedTimestamp: "2026-01-20T10:00:00.000Z",
        },
      });
      await saveConfig(config, { configPath });

      const cursor = createSyncCursor(cursorPath, {
        legacyConfigPath: configPath,
      });
      await cursor.write("2026-01-21T10:00:00.000Z");

      expect(await cursor.read()).toBe("2026-01-21T10:00:00.000Z");
      const reloaded = await loadConfig({ configPath });
      expect(reloaded.sync.lastProcessedTimestamp).toBe(
        "2026-01-20T10:00:00.000Z",
      );
      const cursorState = JSON.parse(await readFile(cursorPath, "utf8"));
      expect(cursorState).toEqual({
        version: 1,
        lastProcessedTimestamp: "2026-01-21T10:00:00.000Z",
      });
    });
  });

  it("falls back to legacy config cursor before new cursor state exists", async () => {
    await withTempDir(async (dir) => {
      const configPath = join(dir, "config.json");
      const cursorPath = join(dir, "sync-cursor.json");
      const config = ServerConfigSchema.parse({
        sync: {
          enabled: true,
          lastProcessedTimestamp: "2026-01-20T10:00:00.000Z",
        },
      });
      await saveConfig(config, { configPath });

      const cursor = createSyncCursor(cursorPath, {
        legacyConfigPath: configPath,
      });

      expect(await cursor.read()).toBe("2026-01-20T10:00:00.000Z");
    });
  });
});
