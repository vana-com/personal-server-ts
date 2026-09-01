import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  DEFAULTS,
  ServerConfigSchema,
  SUPERSEDED_INFERENCE_MODELS,
  withCurrentInferenceModel,
} from "./server-config.js";
import {
  DEFAULT_INFERENCE_BASE_URL,
  DEFAULT_INFERENCE_MODEL,
} from "../derivatives/inference.js";
import { loadConfig, saveConfig } from "../../../server/src/config/loader.js";

async function withTempDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "server-config-test-"));
  try {
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true });
  }
}

describe("ServerConfigSchema — sync fields", () => {
  it("default config has sync.enabled: false and sync.lastProcessedTimestamp: null", () => {
    const config = ServerConfigSchema.parse({});

    expect(config.sync.enabled).toBe(false);
    expect(config.sync.lastProcessedTimestamp).toBeNull();
  });

  it("sync.enabled: true parses correctly", () => {
    const config = ServerConfigSchema.parse({
      sync: { enabled: true },
    });

    expect(config.sync.enabled).toBe(true);
    expect(config.sync.lastProcessedTimestamp).toBeNull();
  });

  it("sync.lastProcessedTimestamp with valid ISO 8601 parses correctly", () => {
    const config = ServerConfigSchema.parse({
      sync: { lastProcessedTimestamp: "2026-01-21T10:00:00Z" },
    });

    expect(config.sync.lastProcessedTimestamp).toBe("2026-01-21T10:00:00Z");
  });

  it("storage.config.vana.apiUrl defaults to https://storage.vana.org", () => {
    const config = ServerConfigSchema.parse({
      storage: { config: { vana: {} } },
    });

    expect(config.storage.config.vana?.apiUrl).toBe("https://storage.vana.org");
  });
});

describe("withCurrentInferenceModel", () => {
  it("moves a superseded default forward", () => {
    const stored = ServerConfigSchema.parse({
      inference: { model: SUPERSEDED_INFERENCE_MODELS[0] },
    });

    const next = withCurrentInferenceModel(stored);

    expect(next.inference.model).toBe(DEFAULTS.inference.model);
    expect(next).not.toBe(stored);
  });

  it("carries every other field through untouched", () => {
    const stored = ServerConfigSchema.parse({
      server: { origin: "https://lite.example" },
      inference: {
        model: SUPERSEDED_INFERENCE_MODELS[0],
        maxSourceItems: 7,
        e2ee: false,
      },
      sync: { lastProcessedTimestamp: "2026-08-31T09:12:44.000Z" },
    });

    const next = withCurrentInferenceModel(stored);

    expect(next.inference.maxSourceItems).toBe(7);
    expect(next.inference.e2ee).toBe(false);
    expect(next.server.origin).toBe("https://lite.example");
    expect(next.sync.lastProcessedTimestamp).toBe("2026-08-31T09:12:44.000Z");
    // The input is not mutated: the caller decides whether to persist.
    expect(stored.inference.model).toBe(SUPERSEDED_INFERENCE_MODELS[0]);
  });

  it("returns the same object for the current default and for a chosen model", () => {
    const current = ServerConfigSchema.parse({});
    expect(withCurrentInferenceModel(current)).toBe(current);

    const chosen = ServerConfigSchema.parse({
      inference: { model: "openai/gpt-4o-mini" },
    });
    expect(withCurrentInferenceModel(chosen)).toBe(chosen);
    expect(withCurrentInferenceModel(chosen).inference.model).toBe(
      "openai/gpt-4o-mini",
    );
  });

  it("never supersedes the current default", () => {
    expect(SUPERSEDED_INFERENCE_MODELS).not.toContain(DEFAULTS.inference.model);
  });

  it("keeps the schema default and the provider default in step", () => {
    // Two definitions, one choice: a config without an `inference.model` and a
    // provider built without one must reach the same model.
    expect(DEFAULTS.inference.model).toBe(DEFAULT_INFERENCE_MODEL);
    expect(DEFAULTS.inference.baseUrl).toBe(DEFAULT_INFERENCE_BASE_URL);
  });
});

describe("saveConfig", () => {
  it("writes JSON file that loadConfig reads back identically", async () => {
    await withTempDir(async (dir) => {
      const configPath = join(dir, "config.json");

      // Load default config (creates file)
      const original = await loadConfig({ configPath });

      // Modify sync fields
      original.sync.enabled = true;
      original.sync.lastProcessedTimestamp = "2026-01-21T10:00:00Z";

      // Save modified config
      await saveConfig(original, { configPath });

      // Load it back
      const reloaded = await loadConfig({ configPath });

      expect(reloaded.sync.enabled).toBe(true);
      expect(reloaded.sync.lastProcessedTimestamp).toBe("2026-01-21T10:00:00Z");
      expect(reloaded.server.port).toBe(original.server.port);
      expect(reloaded.logging.level).toBe(original.logging.level);
    });
  });

  it("creates parent directory if missing", async () => {
    await withTempDir(async (dir) => {
      const configPath = join(dir, "nested", "deep", "config.json");

      const config = ServerConfigSchema.parse({});
      await saveConfig(config, { configPath });

      const raw = await readFile(configPath, "utf-8");
      const parsed = JSON.parse(raw);
      expect(parsed.server.port).toBe(8080);
      expect(parsed.sync.enabled).toBe(false);
    });
  });
});
