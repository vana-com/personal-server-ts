import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { migrateLocalState } from "./local-state.js";

describe("migrateLocalState", () => {
  let tempDir: string;
  let storageRoot: string;
  let dataDir: string;
  let configPath: string;
  let syncCursorPath: string;
  let tokensPath: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "local-state-migration-"));
    storageRoot = join(tempDir, "ps-root");
    dataDir = join(storageRoot, "data");
    configPath = join(storageRoot, "config.json");
    syncCursorPath = join(storageRoot, "sync-cursor.json");
    tokensPath = join(storageRoot, "tokens.json");
    await mkdir(storageRoot, { recursive: true });
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("versions mutable state without changing existing data files", async () => {
    const dataFile = join(dataDir, "instagram", "profile.json");
    await mkdir(join(dataDir, "instagram"), { recursive: true });
    await writeFile(dataFile, JSON.stringify({ handle: "vana" }), "utf-8");
    await writeFile(
      configPath,
      JSON.stringify({
        sync: { lastProcessedTimestamp: "2026-01-21T10:00:00.000Z" },
      }),
      "utf-8",
    );
    await writeFile(
      tokensPath,
      JSON.stringify({ tokens: ["vana_ps_legacy"] }),
      "utf-8",
    );

    const result = await migrateLocalState({
      storageRoot,
      dataDir,
      configPath,
      syncCursorPath,
      tokensPath,
    });

    expect(result.syncCursorCreated).toBe(true);
    expect(result.tokensFileVersioned).toBe(true);

    const cursor = JSON.parse(await readFile(syncCursorPath, "utf-8"));
    expect(cursor).toEqual({
      version: 1,
      lastProcessedTimestamp: "2026-01-21T10:00:00.000Z",
    });

    const tokens = JSON.parse(await readFile(tokensPath, "utf-8"));
    expect(tokens).toEqual({
      version: 1,
      tokens: ["vana_ps_legacy"],
    });

    const state = JSON.parse(await readFile(result.statePath, "utf-8"));
    expect(state.version).toBe(1);
    expect(state.components).toEqual({
      config: 1,
      index: 1,
      dataHierarchy: 1,
      tokenStore: 1,
      tokensFile: 1,
      syncCursor: 1,
    });
    await expect(readFile(dataFile, "utf-8")).resolves.toBe(
      JSON.stringify({ handle: "vana" }),
    );
  });

  it("is idempotent and does not overwrite an existing sync cursor", async () => {
    await writeFile(
      configPath,
      JSON.stringify({
        sync: { lastProcessedTimestamp: "2026-01-21T10:00:00.000Z" },
      }),
      "utf-8",
    );
    await writeFile(
      syncCursorPath,
      JSON.stringify({
        version: 1,
        lastProcessedTimestamp: "2026-01-22T10:00:00.000Z",
      }),
      "utf-8",
    );
    await writeFile(
      tokensPath,
      JSON.stringify({ version: 1, tokens: ["vana_ps_existing"] }),
      "utf-8",
    );

    const result = await migrateLocalState({
      storageRoot,
      dataDir,
      configPath,
      syncCursorPath,
      tokensPath,
    });

    expect(result.syncCursorCreated).toBe(false);
    expect(result.tokensFileVersioned).toBe(false);

    const cursor = JSON.parse(await readFile(syncCursorPath, "utf-8"));
    expect(cursor.lastProcessedTimestamp).toBe("2026-01-22T10:00:00.000Z");

    await expect(
      readFile(join(storageRoot, "state.json"), "utf-8"),
    ).resolves.toContain('"version": 1');
  });
});
