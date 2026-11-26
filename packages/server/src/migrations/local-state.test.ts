import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { migrateLocalState } from "./local-state.js";
import { runStateMigrations } from "./state-migrations.js";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { DETECT_STUCK_VERSION_LEDGER_ID } from "./detect-stuck-version-ledger.js";
import { HOLD_FOR_TESTS } from "@opendatalabs/personal-server-ts-core/test-utils";

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

  it.each(["", " \t "])(
    "does not create a cursor for a blank legacy timestamp (%j)",
    async (timestamp) => {
      await writeFile(
        configPath,
        JSON.stringify({ sync: { lastProcessedTimestamp: timestamp } }),
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
      await expect(readFile(syncCursorPath, "utf-8")).rejects.toMatchObject({
        code: "ENOENT",
      });
    },
  );

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

  it("leaves existing state untouched when legacy config is malformed", async () => {
    const statePath = join(storageRoot, "state.json");
    const priorState = JSON.stringify({ version: 1, migratedAt: "prior" });
    await writeFile(statePath, priorState);
    await writeFile(configPath, "{truncated");

    await expect(
      migrateLocalState({
        storageRoot,
        dataDir,
        configPath,
        syncCursorPath,
        tokensPath,
      }),
    ).rejects.toThrow(SyntaxError);

    await expect(readFile(statePath, "utf-8")).resolves.toBe(priorState);
    await expect(readFile(syncCursorPath, "utf-8")).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("propagates a non-missing legacy config read failure", async () => {
    const nonDirectory = join(storageRoot, "not-a-directory");
    await writeFile(nonDirectory, "fixture");

    await expect(
      migrateLocalState({
        storageRoot,
        dataDir,
        configPath: join(nonDirectory, "config.json"),
        syncCursorPath,
        tokensPath,
      }),
    ).rejects.toMatchObject({ code: "ENOTDIR" });

    await expect(
      readFile(join(storageRoot, "state.json"), "utf-8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("preserves state when staging the write fails and does not replay the cursor on retry", async () => {
    const statePath = join(storageRoot, "state.json");
    const stagePath = `${statePath}.tmp`;
    const priorState = JSON.stringify({ version: 1, migratedAt: "prior" });
    const timestamp = "2026-01-21T10:00:00.000Z";
    await writeFile(statePath, priorState);
    await writeFile(
      configPath,
      JSON.stringify({ sync: { lastProcessedTimestamp: timestamp } }),
    );
    await mkdir(stagePath);

    const options = {
      storageRoot,
      dataDir,
      configPath,
      syncCursorPath,
      tokensPath,
    };
    await expect(migrateLocalState(options)).rejects.toMatchObject({
      code: "EISDIR",
      path: stagePath,
    });
    await expect(readFile(statePath, "utf-8")).resolves.toBe(priorState);
    const cursor = await readFile(syncCursorPath, "utf-8");
    expect(JSON.parse(cursor)).toEqual({
      version: 1,
      lastProcessedTimestamp: timestamp,
    });

    await rm(stagePath, { recursive: true });
    await expect(migrateLocalState(options)).resolves.toMatchObject({
      statePath,
      syncCursorCreated: false,
    });
    await expect(readFile(syncCursorPath, "utf-8")).resolves.toBe(cursor);
    expect(JSON.parse(await readFile(statePath, "utf-8"))).toMatchObject({
      version: 1,
      components: { syncCursor: 1 },
    });
  });

  it("preserves the migration journal during a file-only run at a custom state path", async () => {
    const stateDir = join(storageRoot, "custom");
    const statePath = join(stateDir, "state.json");
    const migrations = {
      applied: ["2026-01-01-test-step"],
      log: [
        {
          id: "2026-01-01-test-step",
          ranAt: "2026-01-01T00:00:00.000Z",
          changed: true,
          detail: "test fixture",
        },
      ],
    };
    await mkdir(stateDir);
    await writeFile(statePath, JSON.stringify({ version: 1, migrations }));

    const result = await migrateLocalState({
      storageRoot,
      dataDir,
      configPath,
      syncCursorPath,
      tokensPath,
      statePath,
    });

    expect(result.statePath).toBe(statePath);
    expect(result.migrations).toEqual(migrations);
    expect(JSON.parse(await readFile(statePath, "utf-8"))).toMatchObject({
      version: 1,
      migrations,
    });
    await expect(
      readFile(join(storageRoot, "state.json"), "utf-8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rebuilds unreadable JSON bookkeeping without inventing migration history", async () => {
    const statePath = join(storageRoot, "state.json");
    await writeFile(statePath, "{truncated");

    const result = await migrateLocalState({
      storageRoot,
      dataDir,
      configPath,
      syncCursorPath,
      tokensPath,
    });

    expect(result.statePath).toBe(statePath);
    expect(result).not.toHaveProperty("migrations");
    const state = JSON.parse(await readFile(statePath, "utf-8"));
    expect(state).toMatchObject({ version: 1, components: { index: 1 } });
    expect(state).not.toHaveProperty("migrations");
  });

  it("runs the state-migration registry against index.db and records the detection non-destructively", async () => {
    // Seed a stuck scope: two pending (unsynced) rows.
    const db = initializeDatabase(join(storageRoot, "index.db"));
    const index = createIndexManager(db);
    index.insert(HOLD_FOR_TESTS, {
      fileId: null,
      path: "spotify.savedTracks/1.json",
      scope: "spotify.savedTracks",
      collectedAt: "2026-07-13T10:00:00Z",
      sizeBytes: 10,
      version: 4,
    });
    index.insert(HOLD_FOR_TESTS, {
      fileId: null,
      path: "spotify.savedTracks/2.json",
      scope: "spotify.savedTracks",
      collectedAt: "2026-07-13T11:00:00Z",
      sizeBytes: 10,
      version: 5,
    });

    const result = await migrateLocalState({
      storageRoot,
      dataDir,
      configPath,
      syncCursorPath,
      tokensPath,
      db,
    });

    // Non-destructive: rows are untouched — the runtime 409 recovery drains
    // them. The detection is recorded in state.json's migration log (everyBoot
    // detector is never added to `applied`).
    expect(index.countByScope("spotify.savedTracks")).toBe(2);
    expect(index.findUnsynced()).toHaveLength(2);

    expect(result.migrations?.log.at(-1)?.id).toBe(
      DETECT_STUCK_VERSION_LEDGER_ID,
    );
    expect(result.migrations?.applied ?? []).not.toContain(
      DETECT_STUCK_VERSION_LEDGER_ID,
    );
    const state = JSON.parse(await readFile(result.statePath, "utf-8"));
    expect(state.migrations.log.at(-1).id).toBe(DETECT_STUCK_VERSION_LEDGER_ID);

    db.close();
  });
});

describe("local-state migration journal", () => {
  // These registry-only fixtures never touch a database.
  const context = {
    db: {} as Parameters<typeof runStateMigrations>[0]["db"],
    storageRoot: "unused",
  };

  it("drops the oldest log entry without dropping applied migration IDs", () => {
    const originalEntry = { id: "old", ranAt: "2026-01-01", changed: true };
    const prior = { applied: ["old"], log: [originalEntry] };
    const result = runStateMigrations(context, prior, {
      maxLog: 1,
      now: () => "2026-01-02",
      migrations: [
        {
          id: "new",
          description: "Synthetic journal entry",
          check: () => true,
          run: () => ({ changed: true }),
        },
      ],
    });

    expect(result.applied).toEqual(["old", "new"]);
    expect(result.log).toEqual([
      { id: "new", ranAt: "2026-01-02", changed: true, detail: undefined },
    ]);
    expect(prior.log).toEqual([originalEntry]);
  });

  it("keeps a failed check retryable and continues if the warning logger throws", () => {
    const result = runStateMigrations(
      {
        ...context,
        logger: {
          info: () => {},
          warn: () => {
            throw new Error("synthetic log sink failure");
          },
        },
      },
      undefined,
      {
        now: () => "2026-01-02",
        migrations: [
          {
            id: "retry-next-boot",
            description: "Transient check failure",
            check: () => {
              throw new Error("synthetic check failure");
            },
            run: () => {
              throw new Error("must not run after a failed check");
            },
          },
          {
            id: "next",
            description: "Independent migration",
            check: () => true,
            run: () => ({ changed: true }),
          },
        ],
      },
    );

    expect(result.applied).toEqual(["next"]);
    expect(result.log.map(({ id }) => id)).toEqual(["next"]);
  });
});
