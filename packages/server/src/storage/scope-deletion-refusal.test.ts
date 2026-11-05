import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import Database from "better-sqlite3";
import { createMemoryDataStorage } from "@opendatalabs/personal-server-ts-core/test-utils";
import { createScopeDeletionTracker } from "@opendatalabs/personal-server-ts-core/sync";
import { createLegacyScopeView } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { initializeDatabase } from "./index-schema.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createScopeDeletionHistory } from "./scope-deletion-history.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { createIndexManager } from "./index-manager.js";
import { dataRoutes, type DataRouteDeps } from "../routes/data.js";

const owner = "0x1111111111111111111111111111111111111111";
const at = "2026-09-11T00:00:00Z";
const scope = "oura.activity";
describe("durable deletion when scope erasure refuses", () => {
  let dir: string;
  let db: ReturnType<typeof initializeDatabase>;
  let store: ReturnType<typeof createSqliteRecordStore>;
  let history: ReturnType<typeof createScopeDeletionHistory>;
  let tracker: ReturnType<typeof createScopeDeletionTracker>;
  const logger = {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  };
  const point = (scope: string) => ({
    id: scope,
    ownerAddress: owner,
    scope,
    expectedVersion: "7",
    deletedAt: at,
    addedAt: at,
  });
  beforeEach(async () => {
    vi.clearAllMocks();
    dir = await mkdtemp(join(tmpdir(), "scope-refusal-"));
    db = initializeDatabase(join(dir, "index.db"));
    store = createSqliteRecordStore(db);
    store.registerConnection({
      instance: "connection",
      sourceId: "https://registry.pdpp.dev/sources/oura",
      method: "oura",
      label: "",
    });
    for (const stream of ["activity", "readiness"])
      store.replaceStream({
        instance: "connection",
        stream,
        method: "oura",
        generation: 1,
        primaryKey: ["id"],
        emittedAt: at,
        sourceCollectedAt: at,
        envelopes: [
          {
            instance: "connection",
            stream,
            key: "held",
            data: { id: "held", day: "2026-09-10", score: 80 },
            emitted_at: at,
          },
        ],
      });
    db.prepare(
      "INSERT INTO pdpp_records(instance, stream, record_key, data, version, emitted_at, deleted) VALUES ('orphan', 'activity', 'old', '{}', 1, ?, 0)",
    ).run(at);
    history = createScopeDeletionHistory(db, owner, store, { logger });
    tracker = createScopeDeletionTracker({
      deletionHistory: history,
      serverOwner: owner,
      feed: {
        getDataPoint: async () => point(scope) as never,
        listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
      },
    });
  });
  afterEach(async () => {
    store.close();
    await rm(dir, { recursive: true, force: true });
  });
  async function feedPass() {
    const { downloadAll } = await import(
      new URL("../../../core/dist/sync/workers/download.js", import.meta.url)
        .href
    );
    const write = vi.fn();
    await expect(
      downloadAll({
        storage: createMemoryDataStorage(),
        storageAdapter: {},
        gateway: {},
        serverOwner: owner,
        masterKey: new Uint8Array(32),
        cursor: { read: async () => null, write },
        logger,
        scopeDeletions: tracker,
        dataPointFeed: {
          listDataPointsByOwner: async () => ({
            dataPoints: [point(scope), point("oura.readiness")],
            cursor: "next",
          }),
        },
      }),
    ).resolves.toEqual([]);
    return write;
  }
  it("records an orphan-blocked tombstone unmarked and advances while processing another scope", async () => {
    const write = await feedPass();
    expect(write).toHaveBeenCalledWith("next");
    expect(await feedPass()).toHaveBeenCalledWith("next");
    const persisted = new Database(join(dir, "index.db"), { readonly: true });
    try {
      expect(
        persisted
          .prepare(
            "SELECT tombstone_version, erase_applied FROM vana_scope_deletion_history WHERE scope = ?",
          )
          .get(scope),
      ).toEqual({ tombstone_version: "7", erase_applied: 0 });
    } finally {
      persisted.close();
    }
    expect(history.get("oura.readiness")?.eraseApplied).toBe(true);
    expect(store.getRecord("connection", "activity", "held")).toBeDefined();
    expect(store.getRecord("connection", "readiness", "held")).toBeUndefined();
    expect(logger.error).toHaveBeenCalledWith(
      expect.objectContaining({
        scope,
        instance: "orphan",
        stream: "activity",
        error: "Cannot establish the owner of a stream",
      }),
      expect.any(String),
    );
  });
  it("answers 410 rather than 500 when a read observes a refused erase", async () => {
    const app = dataRoutes({
      indexManager: createIndexManager(db),
      hierarchyOptions: { dataDir: dir },
      dataStorage: createMemoryDataStorage(),
      logger: logger as unknown as DataRouteDeps["logger"],
      serverOrigin: "https://server.invalid",
      serverOwner: owner,
      gateway: {} as DataRouteDeps["gateway"],
      accessLogWriter: { write: async () => {} },
      accessToken: "owner-token",
      scopeDeletions: tracker,
      legacyScopeView: createLegacyScopeView({
        authority: createLegacyScopeAuthority(db),
        records: store,
        configuredMethods: () => ["oura"],
      }),
    });
    for (let read = 0; read < 2; read++) {
      const response = await app.request(`/${scope}`, {
        headers: { authorization: "Bearer owner-token" },
      });
      expect(response.status, await response.clone().text()).toBe(410);
    }
    expect(history.get(scope)).toMatchObject({ version: "7" });
    expect(history.get(scope)?.eraseApplied).not.toBe(true);
  });
  it("does not advance past a failed history write and still processes the other scope", async () => {
    db.exec(
      "CREATE TRIGGER reject_history BEFORE INSERT ON vana_scope_deletion_history WHEN NEW.scope = 'oura.activity' BEGIN SELECT RAISE(ABORT, 'history write failed'); END",
    );
    const write = await feedPass();
    expect(write).not.toHaveBeenCalled();
    expect(history.get(scope)).toBeNull();
    expect(history.get("oura.readiness")?.eraseApplied).toBe(true);
    expect(logger.error).toHaveBeenCalledWith(
      expect.objectContaining({ scope, error: "history write failed" }),
      expect.any(String),
    );
    db.exec("DROP TRIGGER reject_history");
    expect(await feedPass()).toHaveBeenCalledWith("next");
  });
});
