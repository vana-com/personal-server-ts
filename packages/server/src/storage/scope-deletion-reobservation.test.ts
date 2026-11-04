import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { initializeDatabase } from "./index-schema.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createScopeDeletionHistory } from "./scope-deletion-history.js";
import { createMemoryDataStorage } from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  createScopeDeletionTracker,
  createGatewayDataPointFeed,
  deleteScope,
} from "@opendatalabs/personal-server-ts-core/sync";

const scope = "oura.activity";
const owner = "0x1111111111111111111111111111111111111111";
const at = "2026-09-11T00:00:00Z";
describe("scope deletion re-observation", () => {
  let db: ReturnType<typeof initializeDatabase>;
  let store: ReturnType<typeof createSqliteRecordStore>;
  let history: ReturnType<typeof createScopeDeletionHistory>;
  beforeEach(() => {
    db = initializeDatabase(":memory:");
    store = createSqliteRecordStore(db);
    store.registerConnection({
      instance: "connection",
      sourceId: "https://registry.pdpp.dev/sources/oura",
      method: "oura",
      label: "",
    });
    history = createScopeDeletionHistory(db, owner, store);
  });
  afterEach(() => store.close());
  it.each([null, "3"])(
    "ignores unknown re-observations after version %s",
    (version) => {
      history.remember(scope, { version, deletedAt: at });
      const generation = store.getInstanceBinding("connection").generation;
      expect(() =>
        history.remember(scope, {
          version: null,
          deletedAt: "2026-09-12T00:00:00Z",
        }),
      ).not.toThrow();
      expect(history.get(scope)).toMatchObject({ version, deletedAt: at });
      expect(store.getInstanceBinding("connection").generation).toBe(
        generation,
      );
    },
  );
  it("promotes an unknown version once and ignores later repeats", () => {
    history.remember(scope, { version: null, deletedAt: at });
    history.remember(scope, { version: "7", deletedAt: at });
    expect(history.get(scope)).toMatchObject({
      version: "7",
      eraseApplied: true,
    });
    expect(store.getInstanceBinding("connection").generation).toBe(3);
    history.remember(scope, { version: "7", deletedAt: at });
    expect(store.getInstanceBinding("connection").generation).toBe(3);
  });
  it("retries an equal unmarked version atomically", () => {
    db.prepare(
      "INSERT INTO vana_scope_deletion_history(owner_address, scope, deleted_at, tombstone_version) VALUES (?, ?, ?, ?)",
    ).run(owner, scope, at, "7");
    history.remember(scope, { version: "7", deletedAt: at });
    expect(history.get(scope)).toMatchObject({ eraseApplied: true });
    expect(store.getInstanceBinding("connection").generation).toBe(2);
  });
  it("rechecks body-less deletion observations without poisoning pending history", async () => {
    let now = 0;
    const tracker = createScopeDeletionTracker({
      deletionHistory: history,
      serverOwner: owner,
      now: () => new Date(now),
      maxStalenessMs: 1,
      feed: createGatewayDataPointFeed({
        gatewayUrl: "https://gateway.invalid",
        fetch: async () => new Response(null, { status: 410 }),
        now: () => new Date(now),
      }),
    });
    await expect(tracker.resolve(scope)).resolves.toMatchObject({
      deleted: true,
    });
    now = 2;
    await expect(tracker.resolve(scope)).resolves.toMatchObject({
      deleted: true,
    });
    expect(() => tracker.noteFeedSynced()).not.toThrow();
    expect(tracker.deletionHistory?.get(scope)?.eraseApplied).toBe(true);
  });
  it("advances the download cursor after an unknown version becomes known", async () => {
    const { downloadAll } = await import(
      new URL("../../../core/dist/sync/workers/download.js", import.meta.url)
        .href
    );
    history.remember(scope, { version: null, deletedAt: at });
    const tracker = createScopeDeletionTracker({ deletionHistory: history });
    const write = vi.fn();
    await downloadAll({
      storage: createMemoryDataStorage(),
      storageAdapter: {},
      gateway: {},
      serverOwner: owner,
      masterKey: new Uint8Array(32),
      cursor: { read: async () => null, write },
      logger: { info() {}, error() {}, warn() {}, debug() {} },
      scopeDeletions: tracker,
      dataPointFeed: {
        listDataPointsByOwner: async () => ({
          dataPoints: [
            {
              id: "point",
              scope,
              ownerAddress: owner,
              expectedVersion: "7",
              deletedAt: at,
              addedAt: at,
            },
          ],
          cursor: "next",
        }),
      },
    });
    expect(write).toHaveBeenCalledWith("next");
    expect(history.get(scope)).toMatchObject({
      version: "7",
      eraseApplied: true,
    });
  });
  it("repeats an unversioned durable DELETE without a tombstone failure", async () => {
    const tracker = createScopeDeletionTracker({ deletionHistory: history });
    const deps = {
      storage: createMemoryDataStorage(),
      serverOwner: owner,
      scopeDeletions: tracker,
      logger: { info() {}, error() {}, warn() {}, debug() {} },
      deleteData: {
        tombstone: async () => ({
          status: "tombstoned" as const,
          dataPointId: "point",
          version: null,
        }),
        deleteBlobVersions: async () => ({
          deleted: [],
          missing: [],
          failed: [],
        }),
      },
    };
    await expect(deleteScope(deps, scope)).resolves.toMatchObject({
      durable: true,
    });
    await expect(
      deleteScope({ ...deps, now: () => new Date("2026-09-12") }, scope),
    ).resolves.toMatchObject({ durable: true });
  });
  it("rejects a history/store database mismatch", () => {
    const other = initializeDatabase(":memory:");
    try {
      expect(() => createScopeDeletionHistory(other, owner, store)).toThrow(
        "same SQLite connection",
      );
    } finally {
      other.close();
    }
  });
  it("does not trust an erase marker left behind by an older upsert", () => {
    history.remember(scope, { version: "3", deletedAt: at });
    db.prepare(
      "UPDATE vana_scope_deletion_history SET tombstone_version = '4' WHERE scope = ?",
    ).run(scope);
    expect(history.get(scope)?.eraseApplied).not.toBe(true);
  });
});
