import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type Database from "better-sqlite3";
import { initializeDatabase } from "./index-schema.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createScopeDeletionHistory } from "./scope-deletion-history.js";
import { createScopeDeletionTracker } from "@opendatalabs/personal-server-ts-core/sync";

const OWNER = "0x1111111111111111111111111111111111111111";
const SCOPE = "oura.activity";
const SOURCE = "https://registry.pdpp.dev/sources/oura";

describe("scope deletion observations", () => {
  let db: Database.Database;
  let store: ReturnType<typeof createSqliteRecordStore>;
  let history: ReturnType<typeof createScopeDeletionHistory>;
  const deleted = { version: "3", deletedAt: "2026-09-11T00:00:00Z" };

  function replace(stream: string, id: string, generation = 1) {
    return store.replaceStream({
      instance: "connection",
      stream,
      method: "oura",
      generation,
      primaryKey: ["id"],
      emittedAt: "2026-09-10T00:00:00Z",
      sourceCollectedAt: "2026-09-10T00:00:00Z",
      envelopes: [
        {
          instance: "connection",
          stream,
          key: id,
          data: { id },
          emitted_at: "2026-09-10T00:00:00Z",
        },
      ],
    });
  }

  beforeEach(() => {
    db = initializeDatabase(":memory:");
    store = createSqliteRecordStore(db);
    store.registerConnection({
      instance: "connection",
      sourceId: SOURCE,
      method: "oura",
      label: "",
    });
    replace("activity", "old");
    replace("readiness", "sibling");
    history = createScopeDeletionHistory(db, OWNER, store);
  });
  afterEach(() => store.close());

  it("records an observed tombstone unmarked without erasing when replication is enabled", () => {
    const replicated = createScopeDeletionHistory(db, OWNER, store, {
      replicationEnabled: true,
    });
    replicated.remember(SCOPE, deleted);
    expect(replicated.get(SCOPE)).toMatchObject({ version: "3" });
    expect(replicated.get(SCOPE)?.eraseApplied).not.toBe(true);
    expect(store.getRecord("connection", "activity", "old")).toBeDefined();
    expect(store.getInstanceBinding("connection").generation).toBe(1);
  });
  it("gates an earlier applied tombstone when replication is enabled after restart", () => {
    history.remember(SCOPE, deleted);
    replace("activity", "recollected", 2);
    const replicated = createScopeDeletionHistory(db, OWNER, store, {
      replicationEnabled: true,
    });
    expect(replicated.get(SCOPE)?.eraseApplied).not.toBe(true);
    expect(
      store.getRecord("connection", "activity", "recollected"),
    ).toBeDefined();
  });
  it("erases only the scope stream and fences old-generation writers", () => {
    const resetClock = store.getInstanceBinding("connection").resetClock;
    history.remember(SCOPE, deleted);
    expect(history.get(SCOPE)).toMatchObject({ eraseApplied: true });
    expect(store.getRecord("connection", "activity", "old")).toBeUndefined();
    expect(store.getRecord("connection", "readiness", "sibling")).toBeDefined();
    expect(store.getInstanceBinding("connection")).toMatchObject({
      generation: 2,
      resetClock: expect.any(Number),
    });
    expect(store.getInstanceBinding("connection").resetClock).toBeGreaterThan(
      resetClock,
    );
    expect(store.listStreamCompletions("connection")).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ stream: "readiness", generation: 2 }),
      ]),
    );
    expect(() => replace("activity", "stale")).toThrow();
    expect(replace("activity", "fresh", 2).applied).toBe(true);
    history.remember(SCOPE, deleted);
    history.remember(SCOPE, { ...deleted, version: "2" });
    expect(store.getRecord("connection", "activity", "fresh")).toBeDefined();
    expect(store.getInstanceBinding("connection").generation).toBe(2);
    history.remember(SCOPE, { ...deleted, version: "4" });
    expect(store.getRecord("connection", "activity", "fresh")).toBeUndefined();
    expect(store.getInstanceBinding("connection").generation).toBe(3);
  });

  it("refuses to mark a live deletion while an unbound orphan holds exclusive rows", () => {
    db.prepare(
      "INSERT INTO pdpp_records (instance, stream, record_key, data, version, emitted_at, deleted) VALUES ('orphan', 'activity', 'old', '{}', 1, '2026-09-10', 0)",
    ).run();
    const tracker = createScopeDeletionTracker({ deletionHistory: history });
    expect(() => tracker.markDeleted(SCOPE, deleted)).toThrow(
      "Cannot establish",
    );
    expect(tracker.deletionHistory?.get(SCOPE)?.eraseApplied).not.toBe(true);
    expect(store.getRecord("connection", "activity", "old")).toBeDefined();
  });
  it("expires a continuation token when a scope erase removes rows", () => {
    const page = store.changesSince("activity", {
      instanceIds: ["connection"],
      limit: 100,
    });
    history.remember(SCOPE, deleted);
    expect(() =>
      store.changesSince("activity", {
        instanceIds: ["connection"],
        changesSince: page.nextChangesSince,
        limit: 100,
      }),
    ).toThrow();
  });
  it("fences a bound collector even when the stream is still empty", () => {
    store.registerConnection({
      instance: "empty",
      sourceId: SOURCE,
      method: "oura",
      label: "",
    });
    history.remember(SCOPE, deleted);
    expect(store.getInstanceBinding("empty").generation).toBe(2);
  });

  it("erases on a feed observation and ignores the same tombstone after recollection", () => {
    const tracker = createScopeDeletionTracker({ deletionHistory: history });
    tracker.markDeleted(SCOPE, deleted, "feed");
    expect(store.getRecord("connection", "activity", "old")).toBeUndefined();
    expect(replace("activity", "fresh", 2).applied).toBe(true);
    tracker.markDeleted(SCOPE, deleted, "feed");
    expect(store.getRecord("connection", "activity", "fresh")).toBeDefined();
  });

  it("does not record a deletion while an existing record store is unavailable", () => {
    const unavailable = createScopeDeletionHistory(db, OWNER, () => undefined);
    expect(() => unavailable.remember(SCOPE, deleted)).toThrow(
      "Canonical record store unavailable for deletion observation",
    );
    expect(unavailable.get(SCOPE)).toBeNull();
    expect(store.getRecord("connection", "activity", "old")).toBeDefined();
  });

  it("retries pre-upgrade history when the same version is observed", () => {
    db.prepare(
      "INSERT INTO vana_scope_deletion_history (owner_address, scope, deleted_at, tombstone_version) VALUES (?, ?, ?, ?)",
    ).run(OWNER, SCOPE, deleted.deletedAt, deleted.version);
    expect(history.get(SCOPE)?.eraseApplied).not.toBe(true);
    history.remember(SCOPE, deleted);
    expect(history.get(SCOPE)?.eraseApplied).toBe(true);
    expect(store.getRecord("connection", "activity", "old")).toBeUndefined();
  });

  it("keeps a failed newer observation unmarked even when older history was applied", () => {
    const tracker = createScopeDeletionTracker({ deletionHistory: history });
    tracker.markDeleted(SCOPE, deleted, "feed");
    expect(replace("activity", "fresh", 2).applied).toBe(true);
    db.exec(
      "CREATE TRIGGER reject_generation BEFORE UPDATE OF generation ON pdpp_instance_binding BEGIN SELECT RAISE(ABORT, 'test rollback'); END",
    );
    expect(() =>
      tracker.markDeleted(
        SCOPE,
        { version: "4", deletedAt: "2026-09-12T00:00:00Z" },
        "feed",
      ),
    ).toThrow("test rollback");
    expect(tracker.deletionHistory?.get(SCOPE)).toMatchObject({ version: "4" });
    expect(tracker.deletionHistory?.get(SCOPE)?.eraseApplied).not.toBe(true);
    expect(store.getRecord("connection", "activity", "fresh")).toBeDefined();
  });

  it("rolls back history and row erasure together on failure", () => {
    db.exec(
      "CREATE TRIGGER reject_generation BEFORE UPDATE OF generation ON pdpp_instance_binding BEGIN SELECT RAISE(ABORT, 'test rollback'); END",
    );
    expect(() => history.remember(SCOPE, deleted)).toThrow("test rollback");
    expect(history.get(SCOPE)).toBeNull();
    expect(store.getRecord("connection", "activity", "old")).toBeDefined();
    expect(store.getInstanceBinding("connection").generation).toBe(1);
  });
});
