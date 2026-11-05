import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { initializeDatabase } from "./index-schema.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createScopeDeletionHistory } from "./scope-deletion-history.js";
import { createScopeDeletionTracker } from "@opendatalabs/personal-server-ts-core/sync";
import { resolveReadDeletion } from "@opendatalabs/personal-server-ts-core/api";
const scope = "icloud_notes.notes";
const owner = "0x1111111111111111111111111111111111111111";
const tomb = { version: "2", deletedAt: "2026-09-11T00:00:00Z" };
describe("shared scope full-reset proof", () => {
  let db: ReturnType<typeof initializeDatabase>;
  let store: ReturnType<typeof createSqliteRecordStore>;
  let history: ReturnType<typeof createScopeDeletionHistory>;
  function register(instance: string) {
    store.registerConnection({
      instance,
      sourceId: "https://registry.pdpp.dev/sources/icloud-notes",
      method: "icloud-notes",
      label: "",
    });
  }
  function write(instance = "conn", generation = 1) {
    return store.replaceStream({
      instance,
      stream: "folders",
      method: "icloud-notes",
      generation,
      primaryKey: ["id"],
      emittedAt: tomb.deletedAt,
      sourceCollectedAt: tomb.deletedAt,
      envelopes: [
        {
          instance,
          stream: "folders",
          key: "folder",
          data: { id: "folder" },
          emitted_at: tomb.deletedAt,
        },
      ],
    });
  }
  function reset() {
    const generation = store.getInstanceBinding("conn").generation;
    return store.resetInstanceBinding({
      instance: "conn",
      expectedMethod: "icloud-notes",
      expectedGeneration: generation,
      nextMethod: "icloud-notes",
    });
  }
  beforeEach(() => {
    db = initializeDatabase(":memory:");
    store = createSqliteRecordStore(db);
    register("conn");
    write();
    history = createScopeDeletionHistory(db, owner, store);
    history.remember(scope, tomb);
  });
  afterEach(() => store.close());
  it("lifts the gate after full reset and fresh collection, and rejects the old generation", async () => {
    const old = store.getInstanceBinding("conn").generation;
    reset();
    expect(() => write("conn", old)).toThrow();
    write("conn", old + 1);
    expect(
      await resolveReadDeletion(
        {
          scopeDeletions: createScopeDeletionTracker({
            deletionHistory: history,
          }),
        },
        scope,
        undefined,
        "canonical",
      ),
    ).toBeNull();
  });
  it.each([false, true])(
    "does not lift while another instance still holds rows (deleted=%s)",
    (deleted) => {
      register("other");
      write("other");
      if (deleted)
        db.prepare(
          "UPDATE pdpp_instance_binding SET deleted_at = ? WHERE instance = 'other'",
        ).run(tomb.deletedAt);
      reset();
      expect(history.get(scope)?.sharedFresh).not.toBe(true);
    },
  );
  it("does not lift a scope while its transition archive retains shared rows", () => {
    store.registerConnection({
      instance: "claude",
      sourceId: "https://registry.pdpp.dev/sources/claude",
      method: "anthropic",
      label: "",
    });
    db.prepare(
      "INSERT INTO pdpp_claude_transition(instance, archive_instance, generation, snapshots_json) VALUES ('claude', 'archive', 1, '{}')",
    ).run();
    db.prepare(
      "INSERT INTO pdpp_records(instance, stream, record_key, data, version, emitted_at, deleted) VALUES ('archive', 'account_profile', 'profile', '{}', 1, ?, 0)",
    ).run(tomb.deletedAt);
    history.remember("claude.projects", tomb);
    reset();
    expect(history.get("claude.projects")?.sharedFresh).not.toBe(true);
  });
  it("a connection delete can prove all shared rows empty", () => {
    store.deleteConnection("conn");
    expect(history.get(scope)?.sharedFresh).toBe(true);
  });
  it("does not lift under replication", () => {
    history = createScopeDeletionHistory(db, owner, store, {
      replicationEnabled: true,
    });
    reset();
    expect(history.get(scope)?.sharedFresh).not.toBe(true);
  });
  it("fences an empty peer's pre-deletion writer for a fully shared scope", () => {
    register("other");
    const old = store.getInstanceBinding("other").generation;
    history.remember("icloud_notes.folders", tomb);
    reset();
    expect(history.get("icloud_notes.folders")?.sharedFresh).toBe(true);
    expect(() => write("other", old)).toThrow();
  });
  it("a newer tombstone clears the full reset proof", () => {
    reset();
    expect(history.get(scope)?.sharedFresh).toBe(true);
    history.remember(scope, { ...tomb, version: "3" });
    expect(history.get(scope)?.sharedFresh).not.toBe(true);
  });
  it("an interrupted reset rolls back the erase and proof together", () => {
    db.exec(
      "CREATE TRIGGER reject_reset BEFORE UPDATE OF generation ON pdpp_instance_binding BEGIN SELECT RAISE(ABORT, 'reset interrupted'); END",
    );
    expect(reset).toThrow("reset interrupted");
    expect(history.get(scope)?.sharedFresh).not.toBe(true);
    expect(store.getRecord("conn", "folders", "folder")).toBeDefined();
  });
});
