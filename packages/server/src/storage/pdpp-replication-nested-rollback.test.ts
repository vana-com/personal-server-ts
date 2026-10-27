/**
 * A canonical mutator called inside an outer transaction keeps its own
 * rollback boundary, with replication off and on, exactly as on main: a caller
 * that catches the mutator's error and commits keeps none of its writes.
 */
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { openRecordStore } from "../pdpp/records-bootstrap.js";
import type { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

const sourceId = "https://source.invalid/declaration";
const at = "2026-10-20T00:00:00.000Z";

type Store = ReturnType<typeof createSqliteRecordStore>;

const handles: Database.Database[] = [];
function open(): Database.Database {
  const db = new Database(":memory:");
  handles.push(db);
  return db;
}
afterEach(() => {
  for (const db of handles.splice(0)) if (db.open) db.close();
});

const register = (store: Store) =>
  store.registerConnection({
    instance: "conn_a",
    sourceId,
    method: "collector",
    label: "A",
  });
const ingest = (store: Store, key: string) =>
  store.ingestBatch(
    [
      {
        instance: "conn_a",
        stream: "messages",
        key,
        data: { id: key },
        emitted_at: at,
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );

describe.each([false, true])(
  "a nested canonical mutator rolls back by itself (replication %s)",
  (replication) => {
    /**
     * Calls `mutate` inside an outer transaction with `failure` armed, catches
     * the error inside the outer callback, and reports what the outer
     * transaction then sees and finally commits.
     */
    function nested(
      mutate: (store: Store) => unknown,
      failure: string,
    ): {
      seenInside: { keys: string[]; deleted: boolean; generation: number };
      committed: { keys: string[]; deleted: boolean; generation: number };
      journalBefore: number;
      journalAfter: number;
    } {
      const db = open();
      const store = openRecordStore(db, replication);
      register(store);
      ingest(store, "a");
      const journal = () =>
        replication
          ? (
              db
                .prepare("SELECT count(*) AS n FROM pdpp_replica_operations")
                .get() as { n: number }
            ).n
          : 0;
      const state = () => {
        const current = store.getInstanceBinding("conn_a");
        return {
          keys: (
            db
              .prepare(
                "SELECT record_key FROM pdpp_records WHERE deleted = 0 ORDER BY record_key",
              )
              .all() as { record_key: string }[]
          ).map((row) => row.record_key),
          deleted: current.deletedAt !== null,
          generation: current.generation,
        };
      };
      const journalBefore = journal();
      db.exec(failure);
      let seenInside!: ReturnType<typeof state>;
      store.writeTransaction(() => {
        expect(() => mutate(store)).toThrow(/injected failure/);
        seenInside = state();
      });
      return {
        seenInside,
        committed: state(),
        journalBefore,
        journalAfter: journal(),
      };
    }
    const untouched = { keys: ["a"], deleted: false, generation: 1 };

    it.each([
      [
        "deleteConnection",
        (store: Store) => store.deleteConnection("conn_a"),
        "CREATE TRIGGER fail BEFORE UPDATE ON pdpp_instance_binding WHEN NEW.deleted_at IS NOT NULL BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
      ],
      [
        "resetInstanceBinding",
        (store: Store) =>
          store.resetInstanceBinding({
            instance: "conn_a",
            expectedMethod: "collector",
            expectedGeneration: 1,
            nextMethod: "collector",
          }),
        "CREATE TRIGGER fail BEFORE UPDATE ON pdpp_instance_binding WHEN NEW.generation > OLD.generation BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
      ],
      [
        "replaceStream",
        (store: Store) =>
          store.replaceStream({
            instance: "conn_a",
            stream: "messages",
            method: "collector",
            generation: 1,
            emittedAt: at,
            envelopes: [],
            primaryKey: ["id"],
            sourceCollectedAt: at,
          }),
        "CREATE TRIGGER fail BEFORE INSERT ON pdpp_stream_completion BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
      ],
      [
        "deleteRecord",
        (store: Store) =>
          store.deleteRecord("conn_a", "messages", "a", at, "mutable_state"),
        "CREATE TRIGGER fail BEFORE INSERT ON pdpp_record_changes WHEN NEW.deleted = 1 BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
      ],
    ])("%s", (_name, mutate, failure) => {
      const result = nested(mutate, failure);
      expect(result.seenInside).toEqual(untouched);
      expect(result.committed).toEqual(untouched);
      expect(result.journalAfter).toBe(result.journalBefore);
    });
  },
);
