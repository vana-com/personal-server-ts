import Database from "better-sqlite3";
import { afterEach, expect, it, vi } from "vitest";
import {
  binding,
  identity,
  registration,
  upsert,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import { planReplicaMerge } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import type * as MergePlan from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";

// Count reducer runs: the receiver's canonical reconcile plus any view materialization.
vi.mock(
  "@opendatalabs/personal-server-ts-core/replication/merge-plan",
  async (original) => {
    const actual = await original<typeof MergePlan>();
    return { ...actual, planReplicaMerge: vi.fn(actual.planReplicaMerge) };
  },
);
const merges = vi.mocked(planReplicaMerge);

const stores: ReturnType<typeof createSqliteRecordStore>[] = [];
afterEach(() => {
  merges.mockClear();
  for (const store of stores.splice(0)) store.close();
});

const declarations = [
  { sourceId: identity.sourceId, binding, validateData: () => true },
];
const envelope = (batchId: string, operations: unknown[]) => ({
  format: "vana-pdpp-replica",
  version: 1,
  owner: identity.owner,
  batchId,
  operations,
});
const rows = (prefix: string, n: number, instance = identity.connectionId) =>
  Array.from({ length: n }, (_, i) => {
    const key = `${prefix}${String(i).padStart(4, "0")}`;
    return {
      instance,
      stream: binding.stream,
      key,
      data: { id: key, text: "x".repeat(200) },
      emitted_at: `2026-10-21T00:00:${String(i % 60).padStart(2, "0")}.000Z`,
    };
  });

function device(size: number) {
  const db = new Database(":memory:");
  const store = createSqliteRecordStore(db);
  stores.push(store);
  store.registerConnection({
    instance: identity.connectionId,
    sourceId: identity.sourceId,
    method: identity.methodId,
    label: "A",
  });
  store.replication.beginBaseline({ owner: identity.owner, declarations });
  const ingest = (batch: ReturnType<typeof rows>) =>
    store.ingestBatch(
      batch,
      () => "mutable_state",
      () => ["id"],
      {
        method: identity.methodId,
        generation: 1,
      },
    );
  ingest(rows("base", size));
  const receiver = () =>
    createReplicaReceiver({
      db,
      store,
      owner: identity.owner,
      authenticate: () => identity.owner,
      declarations: () => declarations,
      enabled: true,
    });
  return { db, store, ingest, receiver };
}

/** Bytes held by derived view tables and their indexes. */
function viewBytes(db: Database.Database) {
  return (
    db
      .prepare(
        "SELECT COALESCE(SUM(pgsize),0) AS bytes FROM dbstat WHERE name IN (SELECT name FROM sqlite_master WHERE tbl_name GLOB 'pdpp_replica_view*' OR tbl_name='pdpp_replica_local_view')",
      )
      .get() as { bytes: number }
  ).bytes;
}
const overlayRows = (db: Database.Database) =>
  (
    db.prepare("SELECT COUNT(*) AS n FROM pdpp_replica_view").get() as {
      n: number;
    }
  ).n;

it.each([100, 1000])(
  "keeps derived view storage independent of %i canonical rows",
  (size) => {
    const { db, receiver } = device(size);
    receiver();
    expect(overlayRows(db)).toBe(0);
    // A handful of 4 KiB pages, never a copy of rows or operation JSON.
    expect(viewBytes(db)).toBeLessThan(25 * 4096);
  },
);

it("persists only keys whose owner-visible state differs from canonical", () => {
  const { db, receiver } = device(120);
  const replica = receiver();
  replica.stage({
    credential: "x",
    id: "pending",
    envelope: envelope("pending", [
      {
        ...upsert("pending", 1_000_000, "pending", "device-b"),
        recordKey: "base0007",
        data: { id: "base0007", text: "pending" },
      },
    ]),
  });
  expect(overlayRows(db)).toBe(1);
  const owner = replica.readStore({ reader: "owner" });
  expect(
    owner.getRecord(identity.connectionId, binding.stream, "base0007"),
  ).toMatchObject({
    data: { text: "pending" },
    visibility: "pending",
  });
  const page = owner.listRecords(binding.stream, {
    instanceIds: [identity.connectionId],
    limit: 200,
    order: "asc",
  });
  expect(page.data).toHaveLength(120);
  expect(page.data.filter((row) => row.visibility === "pending")).toHaveLength(
    1,
  );
  replica.quarantine({ credential: "x", id: "pending", reason: "test" });
  expect(overlayRows(db)).toBe(0);
});

it("runs no view reducer for constructor rebuild or local ingest outside pending keys", () => {
  const { ingest, receiver } = device(300);
  merges.mockClear();
  const replica = receiver();
  expect(merges).not.toHaveBeenCalled();
  replica.stage({
    credential: "x",
    id: "pending",
    envelope: envelope("pending", [
      {
        ...registration,
        revision: {
          counter: 1,
          writerId: "device-b",
          operationId: "register-b",
        },
      },
      {
        ...upsert("pending", 1_000_000, "pending", "device-b"),
        recordKey: "base0007",
        data: { id: "base0007", text: "pending" },
      },
    ]),
  });
  merges.mockClear();
  ingest(rows("new", 200));
  expect(merges).not.toHaveBeenCalled();
});

it("keeps the local journal projection only for conflicted connections", () => {
  const { db, store, ingest } = device(50);
  store.registerConnection({
    instance: "connection-b",
    sourceId: identity.sourceId,
    method: identity.methodId,
    label: "B",
  });
  ingest(rows("b", 50, "connection-b"));
  db.exec(
    "CREATE TABLE pdpp_replica_binding_conflicts (instance TEXT PRIMARY KEY)",
  );
  db.prepare("INSERT INTO pdpp_replica_binding_conflicts VALUES (?)").run(
    "connection-b",
  );
  const replica = createReplicaReceiver({
    db,
    store,
    owner: identity.owner,
    authenticate: () => identity.owner,
    declarations: () => declarations,
    enabled: true,
  });
  expect(
    db.prepare("SELECT DISTINCT instance FROM pdpp_replica_local_view").all(),
  ).toEqual([{ instance: "connection-b" }]);
  ingest(rows("late", 5));
  expect(
    db.prepare("SELECT DISTINCT instance FROM pdpp_replica_local_view").all(),
  ).toEqual([{ instance: "connection-b" }]);
  const owner = replica.readStore({ reader: "owner" });
  expect(
    owner.listRecords(binding.stream, {
      instanceIds: ["connection-b"],
      limit: 100,
      order: "asc",
    }).data,
  ).toHaveLength(50);
  db.prepare("INSERT INTO pdpp_replica_binding_conflicts VALUES (?)").run(
    identity.connectionId,
  );
  expect(
    owner.listRecords(binding.stream, {
      instanceIds: [identity.connectionId],
      limit: 100,
      order: "asc",
    }).data,
  ).toHaveLength(55);
});
