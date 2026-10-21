import Database from "better-sqlite3";
import { afterEach, expect, it, vi } from "vitest";
import {
  binding,
  identity,
  registration,
  upsert,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import {
  CursorExpiredError,
  decodeCursor,
  encodeCursor,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";

const stores: ReturnType<typeof createSqliteRecordStore>[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const store of stores.splice(0)) store.close();
});

const envelope = (batchId: string, operations: unknown[]) => ({
  format: "vana-pdpp-replica",
  version: 1,
  owner: identity.owner,
  batchId,
  operations,
});

function fixture(
  size = 3,
  { local = false, epoch }: { local?: boolean; epoch?: () => number } = {},
) {
  const db = new Database(":memory:");
  const store = createSqliteRecordStore(db);
  stores.push(store);
  store.registerConnection({
    instance: identity.connectionId,
    sourceId: identity.sourceId,
    method: identity.methodId,
    label: "A",
  });
  const declarations = [binding, { ...binding, stream: "other" }].map(
    (binding) => ({
      sourceId: identity.sourceId,
      binding,
      validateData: (data: Record<string, unknown>) =>
        typeof data.id === "string",
    }),
  );
  store.replication.beginBaseline({ owner: identity.owner, declarations });
  // Compose the hardening lane's fact seam without owning its migration/policy.
  if (local)
    db.exec(
      "CREATE TABLE IF NOT EXISTS pdpp_replica_binding_conflicts (instance TEXT PRIMARY KEY, reason TEXT NOT NULL, evidence_json TEXT NOT NULL)",
    );
  // The synthesis lane's integrity epoch is an optional store capability.
  const host = epoch
    ? { ...store, replicaIntegrityEpoch: (_connection: string) => epoch() }
    : store;
  const receiver = createReplicaReceiver({
    db,
    store: host,
    owner: identity.owner,
    authenticate: (credential) =>
      credential === "secret" ? identity.owner : undefined,
    declarations: () => declarations,
    enabled: true,
    visibilityPolicy: { owner: "include-pending", grant: "confirmed-only" },
  });
  const records = Array.from({ length: size }, (_, i) => ({
    ...upsert(`row-${i}`, i + 2),
    recordKey: `key-${i.toString().padStart(3, "0")}`,
    data: { id: `key-${i.toString().padStart(3, "0")}` },
  }));
  if (local) {
    store.ingestBatch(
      records.map((row) => ({
        instance: identity.connectionId,
        stream: binding.stream,
        key: row.recordKey,
        data: row.data,
        emitted_at: row.emittedAt,
      })),
      () => binding.semantics,
      () => ["id"],
      { method: identity.methodId, generation: 1 },
    );
    db.prepare(
      "INSERT INTO pdpp_replica_binding_conflicts VALUES (?, 'source_binding_conflict', '{}')",
    ).run(identity.connectionId);
  } else {
    receiver.import({
      credential: "secret",
      envelope: envelope("initial", [registration, ...records]),
    });
  }
  const options = {
    instanceIds: [identity.connectionId],
    limit: 1,
    order: "asc" as const,
  };
  const owner = receiver.readStore({ reader: "owner" });
  const grant = receiver.readStore({ reader: "grant" });
  const cursors = () =>
    [owner, grant].map(
      (read) => read.listRecords(binding.stream, options).nextCursor!,
    );
  const continues = (cursor: string[]) =>
    [owner, grant].map(
      (read, i) =>
        read.listRecords(binding.stream, { ...options, cursor: cursor[i] })
          .data[0]?.recordKey,
    );
  return { db, store, receiver, options, owner, grant, cursors, continues };
}

function countViewWrites(db: Database.Database) {
  const tables = (
    db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'pdpp_replica_view%' AND name NOT LIKE '%dirty%'",
      )
      .all() as { name: string }[]
  ).map((row) => row.name);
  db.exec(
    "CREATE TABLE view_writes (n INTEGER); INSERT INTO view_writes VALUES (0);",
  );
  for (const table of tables)
    for (const event of ["INSERT", "UPDATE", "DELETE"])
      db.exec(
        `CREATE TRIGGER count_${table}_${event} AFTER ${event} ON ${table} BEGIN UPDATE view_writes SET n=n+1; END;`,
      );
  return () =>
    (db.prepare("SELECT n FROM view_writes").get() as { n: number }).n;
}

it.each([1, 120])(
  "idle retry does zero view materialization or row writes at %i keys and preserves cursors",
  (size) => {
    // One continuation sentinel supplements the 1/120 target keys.
    const { db, receiver, cursors, continues } = fixture(size + 1);
    const before = cursors();
    const writes = countViewWrites(db);
    const prepare = vi.spyOn(db, "prepare");
    receiver.retry({ credential: "secret" });
    expect(writes()).toBe(0);
    expect(
      prepare.mock.calls.filter(([sql]) =>
        sql.includes("pdpp_replica_view_operations"),
      ),
    ).toHaveLength(0);
    expect(continues(before)).toEqual(["key-001", "key-001"]);
  },
);

it("explicit unchanged declaration reconciliation writes no view row and keeps cursors", () => {
  const { db, receiver, cursors, continues } = fixture();
  const before = cursors();
  const writes = countViewWrites(db);
  receiver.reconcileDeclarations({ credential: "secret" });
  expect(writes()).toBe(0);
  expect(continues(before)).toEqual(["key-001", "key-001"]);
});

it("other-stream writes preserve owner and grant cursors on the same connection", () => {
  const { receiver, cursors, continues } = fixture();
  const before = cursors();
  receiver.import({
    credential: "secret",
    envelope: envelope("other-stream", [
      { ...upsert("other", 50), declaration: { ...binding, stream: "other" } },
    ]),
  });
  expect(continues(before)).toEqual(["key-001", "key-001"]);
});

it("pending-only churn on the same stream never moves grant cursors", () => {
  const { receiver, owner, grant, options } = fixture();
  const [ownerCursor, grantCursor] = [owner, grant].map(
    (read) => read.listRecords(binding.stream, options).nextCursor!,
  );
  receiver.stage({
    credential: "secret",
    id: "pending",
    envelope: envelope("pending", [
      {
        ...upsert("pending", 90),
        recordKey: "key-002",
        data: { id: "key-002", text: "p" },
      },
    ]),
  });
  expect(() =>
    owner.listRecords(binding.stream, { ...options, cursor: ownerCursor }),
  ).toThrow(CursorExpiredError);
  receiver.quarantine({ credential: "secret", id: "pending", reason: "test" });
  expect(
    grant.listRecords(binding.stream, { ...options, cursor: grantCursor })
      .data[0]?.recordKey,
  ).toBe("key-001");
});

it("a connection lifecycle change expires owner and grant cursors on every stream", () => {
  const { receiver, owner, grant, options } = fixture();
  receiver.import({
    credential: "secret",
    envelope: envelope("other-rows", [
      ...["o-1", "o-2"].map((key, i) => ({
        ...upsert(key, 60 + i),
        recordKey: key,
        data: { id: key },
        declaration: { ...binding, stream: "other" },
      })),
    ]),
  });
  const before = [binding.stream, "other"].flatMap((stream) =>
    [owner, grant].map((read) => ({
      read,
      stream,
      cursor: read.listRecords(stream, options).nextCursor!,
    })),
  );
  receiver.import({
    credential: "secret",
    envelope: envelope("reset", [
      {
        ...registration,
        kind: "connection-reset",
        generation: 2,
        previousGeneration: 1,
        revision: { counter: 900, writerId: "device-a", operationId: "reset" },
      },
    ]),
  });
  for (const { read, stream, cursor } of before)
    expect(() => read.listRecords(stream, { ...options, cursor })).toThrow(
      CursorExpiredError,
    );
});

it.each([false, true])(
  "an integrity epoch change expires owner and grant cursors (conflicted connection=%s)",
  (local) => {
    let epoch = 7;
    const { owner, grant, options } = fixture(3, { local, epoch: () => epoch });
    const readers = local ? [owner] : [owner, grant];
    const before = readers.map(
      (read) => read.listRecords(binding.stream, options).nextCursor!,
    );
    expect(
      readers.map(
        (read, i) =>
          read.listRecords(binding.stream, { ...options, cursor: before[i] })
            .data[0]?.recordKey,
      ),
    ).toEqual(readers.map(() => "key-001"));
    epoch++;
    for (const [i, read] of readers.entries())
      expect(() =>
        read.listRecords(binding.stream, { ...options, cursor: before[i] }),
      ).toThrow(CursorExpiredError);
  },
);

it("cursors minted in the previous view-revision format expire", () => {
  const { owner, grant, options } = fixture();
  for (const read of [owner, grant]) {
    const payload = decodeCursor(
      read.listRecords(binding.stream, options).nextCursor!,
    );
    if (payload.kind !== "list") throw new Error("list cursor expected");
    // 70d52db0 format: [[instance, mode, fence, ...connection clocks]].
    const legacy = encodeCursor({
      ...payload,
      viewRevision: JSON.stringify([
        [
          identity.connectionId,
          read === owner ? "preview" : "canonical",
          0,
          1,
          1,
        ],
      ]),
    });
    expect(() =>
      read.listRecords(binding.stream, { ...options, cursor: legacy }),
    ).toThrow(CursorExpiredError);
  }
});
