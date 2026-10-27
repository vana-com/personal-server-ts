/**
 * Replication must not change what a plain open of the same file does, and its
 * derived state must follow commits that other connections make.
 *
 * - Flag off, a top-level mutation starts the transaction main started (a
 *   deferred one), so a no-op mutation does not need the write lock.
 * - With replication on, SQLite's `PRAGMA data_version` says when another
 *   connection committed (a flag-off build, or a main build, running
 *   concurrently). The view re-derives from canonical rows before it answers.
 * - A cursor never survives a change a plain writer made to the rows it pages.
 */
import Database from "better-sqlite3";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";

const sourceId = "https://source.invalid/declaration";
const at = "2026-10-20T00:00:00.000Z";
const binding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const streams = ["messages", "other", "s1", "s2"];
const bindings = streams.map((stream, index) => ({
  ...binding,
  stream,
  digest: `sha256:${index.toString(16).repeat(64)}`,
}));
const declarations: MergeContext["declarations"] = bindings.map((b) => ({
  sourceId,
  binding: b,
  validateData: (data) => typeof data.id === "string",
}));

type Store = ReturnType<typeof createSqliteRecordStore>;

const directories: string[] = [];
const handles: Database.Database[] = [];
function file(): string {
  const directory = mkdtempSync(join(tmpdir(), "pdpp-replication-concurrent-"));
  directories.push(directory);
  return join(directory, "db.sqlite");
}
/** `timeout` is the busy wait; short, so a lock conflict fails fast. */
function open(path: string): Database.Database {
  const db = new Database(path, { timeout: 50 });
  handles.push(db);
  return db;
}
afterEach(() => {
  for (const db of handles.splice(0)) if (db.open) db.close();
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

const register = (store: Store) =>
  store.registerConnection({
    instance: "conn_a",
    sourceId,
    method: "collector",
    label: "A",
  });
const envelope = (
  instance: string,
  stream: string,
  key: string,
  text = key,
) => ({
  instance,
  stream,
  key,
  data: { id: key, text },
  emitted_at: at,
});
const ingest = (
  store: Store,
  key: string,
  text = key,
  stream = "messages",
  instance = "conn_a",
) =>
  store.ingestBatch(
    [envelope(instance, stream, key, text)],
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );

function receiverOf(
  db: Database.Database,
  store: ReturnType<typeof createReplicaRecordStore>,
) {
  return createReplicaReceiver({
    db,
    store,
    owner: "owner",
    enabled: true,
    authenticate: () => "owner",
    declarations: () => declarations,
  });
}

describe("flag off: the top-level transaction is main's", () => {
  it("a mutation that writes nothing needs no write lock", () => {
    const path = file();
    const db = open(path);
    const store = createSqliteRecordStore(db);
    register(store);
    ingest(store, "a");

    const other = open(path);
    other.exec("BEGIN IMMEDIATE");
    // Another connection holds the write lock. These write nothing.
    expect(
      store.deleteRecord("conn_a", "messages", "missing", at, "mutable_state"),
    ).toBe(false);
    expect(() =>
      store.ingestBatch(
        [],
        () => "mutable_state",
        () => ["id"],
        { method: "collector", generation: 1 },
      ),
    ).not.toThrow();
    // A write still needs the lock, as on main.
    expect(() => ingest(store, "b")).toThrow(/SQLITE_BUSY|database is locked/);
    other.exec("ROLLBACK");
    ingest(store, "b");
  });
});

describe("replication on: derived state follows other connections", () => {
  it("lists a stream another connection created, without a restart", () => {
    const path = file();
    const aDb = open(path);
    const a = createReplicaRecordStore(aDb);
    register(a);
    a.replication.beginBaseline({
      owner: "owner",
      declarations: bindings.map((b) => ({ sourceId, binding: b })),
    });
    const receiver = receiverOf(aDb, a);
    ingest(a, "first");
    const reads = receiver.readStore({ reader: "owner" });
    expect(reads.listStreams(["conn_a"]).map((s) => s.stream)).toEqual([
      "messages",
    ]);

    // A plain connection (a flag-off build, or main) commits a new stream.
    const bDb = open(path);
    const b = createSqliteRecordStore(bDb);
    ingest(b, "x", "x", "other");
    ingest(b, "second");
    ingest(b, "third");
    b.deleteRecord("conn_a", "messages", "first", at, "mutable_state");

    const streams = reads.listStreams(["conn_a"]);
    expect(streams.map((s) => s.stream).sort()).toEqual(["messages", "other"]);
    expect(streams.find((s) => s.stream === "messages")?.recordCount).toBe(2);
    expect(streams.find((s) => s.stream === "other")?.recordCount).toBe(1);
  });

  it("refuses a cursor after another connection changed a row's content at the same instant", () => {
    const path = file();
    const aDb = open(path);
    const a = createReplicaRecordStore(aDb);
    register(a);
    a.replication.beginBaseline({
      owner: "owner",
      declarations: bindings.map((b) => ({ sourceId, binding: b })),
    });
    const receiver = receiverOf(aDb, a);
    ingest(a, "a");
    ingest(a, "b");
    const reads = receiver.readStore({ reader: "owner" });
    const first = reads.listRecords("messages", {
      instanceIds: ["conn_a"],
      limit: 1,
      order: "asc",
    });
    expect(first.nextCursor).toBeTruthy();

    // Same key, same timestamp, other text: count and latest instant match.
    const bDb = open(path);
    ingest(createSqliteRecordStore(bDb), "b", "changed");

    expect(() =>
      reads.listRecords("messages", {
        instanceIds: ["conn_a"],
        limit: 1,
        order: "asc",
        cursor: first.nextCursor,
      }),
    ).toThrow();
  });

  it("refuses a cursor minted before a restart when a plain open changed content meanwhile", () => {
    const path = file();
    const aDb = open(path);
    const a = createReplicaRecordStore(aDb);
    register(a);
    a.replication.beginBaseline({
      owner: "owner",
      declarations: bindings.map((b) => ({ sourceId, binding: b })),
    });
    const receiver = receiverOf(aDb, a);
    ingest(a, "a");
    ingest(a, "b");
    const first = receiver
      .readStore({ reader: "owner" })
      .listRecords("messages", {
        instanceIds: ["conn_a"],
        limit: 1,
        order: "asc",
      });
    expect(first.nextCursor).toBeTruthy();
    aDb.close();

    const plainDb = open(path);
    ingest(createSqliteRecordStore(plainDb), "b", "changed");
    plainDb.close();

    const againDb = open(path);
    const again = createReplicaRecordStore(againDb);
    expect(() =>
      receiverOf(againDb, again)
        .readStore({ reader: "owner" })
        .listRecords("messages", {
          instanceIds: ["conn_a"],
          limit: 1,
          order: "asc",
          cursor: first.nextCursor,
        }),
    ).toThrow();
  });

  it("a write after another connection's commit counts both writers' rows", () => {
    const path = file();
    const aDb = open(path);
    const a = createReplicaRecordStore(aDb);
    register(a);
    a.replication.beginBaseline({
      owner: "owner",
      declarations: bindings.map((b) => ({ sourceId, binding: b })),
    });
    const reads = receiverOf(aDb, a).readStore({ reader: "owner" });
    ingest(a, "mine");
    reads.listStreams(["conn_a"]);

    // Another connection's first row of a stream, then this connection's own.
    ingest(createSqliteRecordStore(open(path)), "theirs", "theirs", "other");
    ingest(a, "mine", "mine", "other");

    expect(
      reads.listStreams(["conn_a"]).find((s) => s.stream === "other")
        ?.recordCount,
    ).toBe(2);
  });

  it("a mutation that fails still leaves the other connection's commit followed", () => {
    const path = file();
    const aDb = open(path);
    const a = createReplicaRecordStore(aDb);
    register(a);
    a.replication.beginBaseline({
      owner: "owner",
      declarations: bindings.map((b) => ({ sourceId, binding: b })),
    });
    const reads = receiverOf(aDb, a).readStore({ reader: "owner" });
    ingest(a, "mine");

    ingest(createSqliteRecordStore(open(path)), "theirs", "theirs", "other");
    expect(() => ingest(a, "nope", "nope", "messages", "unknown")).toThrow();

    expect(
      reads
        .listStreams(["conn_a"])
        .map((s) => s.stream)
        .sort(),
    ).toEqual(["messages", "other"]);
  });

  it("an outer transaction is not committed or rolled back by following", () => {
    const path = file();
    const aDb = open(path);
    const a = createReplicaRecordStore(aDb);
    register(a);
    a.replication.beginBaseline({
      owner: "owner",
      declarations: bindings.map((b) => ({ sourceId, binding: b })),
    });
    const reads = receiverOf(aDb, a).readStore({ reader: "owner" });
    ingest(a, "mine");

    ingest(createSqliteRecordStore(open(path)), "theirs", "theirs", "other");
    // Inside the caller's transaction a read cannot follow (no write there), and
    // must not disturb the transaction; the next top-level read follows.
    aDb.exec("BEGIN");
    reads.listStreams(["conn_a"]);
    expect(aDb.inTransaction).toBe(true);
    aDb.exec("ROLLBACK");
    expect(
      reads
        .listStreams(["conn_a"])
        .map((s) => s.stream)
        .sort(),
    ).toEqual(["messages", "other"]);
  });

  it("matches a plain open's listing after any mix of other-connection writes", () => {
    const path = file();
    const aDb = open(path);
    const a = createReplicaRecordStore(aDb);
    register(a);
    a.replication.beginBaseline({
      owner: "owner",
      declarations: bindings.map((b) => ({ sourceId, binding: b })),
    });
    const reads = receiverOf(aDb, a).readStore({ reader: "owner" });
    const plain = createSqliteRecordStore(open(path));
    const put = (stream: string, key: string, emittedAt: string, text = key) =>
      plain.ingestBatch(
        [
          {
            instance: "conn_a",
            stream,
            key,
            data: { id: key, text },
            emitted_at: emittedAt,
          },
        ],
        () => "mutable_state",
        () => ["id"],
        { method: "collector", generation: 1 },
      );
    const agree = (label: string) => {
      const mine = (x: { stream: string }[]) =>
        JSON.stringify([...x].sort((l, r) => l.stream.localeCompare(r.stream)));
      expect(mine(reads.listStreams(["conn_a"])), label).toBe(
        mine(plain.listStreams(["conn_a"])),
      );
      for (const stream of ["s1", "s2"]) {
        const options = {
          instanceIds: ["conn_a"],
          limit: 100,
          order: "asc" as const,
        };
        expect(
          reads.listRecords(stream, options).data.map((r) => r.recordKey),
          label,
        ).toEqual(
          plain.listRecords(stream, options).data.map((r) => r.recordKey),
        );
      }
    };
    ingest(a, "seed", "seed", "s1");
    agree("seed");
    put("s1", "a", "2026-10-21T00:00:00.000Z");
    put("s1", "b", "2026-10-22T00:00:00.000Z");
    agree("two new rows");
    put("s1", "a", "2026-10-20T00:00:00.000Z", "older now");
    agree("a row moved earlier");
    plain.deleteRecord(
      "conn_a",
      "s1",
      "b",
      "2026-10-23T00:00:00.000Z",
      "mutable_state",
    );
    agree("the latest row deleted");
    put("s2", "z", "2026-10-24T00:00:00.000Z");
    agree("a new stream");
    plain.replaceStream({
      instance: "conn_a",
      stream: "s1",
      method: "collector",
      generation: 1,
      emittedAt: "2026-10-25T00:00:00.000Z",
      envelopes: [
        {
          instance: "conn_a",
          stream: "s1",
          key: "only",
          data: { id: "only" },
          emitted_at: "2026-10-25T00:00:00.000Z",
        },
      ],
      primaryKey: ["id"],
    });
    agree("a stream replaced");
    plain.resetInstanceBinding({
      instance: "conn_a",
      expectedMethod: "collector",
      expectedGeneration: 1,
      nextMethod: "collector",
    });
    agree("the connection reset");
    plain.deleteConnection("conn_a");
    agree("the connection deleted");
  });

  it("a commit landing between the version check and the write's BEGIN is followed", () => {
    const path = file();
    const aDb = open(path);
    const a = createReplicaRecordStore(aDb);
    register(a);
    a.replication.beginBaseline({
      owner: "owner",
      declarations: bindings.map((b) => ({ sourceId, binding: b })),
    });
    const reads = receiverOf(aDb, a).readStore({ reader: "owner" });
    ingest(a, "mine", "mine", "other");
    reads.listStreams(["conn_a"]);

    // The other connection commits right after A finds nothing new, before
    // A's write transaction begins.
    const plain = createSqliteRecordStore(open(path));
    let raced = false;
    const transaction = aDb.transaction.bind(aDb);
    vi.spyOn(aDb, "transaction").mockImplementation(((fn: () => unknown) => {
      const real = transaction(fn);
      return Object.assign((...args: unknown[]) => real(...args), {
        deferred: real.deferred,
        exclusive: real.exclusive,
        immediate: () => {
          if (!raced && !aDb.inTransaction) {
            raced = true;
            ingest(plain, "theirs", "theirs", "other");
          }
          return real.immediate();
        },
      });
    }) as unknown as typeof aDb.transaction);
    ingest(a, "mine again", "mine again", "other");

    expect(raced).toBe(true);
    expect(
      reads.listStreams(["conn_a"]).find((s) => s.stream === "other")
        ?.recordCount,
    ).toBe(3);
  });

  it("hides every row of a connection another connection deleted, across several flush pages", () => {
    const path = file();
    const aDb = open(path);
    const a = createReplicaRecordStore(aDb);
    register(a);
    a.replication.beginBaseline({
      owner: "owner",
      declarations: bindings.map((b) => ({ sourceId, binding: b })),
    });
    const reads = receiverOf(aDb, a).readStore({ reader: "owner" });
    const plain = createSqliteRecordStore(open(path));
    // More keys than one flush page (1000) holds.
    for (let batch = 0; batch < 3; batch++)
      plain.ingestBatch(
        Array.from({ length: 900 }, (_, k) =>
          envelope("conn_a", "messages", `k${batch}-${k}`),
        ),
        () => "mutable_state",
        () => ["id"],
        { method: "collector", generation: 1 },
      );
    expect(
      reads.listStreams(["conn_a"]).find((s) => s.stream === "messages")
        ?.recordCount,
    ).toBe(2700);

    plain.deleteConnection("conn_a");

    expect(reads.listStreams(["conn_a"])).toEqual([]);
    expect(
      reads.listRecords("messages", { instanceIds: ["conn_a"], limit: 5 }).data,
    ).toEqual([]);
  });
});
