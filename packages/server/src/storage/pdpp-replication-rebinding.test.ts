/**
 * Declaration rebinding (host contract §4.5): deterministic two-writer traces
 * over the real record store, journal, receiver and transport worker. A
 * device rebinds the way a host does on boot: `beginBaseline` with its new
 * bindings, then a trusted set of those bindings plus every retained one.
 */
import Database from "better-sqlite3";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { DeclarationBinding } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import { replicaSchemaDigest } from "@opendatalabs/personal-server-ts-core/replication/host-config";
import {
  at,
  binding,
  cleanupHarness,
  cycles,
  network,
  owner,
  scratchDirectory,
  sourceId,
  transportDevice,
  type TransportDevice,
} from "./pdpp-replica-contract.test-utils.js";
import {
  REPLICA_MIGRATIONS,
  createReplicaRecordStore,
  ensureReplicaSchema,
} from "./pdpp-replica-canonical-port.js";
import { REPLICA_BINDING_HISTORY_MIGRATION } from "./pdpp-replication-sqlite.js";

afterEach(cleanupHarness);

const v1 = { sourceId, binding };
const v2 = {
  sourceId,
  binding: {
    ...binding,
    digest: `sha256:${"d".repeat(64)}`,
    version: "2",
    schemaDigest: `sha256:${"e".repeat(64)}`,
  },
};
const otherSource = "https://source.invalid/added";
const added = {
  sourceId: otherSource,
  binding: { ...binding, digest: `sha256:${"f".repeat(64)}` },
};
type Entry = { sourceId: string; binding: DeclarationBinding };

/** Rebind as a host does: new bindings, then trust them and every retained one. */
function rebind(d: TransportDevice, next: Entry[]) {
  d.store.replication.beginBaseline({ owner, declarations: next });
  d.declarations([...next, ...d.store.replication.declarationHistory()]);
}

const generation = (d: TransportDevice) =>
  d.store.replication.bindingGeneration();

function remove(d: TransportDevice, id: string, instance = d.instance) {
  d.store.deleteRecord(instance, "messages", id, at, "mutable_state");
}

/** The device's visible text per key; a deleted or absent key reads null. */
function view(d: TransportDevice, ids: string[], instance = d.instance) {
  return Object.fromEntries(
    ids.map((id) => [
      id,
      d.store.getRecord(instance, "messages", id)?.data.text ?? null,
    ]),
  );
}

/** Each version a device's own journal wrote, in journal order. */
function writtenVersions(d: TransportDevice) {
  return (
    d.db
      .prepare(
        "SELECT json_extract(operation_json, '$.declaration.version') AS v FROM pdpp_replica_operations ORDER BY sequence",
      )
      .all() as { v: string | null }[]
  ).flatMap((row) => (row.v === null ? [] : [row.v]));
}

/** The dependency the reconcile phase waits on, if any. */
const reconcileWait = (d: TransportDevice) =>
  (
    d.db
      .prepare(
        "SELECT dependency FROM pdpp_transport_phase_state WHERE phase='reconcile'",
      )
      .get() as { dependency: string | null } | undefined
  )?.dependency ?? null;

/** Import work that waits on a declaration: a stopped writer chain. */
const importDeclarationWaits = (d: TransportDevice) =>
  d.db
    .prepare(
      "SELECT 1 FROM pdpp_transport_import_work WHERE dependency LIKE 'declaration:%'",
    )
    .all().length;

function putIn(d: TransportDevice, instance: string, id: string, text: string) {
  d.store.ingestBatch(
    [
      {
        instance,
        stream: "messages",
        key: id,
        data: { id, text },
        emitted_at: at,
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "export", generation: 1 },
  );
}

describe("two-writer rebinding traces", () => {
  it("upgrade on one device first: the other keeps its chain, then converges when it upgrades", async () => {
    const net = network();
    const a = transportDevice(net);
    const b = transportDevice(net);
    a.put("a1", "a");
    a.put("x1", "x");
    await cycles([a, b], 6);
    expect(view(b, ["a", "x"])).toEqual({ a: "a1", x: "x1" });

    rebind(a, [v2]);
    expect(generation(a)).toBe(2);
    a.put("a2", "a");
    remove(a, "x");
    a.put("b2", "b");
    b.put("c1", "c");
    await cycles([a, b], 8);

    // A trusts both versions, so it takes B's v1 write.
    expect(view(a, ["a", "b", "c", "x"])).toEqual({
      a: "a2",
      b: "b2",
      c: "c1",
      x: null,
    });
    // B imported A's v2 batch but cannot validate it yet: it stays pending
    // (no loss), the wait sits on reconcile, and A's chain is not stopped.
    expect(view(b, ["a", "b", "c", "x"])).toEqual({
      a: "a1",
      b: null,
      c: "c1",
      x: "x1",
    });
    expect(reconcileWait(b)).toBe(`declaration:${sourceId}:messages`);
    expect(importDeclarationWaits(b)).toBe(0);
    // A later v2 batch from A is imported too, not held behind the first.
    a.put("b3", "b");
    await cycles([a, b], 6);
    expect(importDeclarationWaits(b)).toBe(0);
    expect(view(b, ["b"])).toEqual({ b: null });

    rebind(b, [v2]);
    b.put("c2", "c");
    await cycles([a, b], 8);
    const final = { a: "a2", b: "b3", c: "c2", x: null };
    expect(view(a, ["a", "b", "c", "x"])).toEqual(final);
    expect(view(b, ["a", "b", "c", "x"])).toEqual(final);
    expect(reconcileWait(b)).toBeNull();
    expect(writtenVersions(b)).toContain("1");
    expect(writtenVersions(b).at(-1)).toBe("2");
  }, 60_000);

  it("upgrade on both devices at once: concurrent writes under the new binding converge", async () => {
    const net = network();
    const a = transportDevice(net);
    const b = transportDevice(net);
    a.put("base", "a");
    a.put("x1", "x");
    a.put("y1", "y");
    await cycles([a, b], 6);

    rebind(a, [v2]);
    rebind(b, [v2]);
    a.put("from A", "a");
    b.put("from B", "a");
    remove(a, "x");
    b.put("y-B", "y");
    remove(a, "y");
    await cycles([a, b], 10);

    const ids = ["a", "x", "y"];
    expect(view(a, ids)).toEqual(view(b, ids));
    // A delete is never undone by an older write, under either version.
    expect(view(a, ["x"])).toEqual({ x: null });
    expect(["from A", "from B"]).toContain(view(a, ["a"]).a);
    expect(generation(a)).toBe(2);
    expect(generation(b)).toBe(2);
    expect(reconcileWait(a)).toBeNull();
    expect(reconcileWait(b)).toBeNull();
  }, 60_000);

  it("upgrade during in-flight batches: older-version operations publish and apply on both sides", async () => {
    const net = network();
    const a = transportDevice(net);
    const b = transportDevice(net);
    a.put("seed", "s");
    await cycles([a, b], 6);

    // A v1 batch is published but B has not imported it yet.
    a.put("published v1", "p");
    await cycles([a], 4);
    // A v1 write is journaled but not prepared when A rebinds.
    a.put("journaled v1", "j");
    remove(a, "s");
    a.store.replication.beginBaseline({ owner, declarations: [v2] });
    // A host that passes only its current bindings must still publish its
    // own older operations: they name a binding the journal retained.
    a.declarations([v2]);
    a.put("after v2", "n");
    await cycles([a], 4);
    expect(writtenVersions(a)).toEqual(expect.arrayContaining(["1", "2"]));
    await cycles([a, b], 8);
    const ids = ["s", "p", "j", "n"];
    // B (v1 only) applies every v1 operation, including the delete; the v2
    // write waits for B's upgrade.
    expect(view(b, ids)).toEqual({
      s: null,
      p: "published v1",
      j: "journaled v1",
      n: null,
    });
    // The host refreshes its trusted set with the retained history.
    a.declarations([v2, ...a.store.replication.declarationHistory()]);
    rebind(b, [v2]);
    await cycles([a, b], 8);
    const final = {
      s: null,
      p: "published v1",
      j: "journaled v1",
      n: "after v2",
    };
    expect(view(a, ids)).toEqual(final);
    expect(view(b, ids)).toEqual(final);
  }, 60_000);

  it("a new connector: the peer keeps replicating, then takes the connector's records when it adds it", async () => {
    const net = network();
    const a = transportDevice(net);
    const b = transportDevice(net);
    a.put("a1", "a");
    await cycles([a, b], 6);

    rebind(a, [v1, added]);
    a.store.registerConnection({
      instance: "conn2",
      sourceId: otherSource,
      method: "export",
      label: "Added",
    });
    putIn(a, "conn2", "n", "new source");
    a.put("a2", "a");
    await cycles([a, b], 8);
    // B does not know the connector or its declaration: its records wait,
    // and the rest of A's batch applies.
    expect(view(b, ["a"])).toEqual({ a: "a2" });
    expect(b.store.getRecord("conn2", "messages", "n")).toBeUndefined();
    expect(importDeclarationWaits(b)).toBe(0);
    b.put("b1", "b");
    await cycles([a, b], 6);
    expect(view(a, ["b"])).toEqual({ b: "b1" });

    rebind(b, [v1, added]);
    b.store.registerConnection({
      instance: "conn2",
      sourceId: otherSource,
      method: "export",
      label: "Added",
    });
    b.reopen();
    b.declarations([v1, added]);
    await cycles([a, b], 8);
    expect(view(b, ["n"], "conn2")).toEqual({ n: "new source" });
    expect(view(a, ["a", "b"])).toEqual(view(b, ["a", "b"]));
    expect(generation(a)).toBe(2);
    expect(generation(b)).toBe(2);
  }, 60_000);
});

describe("binding generations in the journal", () => {
  function journal() {
    const db = new Database(
      join(scratchDirectory("replica-rebinding"), "db.sqlite"),
    );
    const store = createReplicaRecordStore(db);
    return { db, store, replication: store.replication };
  }
  const schema = { type: "object", required: ["id"] };
  const withSchema = {
    sourceId,
    binding: { ...v2.binding, schemaDigest: replicaSchemaDigest(schema) },
  };

  it("records each generation, retains every binding, and repeats idempotently", () => {
    const { replication } = journal();
    replication.beginBaseline({ owner, declarations: [v1] });
    expect(replication.bindingGeneration()).toBe(1);
    replication.beginBaseline({ owner, declarations: [v1] });
    expect(replication.bindingGeneration()).toBe(1);
    replication.beginBaseline({ owner, declarations: [v2, added] });
    replication.beginBaseline({ owner, declarations: [added, v2] });
    expect(replication.bindingGeneration()).toBe(2);
    expect(
      replication.declarationHistory().map((e) => [e.sourceId, e.binding]),
    ).toEqual([
      [sourceId, v1.binding],
      // Within a generation, by source.
      [otherSource, added.binding],
      [sourceId, v2.binding],
    ]);
  });

  it("refuses an owner change and a changed shape without moving the generation", () => {
    const { replication } = journal();
    replication.beginBaseline({ owner, declarations: [v1] });
    replication.beginBaseline({ owner, declarations: [v2] });
    expect(() =>
      replication.beginBaseline({ owner: "other-owner", declarations: [v2] }),
    ).toThrow("replication owner is immutable");
    const reshaped = {
      sourceId,
      binding: { ...v2.binding, version: "3", primaryKey: ["text"] },
    };
    // Refused against a version the database no longer writes, too.
    expect(() =>
      replication.beginBaseline({ owner, declarations: [reshaped] }),
    ).toThrow(
      `replication rebinding refused: ${sourceId} stream messages changed its semantics or primary key`,
    );
    expect(replication.bindingGeneration()).toBe(2);
  });

  it("keeps a schema only when it matches its digest, and fills a missing one later", () => {
    const { replication } = journal();
    expect(() =>
      replication.beginBaseline({
        owner,
        declarations: [{ ...v1, schema: { type: "object" } }],
      }),
    ).toThrow("retained declaration schema does not match its digest");
    replication.beginBaseline({ owner, declarations: [v1] });
    // The upgrade's first boot does not know the schema yet; a later one does.
    replication.beginBaseline({ owner, declarations: [withSchema] });
    expect(replication.declarationHistory()).toEqual([v1, withSchema]);
    replication.beginBaseline({
      owner,
      declarations: [{ ...withSchema, schema }],
    });
    expect(replication.bindingGeneration()).toBe(2);
    expect(replication.declarationHistory()[1]).toEqual({
      ...withSchema,
      schema,
    });
    // A later boot that omits the schema keeps the retained one.
    replication.beginBaseline({ owner, declarations: [withSchema] });
    expect(replication.declarationHistory()[1]).toEqual({
      ...withSchema,
      schema,
    });
  });

  it("gives a database baselined before generations its first generation and history", () => {
    const { db, replication } = journal();
    replication.beginBaseline({ owner, declarations: [v1] });
    db.exec(
      "DROP TABLE pdpp_replica_binding_generations; DROP TABLE pdpp_replica_declaration_history",
    );
    db.prepare("UPDATE pdpp_replica_schema_version SET version = ?").run(
      REPLICA_MIGRATIONS.indexOf(REPLICA_BINDING_HISTORY_MIGRATION),
    );
    ensureReplicaSchema(db);
    expect(replication.bindingGeneration()).toBe(1);
    // The schema of a binding retained before history is unknown.
    expect(replication.declarationHistory()).toEqual([v1]);
    replication.beginBaseline({ owner, declarations: [v2] });
    expect(replication.bindingGeneration()).toBe(2);
  });
});
