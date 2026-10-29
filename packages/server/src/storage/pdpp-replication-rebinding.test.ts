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
import { rotateReplicaWriterIdentity } from "./pdpp-replica-writer-identity.js";

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

function putIn(
  d: TransportDevice,
  instance: string,
  id: string,
  text: string,
  semantics: "mutable_state" | "append_only" = "mutable_state",
) {
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
    () => semantics,
    () => ["id"],
    { method: "export", generation: 1 },
  );
}

describe("two-writer rebinding traces", () => {
  it("upgrade on one device first: the other applies the new version by key and both converge", async () => {
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

    // A trusts both versions, so it takes B's v1 write. B does not retain v2
    // but retains its shape, so it applies A's v2 operations, validated by
    // key, without a wait and without stopping A's chain.
    const mixed = { a: "a2", b: "b2", c: "c1", x: null };
    expect(view(a, ["a", "b", "c", "x"])).toEqual(mixed);
    expect(view(b, ["a", "b", "c", "x"])).toEqual(mixed);
    expect(reconcileWait(b)).toBeNull();
    expect(importDeclarationWaits(b)).toBe(0);

    rebind(b, [v2]);
    a.put("b3", "b");
    b.put("c2", "c");
    await cycles([a, b], 8);
    const final = { a: "a2", b: "b3", c: "c2", x: null };
    expect(view(a, ["a", "b", "c", "x"])).toEqual(final);
    expect(view(b, ["a", "b", "c", "x"])).toEqual(final);
    expect(reconcileWait(b)).toBeNull();
    expect(writtenVersions(b)).toContain("1");
    expect(writtenVersions(b).at(-1)).toBe("2");
  }, 60_000);

  it("a device joins with only the new version: it takes the peer's older-version history", async () => {
    const net = network();
    const a = transportDevice(net);
    // v1 history: writes, an overwrite and a delete.
    a.put("old", "a");
    a.put("kept v1", "k");
    a.put("x1", "x");
    a.put("y1", "y");
    remove(a, "y");
    a.put("o1", "o");
    a.put("o2", "o");
    await cycles([a], 4);
    // v2 writes on top: an overwrite and a delete of v1 records, a new one.
    rebind(a, [v2]);
    a.put("new", "a");
    remove(a, "x");
    a.put("n2", "n");
    await cycles([a], 4);
    expect(writtenVersions(a)).toEqual(expect.arrayContaining(["1", "2"]));

    const b = transportDevice(net, { declarations: [v2] });
    await cycles([a, b], 10);
    const ids = ["a", "k", "x", "y", "o", "n"];
    const all = {
      a: "new",
      k: "kept v1",
      x: null,
      y: null,
      o: "o2",
      n: "n2",
    };
    expect(view(a, ids)).toEqual(all);
    expect(view(b, ids)).toEqual(all);
    expect(reconcileWait(b)).toBeNull();
    expect(importDeclarationWaits(b)).toBe(0);
    // B trusts v1 only through A's operations; its own journal never retains it.
    expect(b.store.replication.declarationHistory()).toEqual([v2]);

    // B writes over a v1 record and deletes another; A takes both.
    b.put("from B", "k");
    remove(b, "o");
    await cycles([a, b], 8);
    const after = { ...all, k: "from B", o: null };
    expect(view(a, ids)).toEqual(after);
    expect(view(b, ids)).toEqual(after);
    expect(writtenVersions(b)).toEqual(["2", "2"]);
  }, 60_000);

  it("an incompatible shape of a retained stream is refused on both sides with an owner wait", async () => {
    const net = network();
    const reshaped = {
      sourceId,
      binding: {
        ...binding,
        digest: `sha256:${"9".repeat(64)}`,
        semantics: "append_only" as const,
      },
    };
    const a = transportDevice(net, { declarations: [reshaped] });
    const b = transportDevice(net, { declarations: [v2] });
    putIn(a, a.instance, "a", "a1", "append_only");
    b.put("b1", "b");
    await cycles([a, b], 8);
    // Neither applies the other's records, and each reports the refusal as
    // a wait only the owner can resolve, not a declaration wait.
    expect(view(b, ["a", "b"])).toEqual({ a: null, b: "b1" });
    expect(view(a, ["a", "b"])).toEqual({ a: "a1", b: null });
    const refused = `owner:declaration:${sourceId}:messages`;
    expect(reconcileWait(b)).toBe(refused);
    expect(reconcileWait(a)).toBe(refused);
    // The writer's chain is not stopped: a later batch still imports.
    putIn(a, a.instance, "c", "c1", "append_only");
    await cycles([a, b], 6);
    expect(importDeclarationWaits(b)).toBe(0);
    expect(view(b, ["c"])).toEqual({ c: null });
    // The refusal is durable: a rebinding to that shape is refused too.
    expect(() =>
      b.store.replication.beginBaseline({ owner, declarations: [reshaped] }),
    ).toThrow(/changed its semantics or primary key/);
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
    // B (v1 only) applies every v1 operation, including the delete, and the
    // v2 write by key.
    expect(view(b, ids)).toEqual({
      s: null,
      p: "published v1",
      j: "journaled v1",
      n: "after v2",
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
    // B does not know the connector or its declaration: its records wait on
    // reconcile, and the rest of A's batch applies.
    expect(view(b, ["a"])).toEqual({ a: "a2" });
    expect(b.store.getRecord("conn2", "messages", "n")).toBeUndefined();
    expect(reconcileWait(b)).toBe("mapping:conn2");
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

describe("writer rotation after a rebinding", () => {
  const reshaped = {
    sourceId,
    binding: {
      ...binding,
      digest: `sha256:${"9".repeat(64)}`,
      semantics: "append_only" as const,
    },
  };
  const notes = {
    sourceId,
    binding: {
      ...binding,
      digest: `sha256:${"8".repeat(64)}`,
      stream: "notes",
    },
  };

  it("a v1 device that applied a peer's v2 writes still publishes after its writer rotates", async () => {
    const net = network();
    const a = transportDevice(net);
    const b = transportDevice(net);
    a.put("x1", "x");
    await cycles([a, b], 6);
    rebind(a, [v2]);
    a.put("x2", "x");
    await cycles([a, b], 6);
    expect(view(b, ["x"])).toEqual({ x: "x2" });

    // B's canonical x is now explained by A's v2 operation. B never retains
    // v2, so its new baseline must still be publishable.
    rotateReplicaWriterIdentity(b.db);
    b.put("y1", "y");
    await cycles([a, b], 8);
    expect(view(a, ["x", "y"])).toEqual({ x: "x2", y: "y1" });
    const c = transportDevice(net);
    await cycles([a, b, c], 8);
    expect(view(c, ["x", "y"])).toEqual({ x: "x2", y: "y1" });
    expect(generation(b)).toBe(1);
  }, 60_000);

  it("a rotated writer never reissues a pending operation's declaration", async () => {
    const net = network();
    const a = transportDevice(net);
    const b = transportDevice(net);
    const c = transportDevice(net, { declarations: [reshaped] });
    a.put("same", "x");
    await cycles([a, b], 6);
    // C, with another shape of the stream, writes the same data at x later,
    // at a higher revision. B keeps it pending as incompatible.
    for (const id of ["c1", "c2", "c3"])
      putIn(c, c.instance, id, id, "append_only");
    putIn(c, c.instance, "x", "same", "append_only");
    await cycles([c, b], 8);
    expect(reconcileWait(b)).toBe(`owner:declaration:${sourceId}:messages`);

    rotateReplicaWriterIdentity(b.db);
    b.put("y1", "y");
    await cycles([a, b], 8);
    expect(view(a, ["x", "y"])).toEqual({ x: "same", y: "y1" });
    const d = transportDevice(net);
    await cycles([b, d], 8);
    expect(view(d, ["x", "y"])).toEqual({ x: "same", y: "y1" });
  }, 60_000);

  it("a retired stream keeps its rows and tombstones through a writer rotation", async () => {
    const net = network();
    const a = transportDevice(net, { declarations: [v1, notes] });
    const b = transportDevice(net, { declarations: [v1, notes] });
    a.put("k1", "k");
    a.put("gone", "g");
    await cycles([a, b], 6);
    expect(view(b, ["k", "g"])).toEqual({ k: "k1", g: "gone" });

    // The delete is never published by the old writer: only the new
    // baseline can carry it.
    remove(a, "g");
    rebind(a, [notes]);
    rotateReplicaWriterIdentity(a.db);
    a.reopen();
    a.declarations([notes, ...a.store.replication.declarationHistory()]);
    await cycles([a, b], 10);
    expect(view(b, ["k", "g"])).toEqual({ k: "k1", g: null });
    // A later boot and rotation still capture the retired stream.
    rotateReplicaWriterIdentity(a.db);
    a.reopen();
    const c = transportDevice(net, { declarations: [v1, notes] });
    await cycles([a, c], 10);
    expect(view(c, ["k", "g"])).toEqual({ k: "k1", g: null });
    expect(view(a, ["k", "g"])).toEqual({ k: "k1", g: null });
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
