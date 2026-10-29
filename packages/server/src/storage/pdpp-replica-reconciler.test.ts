/**
 * A8: incremental retained-history reconcile. Deterministic traces compare
 * a device that reconciles batch by batch (or page by page, across a
 * restart) against a control device that imports the same history in one
 * envelope, and bound the retained evidence each call loads.
 */
import Database from "better-sqlite3";
import { afterEach, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
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
const credential = "replica-secret";
const accepting: MergeContext["declarations"] = [
  { sourceId, binding, validateData: (data) => typeof data.id === "string" },
];

const directories: string[] = [];
const closers: (() => void)[] = [];
afterEach(() => {
  for (const close of closers.splice(0)) close();
  for (const path of directories.splice(0))
    rmSync(path, { recursive: true, force: true });
});

function device(options: { provisioned?: boolean } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "pdpp-reconciler-"));
  directories.push(directory);
  const path = join(directory, "db.sqlite");
  let db = new Database(path);
  let store = createReplicaRecordStore(db);
  if (options.provisioned ?? true) provision();
  store.replication.beginBaseline({
    owner: "owner",
    declarations: [{ sourceId, binding }],
  });
  let declarations = accepting;
  const open = () =>
    createReplicaReceiver({
      db,
      store,
      owner: "owner",
      authenticate: (c) => (c === credential ? "owner" : undefined),
      declarations: () => declarations,
    });
  let receiver = open();
  function provision() {
    store.registerConnection({
      instance: "conn_a",
      sourceId,
      method: "collector",
      label: "A",
    });
  }
  closers.push(() => {
    if (db.open) store.close();
  });
  return {
    get db() {
      return db;
    },
    get receiver() {
      return receiver;
    },
    get store() {
      return store;
    },
    provision,
    declare(entries: MergeContext["declarations"]) {
      declarations = entries;
    },
    send(operations: ReplicaOperation[]) {
      return receiver.import({
        credential,
        envelope: {
          format: "vana-pdpp-replica",
          version: 1,
          owner: "owner",
          batchId: "trace",
          operations,
        },
      });
    },
    /** Loaded retained operations since the last call. */
    loads: (() => {
      let seen = 0;
      return () => {
        const now = receiver.reconcileStats().operations;
        const delta = now - seen;
        seen = now;
        return delta;
      };
    })(),
    reopen() {
      store.close();
      db = new Database(path);
      store = createReplicaRecordStore(db);
      receiver = open();
    },
    /**
     * Live rows, completions and generations. Versions and tombstones depend
     * on delivery order (a row that was never live has no tombstone).
     */
    canonical() {
      return {
        rows: db
          .prepare(
            "SELECT instance, stream, record_key, data FROM pdpp_records WHERE deleted = 0 ORDER BY instance, stream, record_key",
          )
          .all(),
        completions: db
          .prepare(
            "SELECT instance, stream, generation, live_count FROM pdpp_stream_completion ORDER BY instance, stream",
          )
          .all(),
        binding: db
          .prepare(
            "SELECT instance, generation FROM pdpp_instance_binding ORDER BY instance",
          )
          .all(),
      };
    },
  };
}
type Device = ReturnType<typeof device>;

let counter = 100;
const revision = (operationId: string) => ({
  counter: ++counter,
  writerId: "remote",
  operationId,
});
const base = {
  owner: "owner",
  sourceId,
  connectionId: "conn_a",
  methodId: "collector",
};
const registration = (): ReplicaOperation => ({
  ...base,
  kind: "connection-register",
  generation: 1,
  revision: { counter: 1, writerId: "remote", operationId: "register" },
});
const upsert = (
  key: string,
  text: string,
  generation = 1,
): ReplicaOperation => ({
  ...base,
  kind: "upsert",
  generation,
  revision: revision(`u-${key}-${text}`),
  declaration: binding,
  recordKey: key,
  emittedAt: at,
  data: { id: key, text },
  blobs: [],
});
const remove = (key: string): ReplicaOperation => ({
  ...base,
  kind: "delete",
  generation: 1,
  revision: revision(`d-${key}`),
  declaration: binding,
  recordKey: key,
  emittedAt: at,
  deletedAt: at,
});
const text = (d: Device, key: string) =>
  (d.store.getRecord("conn_a", "messages", key)?.data as { text?: string })
    ?.text;
/** The same history in one envelope: the full-history result to match. */
function control(history: ReplicaOperation[]) {
  const d = device();
  d.send(history);
  d.receiver.retry({ credential });
  return d;
}

it("catch-up after a long offline period: each import loads the evidence of its own keys, not the history", () => {
  const d = device();
  const history: ReplicaOperation[] = [registration()];
  d.send([registration()]);
  const loads: number[] = [];
  for (let batch = 0; batch < 60; batch++) {
    const ops = Array.from({ length: 10 }, (_, i) =>
      upsert(`k${batch * 10 + i}`, `v${batch}`),
    );
    history.push(...ops);
    d.loads();
    d.send(ops);
    loads.push(d.loads());
  }
  // 10 keys of one variant each, plus the connection's lifecycle (the local
  // and the remote registration). A full reconcile loaded all 800 by the end.
  expect(Math.max(...loads)).toBeLessThanOrEqual(12);
  expect(loads.at(-1)).toBe(loads[0]);
  expect(d.canonical()).toEqual(control(history).canonical());
}, 60_000);

it("catch-up on keys that change in every batch costs each key its own history (documented limit)", () => {
  const d = device();
  const history: ReplicaOperation[] = [registration()];
  d.send([registration()]);
  for (let batch = 0; batch < 30; batch++) {
    const ops = Array.from({ length: 5 }, (_, i) =>
      upsert(`hot${i}`, `v${batch}`),
    );
    history.push(...ops);
    d.loads();
    d.send(ops);
    // Five keys with batch + 1 variants each, and the connection's
    // lifecycle: the local and the remote registration.
    expect(d.loads()).toBeLessThanOrEqual(5 * (batch + 1) + 2);
  }
  expect(text(d, "hot0")).toBe("v29");
  expect(d.canonical()).toEqual(control(history).canonical());
});

it("partial history: a later generation is held until its reset arrives, then replaces the old rows", () => {
  const d = device();
  const history = [registration(), upsert("a", "one")];
  d.send(history);
  const early = [upsert("a", "two", 2), upsert("b", "new", 2)];
  history.push(...early);
  expect(
    d
      .send(early)
      .pending.some((issue) => issue.reason === "missing_generation_reset"),
  ).toBe(true);
  expect([text(d, "a"), text(d, "b")]).toEqual(["one", undefined]);
  // The reset alone changes the connection's decision, which re-decides
  // every retained key of it.
  const reset: ReplicaOperation = {
    ...base,
    kind: "connection-reset",
    generation: 2,
    previousGeneration: 1,
    revision: revision("reset-2"),
  };
  history.push(reset);
  d.send([reset]);
  expect([text(d, "a"), text(d, "b")]).toEqual(["two", "new"]);
  expect(d.canonical()).toEqual(control(history).canonical());
});

it("partial history: an unprovisioned connection's records appear once the host maps it, even before a retry", () => {
  const d = device({ provisioned: false });
  const early = [registration(), upsert("a", "one")];
  expect(
    d
      .send(early)
      .pending.some((issue) => issue.reason === "missing_local_connection"),
  ).toBe(true);
  expect(text(d, "a")).toBeUndefined();
  d.provision();
  // A later import sees a mapping its last decision did not, and
  // re-decides the connection before its key.
  d.send([upsert("b", "two")]);
  expect([text(d, "a"), text(d, "b")]).toEqual(["one", "two"]);
});

it("deletions and tombstones: an older upsert never resurrects, a newer one does, and connection deletion withdraws every row", () => {
  const d = device();
  const history: ReplicaOperation[] = [];
  const step = (ops: ReplicaOperation[]) => {
    history.push(...ops);
    d.send(ops);
  };
  step([registration(), upsert("a", "one"), upsert("b", "two")]);
  const older = upsert("a", "older");
  step([remove("a")]);
  expect(text(d, "a")).toBeUndefined();
  // Delivered late: its revision is below the delete's.
  older.revision.counter = 1;
  step([older]);
  expect(text(d, "a")).toBeUndefined();
  step([upsert("a", "again")]);
  expect(text(d, "a")).toBe("again");
  expect(d.canonical()).toEqual(control(history).canonical());

  step([
    {
      ...base,
      kind: "connection-delete",
      generation: 2,
      revision: revision("connection-delete"),
    },
  ]);
  expect([text(d, "a"), text(d, "b")]).toEqual([undefined, undefined]);
  step([upsert("c", "after")]);
  expect(text(d, "c")).toBeUndefined();
  expect(d.canonical()).toEqual(control(history).canonical());
});

it("deletions and tombstones: a generation reset withdraws the old generation's rows", () => {
  const d = device();
  const history = [registration(), upsert("a", "one"), upsert("b", "two")];
  d.send(history);
  const reset: ReplicaOperation[] = [
    {
      ...base,
      kind: "connection-reset",
      generation: 2,
      previousGeneration: 1,
      revision: revision("reset-2"),
    },
    upsert("b", "two-again", 2),
  ];
  history.push(...reset);
  d.send(reset);
  expect([text(d, "a"), text(d, "b")]).toEqual([undefined, "two-again"]);
  expect(d.canonical()).toEqual(control(history).canonical());
});

it("restart mid-reconciliation: a paged pass survives a reopen and converges to the full pass", () => {
  const d = device();
  const history = [
    registration(),
    ...Array.from({ length: 120 }, (_, i) => upsert(`k${i}`, `v${i}`)),
  ];
  d.send(history);
  const reference = control(history);
  // A validator change: odd keys become invalid and must be withdrawn.
  const strict: MergeContext["declarations"] = [
    {
      sourceId,
      binding,
      validateData: (data) => Number(String(data.id).slice(1)) % 2 === 0,
    },
  ];
  reference.declare(strict);
  reference.receiver.retry({ credential });
  d.declare(strict);
  const page = { operations: 10, bytes: 1024 * 1024 };
  d.loads();
  const first = d.receiver.reconcileStep({ credential, page, restart: true });
  expect(first.complete).toBe(false);
  expect(d.loads()).toBeLessThanOrEqual(page.operations + 2);
  expect(d.receiver.reconcileQueued()).toBe(true);

  d.reopen();
  d.declare(strict);
  // An import during the open pass finishes its own keys only.
  const late = upsert("k200", "late");
  history.push(late);
  reference.send([late]);
  d.send([late]);
  expect(text(d, "k200")).toBe("late");
  expect(d.receiver.reconcileQueued()).toBe(true);

  let pages = 1;
  for (let done = false; !done; pages++) {
    expect(pages, "the pass must finish").toBeLessThan(200);
    d.loads();
    done = d.receiver.reconcileStep({ credential, page }).complete;
    // One entry may overrun the page: a key's variants and its lifecycle.
    expect(d.loads()).toBeLessThanOrEqual(page.operations + 2);
  }
  expect(pages).toBeGreaterThan(10);
  expect(text(d, "k1")).toBeUndefined();
  expect(text(d, "k2")).toBe("v2");
  expect(d.canonical()).toEqual(reference.canonical());
});

it("an equivocated operation id withdraws its connection through every key, and the plan names it again on a duplicate", () => {
  const d = device();
  const first = upsert("a", "one");
  d.send([registration(), first, upsert("b", "two")]);
  const variant = { ...first, data: { id: "a", text: "forged" } };
  const plan = d.send([variant]);
  expect(
    plan.conflicts.some(
      (issue) => issue.reason === "operation_id_equivocation",
    ),
  ).toBe(true);
  expect([text(d, "a"), text(d, "b")]).toEqual([undefined, undefined]);
  d.reopen();
  expect(
    d
      .send([first])
      .conflicts.some((issue) => issue.reason === "operation_id_equivocation"),
  ).toBe(true);
});

it("a database whose retained history predates the reconciler state is reconciled once, by the next call", () => {
  const d = device();
  d.send([registration(), upsert("k1", "one"), upsert("k2", "two")]);
  // An earlier build: retained rows, no reconciler state.
  for (const table of [
    "pdpp_replica_reconcile_state",
    "pdpp_replica_reconcile_bindings",
    "pdpp_replica_reconcile_equivocations",
    "pdpp_replica_reconcile_connections",
    "pdpp_replica_reconcile_blockers",
    "pdpp_replica_reconcile_queue",
  ])
    d.db.exec(`DROP TABLE ${table}`);
  d.reopen();
  // Odd keys become invalid: only a reconcile of every key withdraws k1.
  d.declare([
    {
      sourceId,
      binding,
      validateData: (data) => Number(String(data.id).slice(1)) % 2 === 0,
    },
  ]);
  expect(d.receiver.reconcileQueued()).toBe(true);
  d.receiver.reconcileStep({
    credential,
    page: { operations: 1_000, bytes: 1024 * 1024 },
  });
  expect(d.receiver.reconcileQueued()).toBe(false);
  expect([text(d, "k1"), text(d, "k2")]).toEqual([undefined, "two"]);
});
