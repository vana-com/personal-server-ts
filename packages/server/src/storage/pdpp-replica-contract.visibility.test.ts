/**
 * Contract D: shared visibility, cursor position and integrity epochs (cases 47-64).
 *
 * Red-first. The write side (integrity epoch, durable binding conflict, eligibility
 * marking) is S3; the read side (cursor expiry and filtering) is the #438 lane.
 * Titles carry the brief finding they pin: e (#428 F1), h (#426), j (155a82f0), k (#440 P1).
 *
 * Retained-import cases run on every adapter in `adapterFactories`. A surface an
 * adapter lacks is asserted absent (`assertSurfaceTruth`), never skipped. Cases that
 * need native ingest, raw durable rows, a mid-read race or process loss use the
 * Node store through `nodeLocal` and have a Lite twin that asserts the absent
 * surfaces and still checks the point read.
 */
import Database from "better-sqlite3";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  CursorExpiredError,
  InvalidCursorError,
  InvalidCursorSyntaxError,
  encodeCursor,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import type {
  DeclarationBinding,
  RecordOperation,
  ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  binding,
  identity,
  mutableVectors,
  registration,
  upsert,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import {
  planReplicaMerge,
  type MergeContext,
} from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import { createLiteCanonicalStore } from "../../../lite/src/canonical-store.js";
import {
  createFakeCanonicalPersistence,
  fakeCanonicalDisk,
} from "../../../lite/src/test-support/canonical-persistence.js";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import {
  CrashController,
  adapterFactories,
  binding as retainedBinding,
  cleanupHarness,
  credential,
  crashableDatabase,
  cycles,
  network,
  scratchDirectory,
  transportDevice,
  type CanonicalAdapter,
  type Surface,
} from "./pdpp-replica-contract.test-utils.js";

afterEach(cleanupHarness);
const closers: (() => void)[] = [];
afterEach(() => {
  for (const close of closers.splice(0).reverse()) close();
});

// ------------------------------------------------------------------ fixtures

const STREAM = binding.stream;
const C = identity.connectionId;
const Y = "connection-y";
const appendDecl: DeclarationBinding = { ...binding, semantics: "append_only" };
const profilesDecl: DeclarationBinding = { ...binding, stream: "profiles" };
const decls = (
  ...bindings: DeclarationBinding[]
): MergeContext["declarations"] =>
  bindings.map((entry) => ({
    sourceId: identity.sourceId,
    binding: entry,
    validateData: (data) => typeof data.id === "string",
  }));
const ctx = (...bindings: DeclarationBinding[]): MergeContext => ({
  owner: identity.owner,
  declarations: decls(...bindings),
});
const mapping = (connectionId: string) => ({
  connectionId,
  sourceId: identity.sourceId,
  methodId: identity.methodId,
});

type RecOptions = {
  text?: string;
  writer?: string;
  declaration?: DeclarationBinding;
  connectionId?: string;
};
function rec(
  key: string,
  operationId: string,
  counter: number,
  options: RecOptions = {},
): RecordOperation & { kind: "upsert" } {
  const text = options.text ?? key;
  const base = upsert(operationId, counter, text, options.writer);
  return {
    ...base,
    connectionId: options.connectionId ?? base.connectionId,
    declaration: options.declaration ?? base.declaration,
    recordKey: key,
    data: { id: key, text },
  };
}
const reg = (connectionId = C): ReplicaOperation => ({
  ...registration,
  connectionId,
  revision: {
    counter: 1,
    writerId: "device-a",
    operationId: `register-${connectionId}`,
  },
});
/** Append-only original, conflict and batch builders. */
const ao = (
  key: string,
  operationId: string,
  counter: number,
  text = `original-${key}`,
  connectionId = C,
) =>
  rec(key, operationId, counter, {
    text,
    declaration: appendDecl,
    connectionId,
  });
const originals = (keys: string[], connectionId = C) =>
  keys.map((key, i) =>
    ao(key, `${key}-orig-${connectionId}`, 2 + i, undefined, connectionId),
  );
const conflict = (key: string, connectionId = C) =>
  ao(
    key,
    `${key}-conflict-${connectionId}`,
    100,
    `conflicting-${key}`,
    connectionId,
  );
const resetOp = (generation: number, counter = 200): ReplicaOperation => ({
  ...identity,
  kind: "connection-reset",
  generation,
  previousGeneration: generation - 1,
  revision: {
    counter,
    writerId: "device-a",
    operationId: `reset-${generation}`,
  },
});
const deleteOp: ReplicaOperation = {
  ...identity,
  kind: "connection-delete",
  revision: {
    counter: 300,
    writerId: "device-a",
    operationId: "delete-connection",
  },
};

// ---------------------------------------------------------------- assertions

const isRefused = (error: unknown) =>
  error instanceof CursorExpiredError ||
  error instanceof InvalidCursorError ||
  error instanceof InvalidCursorSyntaxError;
function expectRefused(run: () => unknown) {
  let thrown: unknown;
  let returned: unknown;
  try {
    returned = run();
  } catch (error) {
    thrown = error;
  }
  expect(
    isRefused(thrown),
    `expected CursorExpired/InvalidCursor, got ${thrown ? String(thrown) : JSON.stringify(returned)}`,
  ).toBe(true);
}
const keysOf = (page: { data: unknown[] }) =>
  page.data.map((row) => (row as { recordKey: string }).recordKey);

type EpochReader = { replicaIntegrityEpoch?: (key: string) => number };
function epochOf(store: object, connection: string): number {
  const read = (store as EpochReader).replicaIntegrityEpoch;
  if (typeof read !== "function")
    throw new Error(
      "store.replicaIntegrityEpoch is missing (CONTRACT-API section 3)",
    );
  return read.call(store, connection);
}
function epochBase(store: object, connection: string): number {
  try {
    return epochOf(store, connection);
  } catch {
    return 0;
  }
}

const SURFACE_METHOD: Record<
  Exclude<Surface, "point">,
  keyof CanonicalAdapter
> = {
  list: "list",
  changes: "changes",
  blob: "blob",
  completion: "completion",
  integrityEpoch: "integrityEpoch",
  bindingConflict: "bindingConflict",
};
/** A declared-unsupported surface has no method; a supported one has. Never skips. */
function assertSurfaceTruth(adapter: CanonicalAdapter) {
  expect(adapter.surfaces.point).toBe("supported");
  for (const [surface, method] of Object.entries(SURFACE_METHOD)) {
    const supported = adapter.surfaces[surface as Surface] === "supported";
    expect(
      typeof adapter[method] === "function",
      `${adapter.name} ${surface}`,
    ).toBe(supported);
  }
}
const visible = async (
  adapter: CanonicalAdapter,
  key: string,
  connection = C,
) => {
  const row = await adapter.point(connection, STREAM, key);
  return row !== undefined && !row.deleted;
};
const visibleKeys = async (
  adapter: CanonicalAdapter,
  keys: string[],
  connection = C,
) => {
  const out: string[] = [];
  for (const key of keys)
    if (await visible(adapter, key, connection)) out.push(key);
  return out;
};

let batchCounter = 0;
const send = (adapter: CanonicalAdapter, ops: ReplicaOperation[]) =>
  adapter.send(ops, `visibility-${++batchCounter}`);
const open = (
  factory: (typeof adapterFactories)[string],
  declaration: DeclarationBinding = binding,
  mapped = true,
) => factory(ctx(declaration), mapped ? mapping(C) : undefined);
async function openTwo(
  factory: (typeof adapterFactories)[string],
  declaration: DeclarationBinding,
) {
  const adapter = await open(factory, declaration);
  await adapter.provision(Y, {
    sourceId: identity.sourceId,
    methodId: identity.methodId,
  });
  return adapter;
}
const epochNow = (adapter: CanonicalAdapter, connection = C) =>
  adapter.integrityEpoch!(connection);
function epochBaseline(adapter: CanonicalAdapter, connection = C): number {
  return adapter.surfaces.integrityEpoch === "supported"
    ? (() => {
        try {
          return adapter.integrityEpoch!(connection);
        } catch {
          return 0;
        }
      })()
    : 0;
}

// ------------------------------------------------------------ Node local store

/** Wraps a handle so `onSelect` runs right after any SELECT ... .all() returns. */
function afterSelectDatabase(
  real: Database.Database,
  onSelect: (sql: string) => void,
): Database.Database {
  return new Proxy(real, {
    get(target, property) {
      if (property === "prepare")
        return (sql: string) =>
          new Proxy(target.prepare(sql), {
            get(statement, name) {
              const value = Reflect.get(statement, name, statement);
              if (typeof value !== "function") return value;
              if (name === "all")
                return (...args: unknown[]) => {
                  const rows = (value as (...a: unknown[]) => unknown).apply(
                    statement,
                    args,
                  );
                  onSelect(sql);
                  return rows;
                };
              // A streamed read fires once its first row is selected.
              if (name === "iterate")
                return function* (...args: unknown[]) {
                  let fired = false;
                  for (const row of (
                    value as (...a: unknown[]) => Iterable<unknown>
                  ).apply(statement, args)) {
                    if (!fired) {
                      fired = true;
                      onSelect(sql);
                    }
                    yield row;
                  }
                  if (!fired) onSelect(sql);
                };
              return value.bind(statement);
            },
          });
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

interface LocalOptions {
  declarations?: MergeContext["declarations"];
  connections?: string[];
  crash?: CrashController;
  hook?: (sql: string) => void;
}
type LocalStore = ReturnType<typeof createReplicaRecordStore>;
type Semantics = "append_only" | "mutable_state";
const at = "2026-10-20T00:00:00.000Z";

/** Receiver + record store on one SQLite file, like the R/L tests, with reopen and crash hooks. */
function nodeLocal(options: LocalOptions = {}) {
  const declarations = options.declarations ?? decls(binding);
  const path = join(scratchDirectory("visibility"), "db.sqlite");
  const wrap = (handle: Database.Database) =>
    options.crash
      ? crashableDatabase(handle, options.crash)
      : options.hook
        ? afterSelectDatabase(handle, options.hook)
        : handle;
  let real = new Database(path);
  let db = wrap(real);
  let store: LocalStore = createReplicaRecordStore(db);
  for (const connection of options.connections ?? [C])
    store.registerConnection({
      instance: connection,
      sourceId: identity.sourceId,
      method: identity.methodId,
      label: connection,
    });
  store.replication.beginBaseline({
    owner: identity.owner,
    declarations: declarations.map(({ sourceId, binding: entry }) => ({
      sourceId,
      binding: entry,
    })),
  });
  closers.push(() => {
    if (real.open) real.close();
  });
  const receiverFor = (handle: Database.Database, target: LocalStore) =>
    createReplicaReceiver({
      db: handle,
      store: target,
      owner: identity.owner,
      authenticate: (c) => (c === credential ? identity.owner : undefined),
      declarations: () => declarations,
    });
  let counter = 0;
  const envelope = (operations: ReplicaOperation[], batchId: string) => ({
    format: "vana-pdpp-replica",
    version: 1,
    owner: identity.owner,
    batchId,
    operations,
  });
  const device = {
    path,
    get db() {
      return db;
    },
    get store() {
      return store;
    },
    receiver: () => receiverFor(db, store),
    send(
      operations: ReplicaOperation[],
      blobs?: { blobId: string; bytes: Uint8Array }[],
    ) {
      return receiverFor(db, store).import({
        credential,
        envelope: envelope(operations, `local-${++counter}`),
        ...(blobs && { blobs }),
      });
    },
    retry: () => receiverFor(db, store).retry({ credential }),
    ingest(
      connection: string,
      key: string,
      text: string,
      semantics: Semantics = "append_only",
      extra: Record<string, unknown> = {},
    ) {
      return store.ingestBatch(
        [
          {
            instance: connection,
            stream: STREAM,
            key,
            data: { id: key, text, ...extra },
            emitted_at: at,
          },
        ],
        () => semantics,
        () => ["id"],
        { method: identity.methodId, generation: 1 },
      );
    },
    ingestAll(
      keys: string[],
      semantics: Semantics = "append_only",
      connection = C,
    ) {
      for (const key of keys)
        device.ingest(connection, key, `original-${key}`, semantics);
    },
    list(
      cursor?: string,
      limit = 1,
      instanceIds = [C],
      order: "asc" | "desc" = "asc",
      stream = STREAM,
      fields?: string[],
    ) {
      return store.listRecords(stream, {
        instanceIds,
        limit,
        order,
        cursor,
        fields,
      });
    },
    changes(
      options: {
        cursor?: string;
        changesSince?: string;
        limit?: number;
        instanceIds?: string[];
        fields?: string[];
      } = {},
    ) {
      return store.changesSince(STREAM, {
        instanceIds: options.instanceIds ?? [C],
        limit: options.limit ?? 100,
        cursor: options.cursor,
        changesSince: options.changesSince,
        fields: options.fields,
      });
    },
    operations(): ReplicaOperation[] {
      return [
        ...store.replication.readBaselinePage({ limit: 1000 }).operations,
        ...store.replication.readTailPage({ limit: 1000 }).operations,
      ];
    },
    retained(): string[] {
      return (
        db
          .prepare(
            "SELECT operation_json FROM pdpp_replica_operations UNION SELECT operation_json FROM pdpp_replica_received",
          )
          .all() as { operation_json: string }[]
      ).map((row) => row.operation_json);
    },
    historyRows(connection: string, key: string) {
      return db
        .prepare(
          "SELECT version, deleted, data FROM pdpp_record_changes WHERE instance=? AND stream=? AND record_key=? ORDER BY version",
        )
        .all(connection, STREAM, key) as {
        version: number;
        deleted: number;
        data: string | null;
      }[];
    },
    quarantinedKeys: (connection = C) =>
      (
        db
          .prepare(
            "SELECT record_key FROM pdpp_replica_quarantined_keys WHERE instance=? ORDER BY record_key",
          )
          .all(connection) as { record_key: string }[]
      ).map((row) => row.record_key),
    epoch: (connection = C) => epochOf(store, connection),
    reopen() {
      if (real.open) real.close();
      real = new Database(path);
      db = wrap(real);
      store = createReplicaRecordStore(db);
    },
    /** Process loss: drop every component, reopen without injection. */
    crashReopen() {
      if (real.open) real.close();
      options.crash?.disarm();
      real = new Database(path);
      db = real;
      store = createReplicaRecordStore(db);
    },
    /** A second connection to the same file (a concurrent writer). */
    second() {
      const handle = new Database(path);
      const other = createReplicaRecordStore(handle);
      closers.push(() => {
        if (handle.open) handle.close();
      });
      return {
        store: other,
        send: (operations: ReplicaOperation[]) =>
          receiverFor(handle, other).import({
            credential,
            envelope: envelope(operations, `second-${++counter}`),
          }),
      };
    },
  };
  return device;
}
type Local = ReturnType<typeof nodeLocal>;

/** Surfaces of one stream as the owner/app read layer exposes them. */
function surfacesOf(d: Local, connection = C) {
  return {
    point: (key: string) => d.store.getRecord(connection, STREAM, key)?.data,
    list: d.list(undefined, 100, [connection]).data.map((row) => row.recordKey),
    changes: d
      .changes({ instanceIds: [connection] })
      .data.map((row) => row.recordKey),
    completions: d.store
      .listStreamCompletions(connection)
      .map((row) => row.stream),
  };
}

// ============================================================================
// 47. Identity conflict outside the queried partition / finding h (#426)
// ============================================================================

for (const [name, factory] of Object.entries(adapterFactories))
  describe(`47 ${name}`, () => {
    for (const order of ["forward", "reverse"] as const)
      it(`47a [${name}] one operation ID on two keys hides both and the connection, ${order}, across reopen`, async () => {
        const a = await openTwo(factory, binding);
        assertSurfaceTruth(a);
        await send(a, [reg(Y), rec("y1", "y-op", 2, { connectionId: Y })]);
        await send(a, [registration, rec("k3", "k3-op", 2)]);
        expect(await visible(a, "k3")).toBe(true);
        const one = rec("k1", "collision", 3);
        const two = rec("k2", "collision", 3);
        const [first, second] = order === "forward" ? [one, two] : [two, one];
        const before = epochBaseline(a);
        const beforeY = epochBaseline(a, Y);
        await send(a, [first]);
        a.reopen();
        await send(a, [second]);
        for (const restart of [false, true]) {
          if (restart) a.reopen();
          expect(
            await visibleKeys(a, ["k1", "k2", "k3"]),
            "neither competing value nor siblings leak",
          ).toEqual([]);
          expect(
            await visible(a, "y1", Y),
            "unrelated connection stays eligible",
          ).toBe(true);
          if (a.list) {
            expect(keysOf(await a.list(C, STREAM))).toEqual([]);
            expect(keysOf(await a.list(Y, STREAM))).toEqual(["y1"]);
          } else expect(a.surfaces.list).toBe("unsupported");
          if (a.changes) {
            const page = await a.changes(C, STREAM);
            expect(page.data).toEqual([]);
          } else expect(a.surfaces.changes).toBe("unsupported");
        }
        if (a.integrityEpoch) {
          expect(
            epochNow(a),
            "write side: connection fence bumps the epoch",
          ).toBeGreaterThan(before);
          expect(
            epochNow(a, Y),
            "unrelated connection epoch is untouched",
          ).toBe(beforeY);
        } else expect(a.surfaces.integrityEpoch).toBe("unsupported");
      });
  });

describe("47h finding h (#426): equivocation must not erase source-binding conflict evidence", () => {
  const sourceB = "https://example.test/other-source";
  const regB: ReplicaOperation = {
    ...registration,
    sourceId: sourceB,
    revision: { counter: 1, writerId: "device-b", operationId: "register-b" },
  };
  const regBPrime: ReplicaOperation = {
    ...regB,
    revision: { counter: 9, writerId: "device-b", operationId: "register-b" },
  };
  const upA = rec("k", "a-op", 2);
  const unrelated = [
    reg("connection-d"),
    rec("d1", "d-op", 2, { connectionId: "connection-d" }),
  ];
  const orders: Record<string, ReplicaOperation[][]> = {
    "A then B then b-prime": [[registration, upA], [regB], [regBPrime]],
    "b-prime then B then A": [[regBPrime], [regB], [registration, upA]],
  };
  for (const [name, factory] of Object.entries(adapterFactories))
    for (const [label, batches] of Object.entries(orders)) {
      const setup = async () => {
        const a = await open(factory, binding, false);
        for (const batch of batches) {
          await send(a, batch);
          a.reopen();
        }
        await a.provision("connection-d", {
          sourceId: identity.sourceId,
          methodId: identity.methodId,
        });
        // The local mapping for C is established after the conflicting evidence was retained.
        await a
          .provision(C, {
            sourceId: identity.sourceId,
            methodId: identity.methodId,
          })
          .catch(() => undefined);
        return a;
      };
      it(`47h-1 [${name}] ${label}: a retained mapping disagreement is connection-scoped, not a global throw`, async () => {
        const a = await setup();
        assertSurfaceTruth(a);
        await send(a, unrelated);
        await a.retry();
        expect(
          await visible(a, "d1", "connection-d"),
          "unrelated connection imports and retries",
        ).toBe(true);
        expect(await visible(a, "k")).toBe(false);
      });
      it(`47h-2 [${name}] ${label}: connection stays hidden and the binding conflict stays true`, async () => {
        const a = await setup();
        assertSurfaceTruth(a);
        await a.retry().catch(() => undefined);
        for (const restart of [false, true, true]) {
          if (restart) {
            a.reopen();
            await a.retry().catch(() => undefined);
          }
          expect(
            await visible(a, "k"),
            "source A's value must not become visible",
          ).toBe(false);
          if (a.list) expect(keysOf(await a.list(C, STREAM))).toEqual([]);
          else expect(a.surfaces.list).toBe("unsupported");
          if (a.bindingConflict)
            expect(a.bindingConflict(C), "durable fact, never erased").toBe(
              true,
            );
          else expect(a.surfaces.bindingConflict).toBe("unsupported");
        }
      });
    }
});

// ============================================================================
// 48. Mutable ordering is policy-defined (full planner is the oracle)
// ============================================================================

for (const [name, factory] of Object.entries(adapterFactories))
  describe(`48 ${name}`, () => {
    const permutations: Record<string, number[]> = {
      forward: [0, 1, 2, 3],
      reverse: [3, 2, 1, 0],
      interleaved: [2, 0, 3, 1],
    };
    for (const [label, order] of Object.entries(permutations))
      it(`48 [${name}] winner equals the full planner at every prefix, ${label}, restart between batches`, async () => {
        const a = await open(factory, binding);
        assertSurfaceTruth(a);
        await send(a, [registration]);
        const sent: ReplicaOperation[] = [registration];
        const expectWinner = async () => {
          const plan = planReplicaMerge(ctx(binding), sent);
          const winner = plan.records.find(
            (r) => r.identity.recordKey === "same-key",
          )?.winner;
          const row = await a.point(C, STREAM, "same-key");
          if (winner?.kind === "upsert") {
            expect(row?.deleted ?? false).toBe(false);
            expect((row?.data as { text?: string } | undefined)?.text).toBe(
              winner.data.text,
            );
          } else expect(row === undefined || row.deleted).toBe(true);
        };
        for (const index of order) {
          const op = mutableVectors[index];
          sent.push(op);
          await send(a, [op]);
          a.reopen();
          await expectWinner();
        }
        // Replay and reverse replay change nothing: receipt time and cursor are not policy.
        await send(a, [...mutableVectors].reverse());
        await expectWinner();
        expect((await a.point(C, STREAM, "same-key"))?.data).toMatchObject({
          text: "resurrect",
        });
      });
  });

// ============================================================================
// 49. Lifecycle gaps preserve the correct prior projection
// ============================================================================

for (const [name, factory] of Object.entries(adapterFactories))
  it(`49 [${name}] generation 3 without reset 2 keeps generation 1 visible; closing the chain swaps them`, async () => {
    const a = await open(factory, binding);
    assertSurfaceTruth(a);
    await send(a, [registration, rec("same-key", "g1", 2, { text: "gen1" })]);
    const g3 = { ...rec("same-key", "g3", 5, { text: "gen3" }), generation: 3 };
    await send(a, [resetOp(3, 4), g3]);
    for (const restart of [false, true]) {
      if (restart) a.reopen();
      expect((await a.point(C, STREAM, "same-key"))?.data).toMatchObject({
        text: "gen1",
      });
      if (a.list) expect(keysOf(await a.list(C, STREAM))).toEqual(["same-key"]);
      else expect(a.surfaces.list).toBe("unsupported");
    }
    await send(a, [resetOp(2, 3)]);
    for (const restart of [false, true]) {
      if (restart) a.reopen();
      const row = await a.point(C, STREAM, "same-key");
      expect(row?.deleted ?? false).toBe(false);
      expect(row?.data).toMatchObject({ text: "gen3" });
    }
  });

// ============================================================================
// 50. Verified blob readiness controls every surface (Node bytes API)
// ============================================================================

describe("50 [Node SQLite] verified blob readiness", () => {
  function blobSource() {
    const source = nodeLocal({ declarations: decls(binding) });
    const bytes = new Uint8Array([8, 9]);
    const blob = source.store.storeBlobBytesForInstance({
      instance: C,
      method: identity.methodId,
      generation: 1,
      bytes,
      mimeType: "application/octet-stream",
    });
    source.store.replaceStream({
      instance: C,
      stream: STREAM,
      method: identity.methodId,
      generation: 1,
      emittedAt: at,
      envelopes: [
        {
          instance: C,
          stream: STREAM,
          key: "k",
          data: {
            id: "k",
            blob_ref: {
              blob_id: blob.blobId,
              mime_type: blob.mimeType,
              size_bytes: 2,
            },
          },
          emitted_at: at,
        },
      ],
      primaryKey: ["id"],
      sourceCollectedAt: at,
    });
    const operations = source.operations();
    expect(operations.some((op) => op.kind === "blob-claim")).toBe(true);
    expect(operations.some((op) => op.kind === "stream-complete")).toBe(true);
    return { operations, bytes, blobId: blob.blobId };
  }
  const hiddenEverywhere = (d: Local, blobId: string) => {
    const s = surfacesOf(d);
    expect(s.point("k")).toBeUndefined();
    expect(s.list).toEqual([]);
    expect(s.changes).toEqual([]);
    expect(d.store.getBlobBytes(blobId)).toBeUndefined();
    expect(
      s.completions,
      "completion stays pending until verified bytes",
    ).toEqual([]);
  };
  it("50 missing, then corrupt, then exact bytes: nothing is exposed until verified, then everything is", () => {
    const { operations, bytes, blobId } = blobSource();
    const target = nodeLocal({ declarations: decls(binding) });
    target.send(operations);
    hiddenEverywhere(target, blobId);
    target.reopen();
    hiddenEverywhere(target, blobId);
    expect(() =>
      target.send(operations, [{ blobId, bytes: new Uint8Array([1, 2]) }]),
    ).toThrow();
    target.reopen();
    hiddenEverywhere(target, blobId);
    target.send(operations, [{ blobId, bytes }]);
    const s = surfacesOf(target);
    expect(s.list).toEqual(["k"]);
    expect(s.changes).toEqual(["k"]);
    expect(target.store.getBlobBytes(blobId)).toEqual(bytes);
    expect(s.completions).toEqual([STREAM]);
    target.reopen();
    expect(surfacesOf(target).completions).toEqual([STREAM]);
  });
  it("50 [Lite] adapters expose no list/changes/completion; a record needing missing bytes is hidden at the point read", async () => {
    for (const [name, factory] of Object.entries(adapterFactories).filter(
      ([n]) => n.startsWith("Lite"),
    )) {
      const a = await open(factory, binding);
      assertSurfaceTruth(a);
      expect(a.surfaces.list, name).toBe("unsupported");
      expect(a.surfaces.completion, name).toBe("unsupported");
      const hash = `sha256:${"1".repeat(64)}`;
      const descriptor = {
        blobId: hash,
        sha256: hash,
        sizeBytes: 2,
        mimeType: "text/plain",
      };
      await send(a, [
        registration,
        {
          ...identity,
          kind: "blob-claim",
          blob: descriptor,
          revision: { counter: 2, writerId: "device-a", operationId: "claim" },
        },
        {
          ...rec("k", "blob-op", 3),
          data: { id: "k", blob_ref: { blob_id: hash } },
          blobs: [descriptor],
        },
      ]);
      expect(await visible(a, "k"), name).toBe(false);
      expect(await a.blob!(hash), name).toBeUndefined();
      a.reopen();
      expect(await visible(a, "k"), name).toBe(false);
    }
  });
});

// ============================================================================
// 51. Completion dependencies are exact and durable
// 52. Ordinary unrelated writes do not rewrite completion receipts
// ============================================================================

function completionSource() {
  const source = nodeLocal({ declarations: decls(binding) });
  source.store.replaceStream({
    instance: C,
    stream: STREAM,
    method: identity.methodId,
    generation: 1,
    emittedAt: at,
    envelopes: ["a", "b"].map((key) => ({
      instance: C,
      stream: STREAM,
      key,
      data: { id: key, text: `snapshot-${key}` },
      emitted_at: at,
    })),
    primaryKey: ["id"],
    sourceCollectedAt: at,
  });
  const operations = source.operations();
  const completion = operations.find((op) => op.kind === "stream-complete");
  if (completion?.kind !== "stream-complete")
    throw new Error("source produced no completion");
  const records = operations.filter((op) => op.kind === "upsert");
  const lifecycle = operations.find((op) => op.kind === "connection-register");
  if (!lifecycle) throw new Error("source produced no registration");
  expect(records).toHaveLength(2);
  // The completion names its two records and the registration it depends on.
  expect(completion.dependencies).toHaveLength(3);
  return { operations, completion, records, lifecycle };
}
describe("51 [Node SQLite] completion dependencies", () => {
  it("51a completion stays unavailable while one dependency is absent, then appears once with the exact record", () => {
    const { completion, records, lifecycle } = completionSource();
    const target = nodeLocal({ declarations: decls(binding) });
    target.send([lifecycle, completion, records[0]]);
    expect(surfacesOf(target).list).toEqual(["a"]);
    expect(target.store.listStreamCompletions(C)).toEqual([]);
    target.reopen();
    expect(target.store.listStreamCompletions(C)).toEqual([]);
    target.send([records[1]]);
    const receipts = target.store.listStreamCompletions(C);
    expect(receipts).toHaveLength(1);
    target.reopen();
    target.send([completion, ...records]);
    expect(target.store.listStreamCompletions(C)).toEqual(receipts);
  });
  it("51b a completion naming a wrong record hash is not available even when count and digest match", () => {
    const { completion, records, lifecycle } = completionSource();
    const bad: ReplicaOperation = {
      ...completion,
      revision: {
        ...completion.revision,
        operationId: "completion-wrong-dependency",
      },
      dependencies: completion.dependencies.map((dep, i, all) =>
        i === all.length - 1
          ? { ...dep, digest: `sha256:${"0".repeat(64)}` as const }
          : dep,
      ),
    };
    const target = nodeLocal({ declarations: decls(binding) });
    target.send([lifecycle, bad, ...records]);
    expect(surfacesOf(target).list).toEqual(["a", "b"]);
    expect(target.store.listStreamCompletions(C)).toEqual([]);
    target.reopen();
    target.retry();
    expect(target.store.listStreamCompletions(C)).toEqual([]);
  });
  it("51c [Lite] has no completion surface and still hides the dependent record state", async () => {
    for (const [name, factory] of Object.entries(adapterFactories).filter(
      ([n]) => n.startsWith("Lite"),
    )) {
      const a = await open(factory, binding);
      assertSurfaceTruth(a);
      expect(a.surfaces.completion, name).toBe("unsupported");
      expect(a.completion, name).toBeUndefined();
    }
  });
});
describe("52 [Node SQLite] completion receipts", () => {
  it("52 an available completion is byte-identical after unrelated writes, replay and reopen", () => {
    const { operations } = completionSource();
    const target = nodeLocal({ declarations: decls(binding) });
    target.send(operations);
    const before = target.store.listStreamCompletions(C);
    expect(before).toHaveLength(1);
    target.store.registerConnection({
      instance: "conn_unrelated",
      sourceId: identity.sourceId,
      method: identity.methodId,
      label: "unrelated",
    });
    target.ingest("conn_unrelated", "other", "unrelated", "mutable_state");
    target.ingest(C, "local-extra", "extra", "mutable_state");
    target.send(operations);
    target.reopen();
    target.send(operations);
    // The ordinary write to the same stream legitimately drops the receipt; the unrelated one does not.
    const unrelatedOnly = nodeLocal({ declarations: decls(binding) });
    unrelatedOnly.send(operations);
    const baseline = unrelatedOnly.store.listStreamCompletions(C);
    unrelatedOnly.store.registerConnection({
      instance: "conn_unrelated",
      sourceId: identity.sourceId,
      method: identity.methodId,
      label: "unrelated",
    });
    unrelatedOnly.ingest(
      "conn_unrelated",
      "other",
      "unrelated",
      "mutable_state",
    );
    unrelatedOnly.send(operations);
    unrelatedOnly.reopen();
    unrelatedOnly.send(operations);
    expect(unrelatedOnly.store.listStreamCompletions(C)).toEqual(baseline);
    expect(surfacesOf(unrelatedOnly).list).toEqual(["a", "b"]);
    expect(
      unrelatedOnly.store.getRecord("conn_unrelated", STREAM, "other"),
    ).toBeDefined();
  });
  it("52 [Lite] has no completion surface", async () => {
    for (const [name, factory] of Object.entries(adapterFactories).filter(
      ([n]) => n.startsWith("Lite"),
    )) {
      const a = await open(factory, binding);
      assertSurfaceTruth(a);
      expect(a.surfaces.completion, name).toBe("unsupported");
    }
  });
});

// ============================================================================
// 53. Cursor position / finding j.1 (155a82f0): quarantine must not shift pagination
// ============================================================================

for (const [name, factory] of Object.entries(adapterFactories))
  describe(`53 ${name}`, () => {
    for (const victim of ["a", "d"]) {
      const kind = victim === "a" ? "already returned" : "not yet returned";
      it(`53a [${name}] finding j.1: quarantining ${kind} key ${victim} between changes pages expires the session and a restart returns every clean key once`, async () => {
        const a = await open(factory, appendDecl);
        assertSurfaceTruth(a);
        const keys = ["a", "b", "c", "d", "e"];
        await send(a, [registration, ...originals(keys)]);
        const clean = keys.filter((key) => key !== victim);
        if (a.changes) {
          const page1 = await a.changes(C, STREAM, { limit: 2 });
          expect(keysOf(page1)).toEqual(["a", "b"]);
          expect(page1.nextCursor).toBeDefined();
          await send(a, [conflict(victim)]);
          // Continuing an offset session over a changed eligible set skips or repeats rows.
          await expect(
            a.changes(C, STREAM, { limit: 2, cursor: page1.nextCursor }),
            "old session cursor must expire, not shift",
          ).rejects.toBeInstanceOf(CursorExpiredError);
          const seen: string[] = [];
          let cursor: string | undefined;
          for (let i = 0; i < 6; i++) {
            const page = await a.changes(C, STREAM, { limit: 2, cursor });
            seen.push(...keysOf(page));
            cursor = page.nextCursor;
            if (!cursor) break;
          }
          expect(
            seen.sort(),
            "every clean key exactly once, victim never",
          ).toEqual(clean);
        } else {
          expect(a.surfaces.changes).toBe("unsupported");
          await send(a, [conflict(victim)]);
        }
        expect(await visibleKeys(a, keys)).toEqual(clean);
        a.reopen();
        expect(await visibleKeys(a, keys)).toEqual(clean);
      });
    }
    it(`53b [${name}] filtered keys a, b, d never create empty-loop, skipped or duplicated list pages`, async () => {
      const a = await open(factory, appendDecl);
      assertSurfaceTruth(a);
      const keys = ["a", "b", "c", "d", "e"];
      await send(a, [registration, ...originals(keys)]);
      for (const victim of ["a", "b", "d"]) await send(a, [conflict(victim)]);
      expect(await visibleKeys(a, keys)).toEqual(["c", "e"]);
      if (a.list) {
        const seen: string[] = [];
        let cursor: string | undefined;
        let pages = 0;
        do {
          const page = await a.list(C, STREAM, { limit: 1, cursor });
          expect(page.data.length).toBeLessThanOrEqual(1);
          seen.push(...keysOf(page));
          cursor = page.nextCursor;
          pages++;
        } while (cursor && pages < 10);
        expect(seen).toEqual(["c", "e"]);
        expect(cursor).toBeUndefined();
      } else expect(a.surfaces.list).toBe("unsupported");
    });
  });

// ============================================================================
// 54. Projection-only changes still advance scan position
// 55. Stable ties and both directions
// 56. Ordinary writes between pages preserve the snapshot horizon
// ============================================================================

describe("54-56 [Node SQLite] cursor position, ties and horizon", () => {
  const mutable = () => nodeLocal({ declarations: decls(binding) });
  it("54 changes hidden by field projection do not hide a later selected-field change", () => {
    const d = mutable();
    for (const key of ["a", "b", "c", "d", "e"])
      d.ingest(C, key, "t", "mutable_state", { other: "o1" });
    const token = d.changes().nextChangesSince;
    expect(token).toBeDefined();
    d.ingest(C, "a", "t", "mutable_state", { other: "o2" });
    d.ingest(C, "b", "t", "mutable_state", { other: "o2" });
    d.ingest(C, "c", "t2", "mutable_state", { other: "o1" });
    const historyBefore = d.historyRows(C, "a").length;
    const selected = d.changes({
      changesSince: token,
      fields: ["id", "text"],
      limit: 1,
    });
    expect(selected.data.map((row) => row.recordKey)).toEqual(["c"]);
    expect(selected.hasMore).toBe(false);
    const all = d.changes({ changesSince: token, limit: 10 });
    expect(all.data.map((row) => row.recordKey)).toEqual(["a", "b", "c"]);
    expect(d.historyRows(C, "a")).toHaveLength(historyBefore);
  });
  it("55a identical ordering values with quarantined keys page ascending and descending exactly once", () => {
    const d = nodeLocal({ declarations: decls(appendDecl) });
    const keys = ["k1", "k2", "k3", "k4", "k5"];
    d.ingestAll(keys);
    d.send([conflict("k2"), conflict("k4")]);
    const clean = ["k1", "k3", "k5"];
    for (const order of ["asc", "desc"] as const) {
      const seen: string[] = [];
      let cursor: string | undefined;
      for (let i = 0; i < 8; i++) {
        const page = d.list(cursor, 1, [C], order);
        seen.push(...page.data.map((row) => row.recordKey));
        cursor = page.nextCursor;
        if (!cursor) break;
      }
      expect(seen).toEqual(order === "asc" ? clean : [...clean].reverse());
    }
  });
  it("55b identical ordering values with a tombstone page both directions and changes report the tombstone once", () => {
    const d = mutable();
    const keys = ["k1", "k2", "k3", "k4", "k5"];
    d.ingestAll(keys, "mutable_state");
    expect(d.store.deleteRecord(C, STREAM, "k3", at, "mutable_state")).toBe(
      true,
    );
    const live = ["k1", "k2", "k4", "k5"];
    for (const order of ["asc", "desc"] as const) {
      const seen: string[] = [];
      let cursor: string | undefined;
      for (let i = 0; i < 8; i++) {
        const page = d.list(cursor, 1, [C], order);
        seen.push(...page.data.map((row) => row.recordKey));
        cursor = page.nextCursor;
        if (!cursor) break;
      }
      expect(seen).toEqual(order === "asc" ? live : [...live].reverse());
    }
    const seen: { key: string; deleted: boolean }[] = [];
    let cursor: string | undefined;
    for (let i = 0; i < 8; i++) {
      const page = d.changes({ limit: 1, cursor });
      seen.push(
        ...page.data.map((row) => ({
          key: row.recordKey,
          deleted: row.deleted ?? false,
        })),
      );
      cursor = page.nextCursor;
      if (!cursor) break;
    }
    expect(seen.map((row) => row.key)).toEqual(keys);
    expect(seen.find((row) => row.key === "k3")?.deleted).toBe(true);
  });
  it("56 ordinary writes between pages neither expire a session nor leak past its horizon; a fresh session sees them", () => {
    const d = mutable();
    d.ingestAll(["a", "b", "c"], "mutable_state");
    const page1 = d.changes({ limit: 1 });
    expect(page1.data.map((row) => row.recordKey)).toEqual(["a"]);
    const listPage = d.list(undefined, 1);
    d.ingest(C, "d", "new", "mutable_state");
    d.ingest(C, "b", "updated", "mutable_state");
    expect(d.store.deleteRecord(C, STREAM, "c", at, "mutable_state")).toBe(
      true,
    );
    const rest: { key: string; text?: unknown; deleted: boolean }[] = [];
    let cursor = page1.nextCursor;
    for (let i = 0; i < 5 && cursor; i++) {
      const page = d.changes({ limit: 1, cursor });
      rest.push(
        ...page.data.map((row) => ({
          key: row.recordKey,
          text: "data" in row ? row.data.text : undefined,
          deleted: row.deleted ?? false,
        })),
      );
      cursor = page.nextCursor;
    }
    expect(rest).toEqual([
      { key: "b", text: "original-b", deleted: false },
      { key: "c", text: "original-c", deleted: false },
    ]);
    expect(() => d.list(listPage.nextCursor, 1)).not.toThrow();
    const fresh = d.changes({ limit: 100 });
    expect(fresh.data.map((row) => row.recordKey)).toEqual([
      "a",
      "b",
      "c",
      "d",
    ]);
    expect(fresh.data.find((row) => row.recordKey === "c")?.deleted).toBe(true);
  });
  it("54-56 [Lite] expose no list or changes cursor surface", async () => {
    for (const [name, factory] of Object.entries(adapterFactories).filter(
      ([n]) => n.startsWith("Lite"),
    )) {
      const a = await open(factory, binding);
      assertSurfaceTruth(a);
      expect([a.surfaces.list, a.surfaces.changes], name).toEqual([
        "unsupported",
        "unsupported",
      ]);
    }
  });
});

// ============================================================================
// 57 / 58. Quarantine mid-list / finding k (#440 P1)
// ============================================================================

for (const [name, factory] of Object.entries(adapterFactories))
  describe(`57-58 ${name}`, () => {
    it(`57 [${name}] finding k: quarantining a not-yet-returned key expires the old list cursor; a fresh list is exactly a, c`, async () => {
      const a = await open(factory, appendDecl);
      assertSurfaceTruth(a);
      await send(a, [registration, ...originals(["a", "b", "c"])]);
      let cursor: string | undefined;
      if (a.list) {
        const page1 = await a.list(C, STREAM, { limit: 1 });
        expect(keysOf(page1)).toEqual(["a"]);
        cursor = page1.nextCursor;
        expect(cursor).toBeDefined();
      } else expect(a.surfaces.list).toBe("unsupported");
      await send(a, [conflict("b")]);
      for (const restart of [false, true]) {
        if (restart) a.reopen();
        expect(await visibleKeys(a, ["a", "b", "c"])).toEqual(["a", "c"]);
        if (a.list) {
          await expect(
            a.list(C, STREAM, { limit: 1, cursor }),
            "old cursor expires deterministically with no data",
          ).rejects.toBeInstanceOf(CursorExpiredError);
          expect(keysOf(await a.list(C, STREAM, { limit: 100 }))).toEqual([
            "a",
            "c",
          ]);
        }
      }
    });
    it(`58 [${name}] finding k: quarantining an already-returned key expires the old cursor; a fresh list is exactly b`, async () => {
      const a = await open(factory, appendDecl);
      assertSurfaceTruth(a);
      await send(a, [registration, ...originals(["a", "b"])]);
      let cursor: string | undefined;
      if (a.list) {
        const page1 = await a.list(C, STREAM, { limit: 1 });
        expect(keysOf(page1)).toEqual(["a"]);
        cursor = page1.nextCursor;
      } else expect(a.surfaces.list).toBe("unsupported");
      await send(a, [conflict("a")]);
      for (const restart of [false, true]) {
        if (restart) a.reopen();
        expect(await visibleKeys(a, ["a", "b"])).toEqual(["b"]);
        if (a.list) {
          await expect(
            a.list(C, STREAM, { limit: 1, cursor }),
          ).rejects.toBeInstanceOf(CursorExpiredError);
          expect(keysOf(await a.list(C, STREAM, { limit: 100 }))).toEqual([
            "b",
          ]);
        }
      }
    });
    it(`57w [${name}] write side: the key quarantine bumps this connection's integrity epoch and a replay does not move it again`, async () => {
      const a = await open(factory, appendDecl);
      assertSurfaceTruth(a);
      await send(a, [registration, ...originals(["a", "b", "c"])]);
      const before = epochBaseline(a);
      await send(a, [conflict("b")]);
      if (a.integrityEpoch) {
        const after = epochNow(a);
        expect(after).toBeGreaterThan(before);
        await send(a, [conflict("b")]);
        a.reopen();
        expect(
          epochNow(a),
          "replay and reopen leave the fence where it is",
        ).toBe(after);
      } else expect(a.surfaces.integrityEpoch).toBe("unsupported");
    });
  });

// ============================================================================
// 59. Quarantine inside historical changes pagination / finding e (#428 F1)
// ============================================================================

describe("59 [Node SQLite] finding e (#428 F1)", () => {
  const seeded = (options: LocalOptions = {}) => {
    const d = nodeLocal({ declarations: decls(appendDecl), ...options });
    d.ingestAll(["a", "b"]);
    return d;
  };
  it("59a write side: the withdrawal and the epoch bump commit together at every process-loss point", () => {
    const probe = new CrashController();
    const reference = seeded({ crash: probe });
    probe.arm();
    reference.send([conflict("b")]);
    const points = probe.trace.length;
    probe.disarm();
    expect(points).toBeGreaterThan(0);
    expect(reference.quarantinedKeys()).toEqual(["b"]);
    expect(
      epochOf(reference.store, C),
      "uncrashed run raises the epoch",
    ).toBeGreaterThan(0);
    for (let i = 0; i < points; i++) {
      const crash = new CrashController();
      const d = seeded({ crash });
      const base = epochBase(d.store, C);
      crash.arm(i);
      try {
        d.send([conflict("b")]);
      } catch {
        /* process loss */
      }
      d.crashReopen();
      const withdrawn = d.quarantinedKeys().includes("b");
      expect(
        epochOf(d.store, C) > base,
        `crash point ${i} (${probe.trace[i]}): epoch moves iff the withdrawal committed (withdrawn=${withdrawn})`,
      ).toBe(withdrawn);
    }
  }, 30_000); // one seeded store per process-loss point
  it("59b read side: an in-flight changes cursor and a terminal token both expire; a fresh session never returns b's payload; history stays", () => {
    const d = seeded();
    const page1 = d.changes({ limit: 1 });
    expect(page1.data.map((row) => row.recordKey)).toEqual(["a"]);
    expect(page1.nextCursor).toBeDefined();
    const terminal = d.changes({ limit: 100 }).nextChangesSince;
    expect(terminal).toBeDefined();
    const liveBefore = d.historyRows(C, "b").filter((row) => row.deleted === 0);
    expect(liveBefore).toHaveLength(1);
    d.send([conflict("b")]);
    for (const restart of [false, true]) {
      if (restart) d.reopen();
      expect(() => d.changes({ limit: 1, cursor: page1.nextCursor })).toThrow(
        CursorExpiredError,
      );
      expect(() => d.changes({ changesSince: terminal })).toThrow(
        CursorExpiredError,
      );
      const fresh = d.changes({ limit: 100 });
      expect(fresh.data.map((row) => row.recordKey)).toEqual(["a"]);
      expect(JSON.stringify(fresh)).not.toContain("original-b");
      expect(JSON.stringify(fresh)).not.toContain("conflicting-b");
      expect(d.store.getRecord(C, STREAM, "b")).toBeUndefined();
      expect(
        d.historyRows(C, "b").filter((row) => row.deleted === 0),
        "evidence is retained, not deleted",
      ).toEqual(liveBefore);
    }
  });
  it("59c [Lite twins] have no changes surface; the same import sequence hides b at the point read", async () => {
    for (const [name, factory] of Object.entries(adapterFactories).filter(
      ([n]) => n.startsWith("Lite"),
    )) {
      const a = await open(factory, appendDecl);
      assertSurfaceTruth(a);
      expect(a.surfaces.changes, name).toBe("unsupported");
      expect(a.surfaces.integrityEpoch, name).toBe("unsupported");
      await send(a, [registration, ...originals(["a", "b"])]);
      await send(a, [conflict("b")]);
      expect(await visibleKeys(a, ["a", "b"]), name).toEqual(["a"]);
      a.reopen();
      expect(await visibleKeys(a, ["a", "b"]), name).toEqual(["a"]);
    }
  });
});

// ============================================================================
// 60. Same-page concurrent fence
// ============================================================================

describe("60 [Node SQLite] a fence that commits between row selection and the response", () => {
  function raced(match: RegExp) {
    let armed = false;
    let fire: () => void = () => undefined;
    const d = nodeLocal({
      declarations: decls(appendDecl),
      hook: (sql) => {
        if (armed && match.test(sql)) {
          armed = false;
          fire();
        }
      },
    });
    d.ingestAll(["a", "b", "c"]);
    const writer = d.second();
    fire = () => writer.send([conflict("b")]);
    return { d, arm: () => (armed = true) };
  }
  it("60a list: the page is wholly pre-fence or expired, and its cursor is never labelled with the post-fence epoch", () => {
    const { d, arm } = raced(
      /FROM pdpp_record_changes c INDEXED BY idx_pdpp_record_changes_snapshot_key_order\s+WHERE c\.stream = \?/,
    );
    arm();
    let page: ReturnType<Local["list"]> | undefined;
    try {
      page = d.list(undefined, 2);
    } catch (error) {
      expect(error).toBeInstanceOf(CursorExpiredError);
    }
    expect(
      d.store.getRecord(C, STREAM, "b"),
      "the fence committed",
    ).toBeUndefined();
    if (page && page.data.some((row) => row.recordKey === "b")) {
      // Linearized before the fence: legal, but its continuation must carry the old epoch.
      expect(page.nextCursor).toBeDefined();
      expect(
        () => d.list(page.nextCursor, 2),
        "minted before the fence, so it expires",
      ).toThrow(CursorExpiredError);
    } else if (page)
      expect(page.data.map((row) => row.recordKey)).toEqual(["a", "c"]);
    expect(d.list(undefined, 100).data.map((row) => row.recordKey)).toEqual([
      "a",
      "c",
    ]);
  });
  it("60b changes: the page is wholly pre-fence or expired, and its terminal token expires", () => {
    const { d, arm } = raced(
      /FROM pdpp_record_changes c INDEXED BY idx_pdpp_record_changes_snapshot_key_order\s+WHERE c\.stream = \?/,
    );
    arm();
    let page: ReturnType<Local["changes"]> | undefined;
    try {
      page = d.changes({ limit: 100 });
    } catch (error) {
      expect(error).toBeInstanceOf(CursorExpiredError);
    }
    expect(d.store.getRecord(C, STREAM, "b")).toBeUndefined();
    if (page && page.data.some((row) => row.recordKey === "b")) {
      // Linearized before the fence: legal, but its terminal token must carry the old epoch.
      expect(page.nextChangesSince).toBeDefined();
      expect(() => d.changes({ changesSince: page.nextChangesSince })).toThrow(
        CursorExpiredError,
      );
    } else if (page)
      expect(page.data.map((row) => row.recordKey)).toEqual(["a", "c"]);
    expect(d.changes({ limit: 100 }).data.map((row) => row.recordKey)).toEqual([
      "a",
      "c",
    ]);
  });
  it("60 [Lite] has no list or changes surface to race", async () => {
    for (const [name, factory] of Object.entries(adapterFactories).filter(
      ([n]) => n.startsWith("Lite"),
    )) {
      const a = await open(factory, appendDecl);
      assertSurfaceTruth(a);
      expect([a.surfaces.list, a.surfaces.changes], name).toEqual([
        "unsupported",
        "unsupported",
      ]);
    }
  });
});

// ============================================================================
// 61. Relevant versus unrelated epoch changes
// ============================================================================

describe("61 relevant versus unrelated fences", () => {
  it("61a [Node SQLite] write side: a Y fence moves only Y's epoch; an X fence moves only X's", () => {
    const d = nodeLocal({
      declarations: decls(appendDecl),
      connections: [C, Y],
    });
    d.ingestAll(["a", "b", "c"]);
    d.ingestAll(["p", "q"], "append_only", Y);
    const x0 = epochBase(d.store, C);
    const y0 = epochBase(d.store, Y);
    d.send([conflict("q", Y)]);
    expect(d.epoch(Y)).toBeGreaterThan(y0);
    expect(d.epoch(C)).toBe(x0);
    const y1 = d.epoch(Y);
    d.send([conflict("c", C)]);
    expect(d.epoch(C)).toBeGreaterThan(x0);
    expect(d.epoch(Y)).toBe(y1);
  });
  it("61b [Node SQLite] read side: a Y-only fence leaves an X-only cursor valid; an X fence expires it", () => {
    const d = nodeLocal({
      declarations: decls(appendDecl),
      connections: [C, Y],
    });
    d.ingestAll(["a", "b", "c"]);
    d.ingestAll(["p", "q"], "append_only", Y);
    const page1 = d.list(undefined, 1);
    expect(page1.data.map((row) => row.recordKey)).toEqual(["a"]);
    d.send([conflict("q", Y)]);
    const page2 = d.list(page1.nextCursor, 1);
    expect(
      page2.data.map((row) => row.recordKey),
      "Y fence does not expire an X-only cursor",
    ).toEqual(["b"]);
    expect(page2.nextCursor).toBeDefined();
    d.send([conflict("c", C)]);
    expect(() => d.list(page2.nextCursor, 1), "an X fence expires it").toThrow(
      CursorExpiredError,
    );
    expect(() => d.list(page1.nextCursor, 1)).toThrow(CursorExpiredError);
  });
  for (const [name, factory] of Object.entries(adapterFactories).filter(([n]) =>
    n.startsWith("Lite"),
  ))
    it(`61c [${name}] has no epoch or list surface; point reads of X are unaffected by a Y fence and lose only the X victim`, async () => {
      const a = await openTwo(factory, appendDecl);
      assertSurfaceTruth(a);
      expect([a.surfaces.list, a.surfaces.integrityEpoch]).toEqual([
        "unsupported",
        "unsupported",
      ]);
      await send(a, [registration, ...originals(["a", "b", "c"])]);
      await send(a, [reg(Y), ...originals(["p", "q"], Y)]);
      await send(a, [conflict("q", Y)]);
      expect(await visibleKeys(a, ["a", "b", "c"])).toEqual(["a", "b", "c"]);
      expect(await visibleKeys(a, ["p", "q"], Y)).toEqual(["p"]);
      await send(a, [conflict("c", C)]);
      expect(await visibleKeys(a, ["a", "b", "c"])).toEqual(["a", "b"]);
      expect(await visibleKeys(a, ["p", "q"], Y)).toEqual(["p"]);
    });
});

// ============================================================================
// 62. Old cursors after reset, delete, quarantine and reopen
// ============================================================================

describe("62 [Node SQLite] old cursors after each fence kind", () => {
  const fences: Record<string, { apply: (d: Local) => void; fresh: string[] }> =
    {
      reset: { apply: (d) => d.send([resetOp(2)]), fresh: [] },
      delete: { apply: (d) => d.send([deleteOp]), fresh: [] },
      quarantine: { apply: (d) => d.send([conflict("b")]), fresh: ["a", "c"] },
    };
  const setup = () => {
    const d = nodeLocal({ declarations: decls(appendDecl) });
    d.send([registration]);
    d.ingestAll(["a", "b", "c"]);
    return d;
  };
  for (const [kind, fence] of Object.entries(fences)) {
    it(`62-${kind}-w write side: the fence bumps the epoch once; replay and reopen do not move it`, () => {
      const d = setup();
      const before = epochBase(d.store, C);
      fence.apply(d);
      const after = d.epoch();
      expect(after).toBeGreaterThan(before);
      d.reopen();
      fence.apply(d);
      d.reopen();
      expect(d.epoch(), "replay does not move the fence").toBe(after);
    });
    it(`62-${kind}-r read side: list cursor, changes-page cursor and changes token stay expired across reopen and replay; fresh reads obey the fence`, () => {
      const d = setup();
      const listCursor = d.list(undefined, 1).nextCursor;
      const pageCursor = d.changes({ limit: 1 }).nextCursor;
      const token = d.changes({ limit: 100 }).nextChangesSince;
      expect(
        [listCursor, pageCursor, token].every((c) => c !== undefined),
      ).toBe(true);
      fence.apply(d);
      for (const phase of ["after fence", "after reopen", "after replay"]) {
        if (phase === "after reopen") d.reopen();
        if (phase === "after replay") fence.apply(d);
        expect(() => d.list(listCursor, 1), `${phase}: list cursor`).toThrow(
          CursorExpiredError,
        );
        expect(
          () => d.changes({ limit: 1, cursor: pageCursor }),
          `${phase}: changes page cursor`,
        ).toThrow(CursorExpiredError);
        expect(
          () => d.changes({ changesSince: token }),
          `${phase}: changes token`,
        ).toThrow(CursorExpiredError);
        expect(d.list(undefined, 100).data.map((row) => row.recordKey)).toEqual(
          fence.fresh,
        );
        expect(
          d
            .changes({ limit: 100 })
            .data.filter((row) => !row.deleted)
            .map((row) => row.recordKey),
        ).toEqual(fence.fresh);
      }
    });
  }
  it("62L [Lite] has no list, changes or epoch API on the real store", () => {
    const store = createLiteCanonicalStore({
      persistence: createFakeCanonicalPersistence(fakeCanonicalDisk()).port,
      enabled: true,
      context: () => ctx(binding),
      authenticateReplica: () => identity.owner,
    });
    for (const method of [
      "listRecords",
      "changesSince",
      "listStreamCompletions",
      "replicaIntegrityEpoch",
      "replicaBindingConflict",
    ])
      expect(method in store, method).toBe(false);
  });
});

// ============================================================================
// 63. Cursor query/account binding and legacy tokens
// ============================================================================

describe("63 [Node SQLite] cursor binding", () => {
  const twoConnections = () => {
    const d = nodeLocal({
      declarations: decls(binding, profilesDecl),
      connections: [C, Y],
    });
    d.ingestAll(["a", "b", "c"], "mutable_state");
    d.ingestAll(["a", "b", "c"], "mutable_state", Y);
    return d;
  };
  it("63a a valid cursor continues an unchanged query", () => {
    const d = twoConnections();
    const page1 = d.list(undefined, 1);
    expect(
      d.list(page1.nextCursor, 1).data.map((row) => row.recordKey),
    ).toEqual(["b"]);
    const changes1 = d.changes({ limit: 1 });
    expect(
      d
        .changes({ limit: 1, cursor: changes1.nextCursor })
        .data.map((row) => row.recordKey),
    ).toEqual(["b"]);
  });
  it("63b a cursor reused on another stream or order is refused with no data", () => {
    const d = twoConnections();
    const cursor = d.list(undefined, 1).nextCursor;
    expectRefused(() => d.list(cursor, 1, [C], "asc", "profiles"));
    expectRefused(() => d.list(cursor, 1, [C], "desc"));
  });
  it("63c a cursor reused for a different connection set is refused with no data", () => {
    const d = twoConnections();
    const cursor = d.list(undefined, 1).nextCursor;
    expectRefused(() => d.list(cursor, 1, [Y]));
    expectRefused(() => d.list(cursor, 1, [C, Y]));
    const pageCursor = d.changes({ limit: 1 }).nextCursor;
    expectRefused(() =>
      d.changes({ limit: 1, cursor: pageCursor, instanceIds: [Y] }),
    );
  });
  it("63d a cursor reused under a different field projection is refused with no data", () => {
    const d = twoConnections();
    const cursor = d.list(undefined, 1, [C], "asc", STREAM, ["id"]).nextCursor;
    expectRefused(() => d.list(cursor, 1, [C], "asc", STREAM, ["id", "text"]));
    expectRefused(() => d.list(cursor, 1));
  });
  it("63e legacy and malformed tokens without store binding or horizon are refused, never restarted at offset zero", () => {
    const d = twoConnections();
    const legacy = [
      encodeCursor({
        kind: "list",
        order: "asc",
        sortValue: at,
        recordKey: "a",
        horizon: "0",
      }),
      encodeCursor({
        kind: "list",
        order: "asc",
        sortValue: at,
        recordKey: "a",
      }),
      "not-a-cursor",
    ];
    for (const cursor of legacy) expectRefused(() => d.list(cursor, 5));
    expectRefused(() =>
      d.changes({
        cursor: encodeCursor({
          kind: "changes_since",
          horizon: "0",
          sinceHorizon: null,
          offset: 0,
        }),
      }),
    );
    expectRefused(() =>
      d.changes({
        changesSince: encodeCursor({
          kind: "changes_since",
          horizon: "0",
          sinceHorizon: null,
          offset: 0,
        }),
      }),
    );
  });
  it("63f a cursor minted by another repository is refused with no data and mutates nothing", () => {
    const first = twoConnections();
    const second = twoConnections();
    const cursor = first.list(undefined, 1).nextCursor;
    const before = second.operations();
    expectRefused(() => second.list(cursor, 1));
    expect(second.operations()).toEqual(before);
    expect(second.list(undefined, 1).data.map((row) => row.recordKey)).toEqual([
      "a",
    ]);
  });
  it("63g [Lite] has no cursor surface to bind", async () => {
    for (const [name, factory] of Object.entries(adapterFactories).filter(
      ([n]) => n.startsWith("Lite"),
    )) {
      const a = await open(factory, binding);
      assertSurfaceTruth(a);
      expect([a.surfaces.list, a.surfaces.changes], name).toEqual([
        "unsupported",
        "unsupported",
      ]);
    }
  });
});

// ============================================================================
// 64. Fence dominates all materialization entry points and preserves evidence
// ============================================================================

describe("64 [Node SQLite] fence dominance", () => {
  const profileRecord = (d: Local) =>
    d.store.replaceStream({
      instance: C,
      stream: "profiles",
      method: identity.methodId,
      generation: 1,
      emittedAt: at,
      envelopes: [
        {
          instance: C,
          stream: "profiles",
          key: "p1",
          data: { id: "p1" },
          emitted_at: at,
        },
      ],
      primaryKey: ["id"],
      sourceCollectedAt: at,
    });
  const emptyReplace = (d: Local) =>
    d.store.replaceStream({
      instance: C,
      stream: STREAM,
      method: identity.methodId,
      generation: 1,
      emittedAt: at,
      envelopes: [],
      primaryKey: ["id"],
      sourceCollectedAt: at,
    });
  const attempt = (run: () => unknown) => {
    try {
      run();
    } catch {
      /* refusal is the contract; the durable state below is what is asserted */
    }
  };
  const refusedEntryPoints = (
    d: Local,
    replayOp: ReplicaOperation,
    repair: () => unknown,
  ) => {
    attempt(repair);
    attempt(() => emptyReplace(d));
    attempt(() => d.send([replayOp]));
    attempt(() => d.retry());
  };
  it("64a append-only key quarantine: no resurrection, no false empty completion, no evidence deletion, unrelated stream stays available", () => {
    const d = nodeLocal({ declarations: decls(appendDecl, profilesDecl) });
    d.ingestAll(["a", "b"]);
    d.send([conflict("b")]);
    const evidence = d.retained();
    const history = d.historyRows(C, "b");
    expect(evidence.some((json) => json.includes("conflicting-b"))).toBe(true);
    expect(history.some((row) => row.deleted === 0)).toBe(true);
    const outbound = d.operations();
    for (const phase of ["live", "reopened"]) {
      if (phase === "reopened") d.reopen();
      expect(
        () => d.ingest(C, "b", "collector-repair"),
        `${phase}: native ingest`,
      ).toThrow("replica_integrity_quarantine");
      refusedEntryPoints(d, conflict("b"), () =>
        d.ingest(C, "b", "collector-repair"),
      );
      expect(d.store.getRecord(C, STREAM, "b"), phase).toBeUndefined();
      expect(d.list(undefined, 100).data.map((row) => row.recordKey)).toEqual([
        "a",
      ]);
      expect(
        d.changes({ limit: 100 }).data.map((row) => row.recordKey),
      ).toEqual(["a"]);
      expect(
        d.store.listStreamCompletions(C).map((row) => row.stream),
        `${phase}: no completion for the fenced stream`,
      ).toEqual([]);
      expect(d.retained()).toEqual(expect.arrayContaining(evidence));
      expect(d.historyRows(C, "b")).toEqual(history);
      expect(d.operations()).toEqual(outbound);
    }
    profileRecord(d);
    expect(d.store.listStreamCompletions(C).map((row) => row.stream)).toEqual([
      "profiles",
    ]);
    d.reopen();
    expect(d.store.listStreamCompletions(C).map((row) => row.stream)).toEqual([
      "profiles",
    ]);
  });
  /**
   * The baseline retains declaration A; an imported record for key k names a
   * different valid declaration B. A local write under A then completes a
   * declaration conflict, and reconciliation must have the last word.
   */
  const conflictedByLocalWrite = () => {
    const declB: DeclarationBinding = {
      ...binding,
      digest: `sha256:${"c".repeat(64)}`,
    };
    const d = nodeLocal({ declarations: decls(binding) });
    createReplicaReceiver({
      db: d.db,
      store: d.store,
      owner: identity.owner,
      authenticate: (c) => (c === credential ? identity.owner : undefined),
      declarations: () => decls(binding, declB),
    }).import({
      credential,
      envelope: {
        format: "vana-pdpp-replica",
        version: 1,
        owner: identity.owner,
        batchId: "declaration-b",
        operations: [
          rec("k", "k-b", 20, { text: "retained", declaration: declB }),
        ],
      },
    });
    return d;
  };
  const arrivals = (d: Local) =>
    d.db
      .prepare(
        "SELECT record_key FROM pdpp_record_arrival WHERE instance = ? AND stream = ?",
      )
      .all(C, STREAM);
  it("64a-l a local replacement that completes a conflict leaves no arrival entry or completion receipt for the fenced key", () => {
    const d = conflictedByLocalWrite();
    const result = d.store.replaceStream({
      instance: C,
      stream: STREAM,
      method: identity.methodId,
      generation: 1,
      emittedAt: at,
      envelopes: [
        {
          instance: C,
          stream: STREAM,
          key: "k",
          data: { id: "k", text: "local content" },
          emitted_at: at,
        },
      ],
      primaryKey: ["id"],
      declaration: binding,
      sourceCollectedAt: at,
    });
    expect(result.applied).toBe(true);
    for (const phase of ["live", "reopened"]) {
      if (phase === "reopened") d.reopen();
      expect(d.store.getRecord(C, STREAM, "k"), phase).toBeUndefined();
      expect(arrivals(d), `${phase}: arrival`).toEqual([]);
      expect(
        d.store.listStreamCompletions(C).map((row) => row.stream),
        `${phase}: completion`,
      ).toEqual([]);
    }
  });
  it("64a-i a local ingest that completes a conflict leaves no arrival entry for the fenced key", () => {
    const d = conflictedByLocalWrite();
    d.ingest(C, "k", "local content", "mutable_state");
    expect(d.store.getRecord(C, STREAM, "k")).toBeUndefined();
    expect(arrivals(d)).toEqual([]);
  });
  it("64a-w write side: the key fence raises the epoch once; refused entry points, replay and reopen never move it", () => {
    const d = nodeLocal({ declarations: decls(appendDecl, profilesDecl) });
    d.ingestAll(["a", "b"]);
    const before = epochBase(d.store, C);
    d.send([conflict("b")]);
    const fenced = d.epoch();
    expect(fenced).toBeGreaterThan(before);
    for (const phase of ["live", "reopened"]) {
      if (phase === "reopened") d.reopen();
      refusedEntryPoints(d, conflict("b"), () =>
        d.ingest(C, "b", "collector-repair"),
      );
      expect(d.epoch(), phase).toBe(fenced);
    }
  });
  const equivocated = () => {
    const d = nodeLocal({ declarations: decls(binding), connections: [C, Y] });
    const original = rec("same-key", "dup", 20, { text: "first" });
    d.send([original]);
    d.ingest(Y, "y1", "kept", "mutable_state");
    const before = epochBase(d.store, C);
    d.send([{ ...original, data: { id: "same-key", text: "equivocated" } }]);
    return { d, original, before };
  };
  it("64b operation-ID equivocation quarantines the connection on every entry point; other connections stay mutable", () => {
    const { d, original } = equivocated();
    const evidence = d.retained();
    expect(
      evidence.filter((json) => json.includes('"operationId":"dup"')),
    ).toHaveLength(2);
    for (const phase of ["live", "reopened"]) {
      if (phase === "reopened") d.reopen();
      expect(
        () => d.ingest(C, "other", "collector-repair", "mutable_state"),
        phase,
      ).toThrow("replica_integrity_quarantine");
      refusedEntryPoints(d, original, () =>
        d.ingest(C, "other", "collector-repair", "mutable_state"),
      );
      const s = surfacesOf(d);
      expect(s.point("same-key"), phase).toBeUndefined();
      expect(s.list).toEqual([]);
      expect(s.changes).toEqual([]);
      expect(s.completions).toEqual([]);
      expect(d.retained()).toEqual(expect.arrayContaining(evidence));
    }
    expect(d.store.getRecord(Y, STREAM, "y1")?.data).toMatchObject({
      text: "kept",
    });
    d.ingest(Y, "y2", "still-mutable", "mutable_state");
    expect(d.store.getRecord(Y, STREAM, "y2")).toBeDefined();
  });
  it("64b-w write side: the connection fence raises only C's epoch; refused entry points, replay and reopen never move it", () => {
    const { d, original, before } = equivocated();
    const fenced = d.epoch();
    expect(fenced).toBeGreaterThan(before);
    expect(d.epoch(Y), "unrelated connection epoch is untouched").toBe(
      epochBase(d.store, Y),
    );
    for (const phase of ["live", "reopened"]) {
      if (phase === "reopened") d.reopen();
      refusedEntryPoints(d, original, () =>
        d.ingest(C, "other", "collector-repair", "mutable_state"),
      );
      expect(d.epoch(), phase).toBe(fenced);
    }
  });
  for (const [name, factory] of Object.entries(adapterFactories).filter(([n]) =>
    n.startsWith("Lite"),
  ))
    it(`64c [${name}] has no completion, list or epoch surface; both fences hide records at the point read after replay and reopen`, async () => {
      const a = await openTwo(factory, appendDecl);
      assertSurfaceTruth(a);
      expect([
        a.surfaces.completion,
        a.surfaces.integrityEpoch,
        a.surfaces.list,
      ]).toEqual(["unsupported", "unsupported", "unsupported"]);
      await send(a, [registration, ...originals(["a", "b"])]);
      await send(a, [reg(Y), ...originals(["p"], Y)]);
      await send(a, [conflict("b")]);
      for (const phase of [0, 1]) {
        if (phase) a.reopen();
        await send(a, [conflict("b")]);
        await a.retry();
        expect(await visibleKeys(a, ["a", "b"])).toEqual(["a"]);
        expect(await visible(a, "p", Y)).toBe(true);
      }
    });
});

// ============================================================================
// finding j.2 (155a82f0): a NULL-pin legacy slot after a finalized replacement
// ============================================================================

describe("j.2 [Node SQLite transport] legacy NULL-pin slot after a finalized replacement", () => {
  async function legacyWithReplacement() {
    const net = network();
    const a = transportDevice(net);
    const b = transportDevice(net);
    a.put("authentic");
    await cycles([a, b], 8);
    expect(b.get()).toEqual({ id: "a", text: "authentic" });
    const base = epochBase(b.store, b.instance);
    // An upgraded retained row: pins are NULL, so the commitment is not bound yet.
    b.db
      .prepare(
        "UPDATE pdpp_transport_inbox SET data_hash=NULL, metadata_hash=NULL",
      )
      .run();
    const scopes = (
      b.db
        .prepare(
          "SELECT scope FROM pdpp_transport_inbox WHERE fragment_json IS NOT NULL",
        )
        .all() as { scope: string }[]
    ).map((row) => row.scope);
    expect(scopes.length).toBeGreaterThan(0);
    for (const scope of scopes) {
      const row = net.head.get(scope)!;
      const replacement = { ...row, dataHash: `0x${"9".repeat(64)}` as const };
      net.head.set(scope, replacement);
      net.chain.set(scope, net.chainRow(scope, replacement));
    }
    await cycles([b], 6);
    return { b, base };
  }
  const readSurfaces = (
    b: Awaited<ReturnType<typeof legacyWithReplacement>>["b"],
  ) => ({
    point: b.store.getRecord(b.instance, "messages", "a"),
    list: b.store.listRecords("messages", {
      instanceIds: [b.instance],
      limit: 10,
      order: "asc",
    }).data,
    changes: b.store.changesSince("messages", {
      instanceIds: [b.instance],
      limit: 10,
    }).data,
  });
  it("j.2r read side: the legacy slot is ineligible on point, list and changes, across reopen", async () => {
    const { b } = await legacyWithReplacement();
    for (const restart of [false, true]) {
      if (restart) b.reopen();
      const s = readSurfaces(b);
      expect(s.point, "point").toBeUndefined();
      expect(s.list, "list").toEqual([]);
      expect(s.changes, "changes").toEqual([]);
    }
  });
  it("j.2w write side: the withdrawal raises the integrity epoch and survives reopen", async () => {
    const { b, base } = await legacyWithReplacement();
    const after = epochOf(b.store, b.instance);
    expect(after).toBeGreaterThan(base);
    b.reopen();
    expect(epochOf(b.store, b.instance)).toBe(after);
  });
});

// ============================================================================
// i. #427 A: the canonical write validator is bound to the retained declaration
// ============================================================================

describe("i [Node SQLite] a canonical write validated against another declaration", () => {
  const write = (
    d: ReturnType<typeof transportDevice>,
    key: string,
    declaration: typeof retainedBinding,
  ) =>
    d.store.ingestBatch(
      [
        {
          instance: d.instance,
          stream: "messages",
          key,
          data: { id: key, text: key },
          emitted_at: "2026-10-20T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "export", generation: 1 },
      () => null,
      () => declaration,
    );
  const exported = (d: ReturnType<typeof transportDevice>) =>
    (
      d.db
        .prepare("SELECT count(*) AS n FROM pdpp_replica_operations")
        .get() as { n: number }
    ).n;
  it("i.1 is refused atomically instead of being exported under the retained declaration", () => {
    const d = transportDevice(network());
    const before = exported(d);
    const v2 = {
      ...retainedBinding,
      digest: `sha256:${"c".repeat(64)}`,
      version: "2",
    };
    expect(() => write(d, "v2", v2)).toThrow(
      "replication declaration mismatch",
    );
    expect(d.get("v2"), "nothing was written").toBeUndefined();
    expect(exported(d), "nothing was exported").toBe(before);
    write(d, "v1", retainedBinding);
    expect(d.get("v1")).toEqual({ id: "v1", text: "v1" });
    expect(exported(d)).toBe(before + 1);
  });
});

// ============================================================================
// Token binding: the store binds and validates canonical changes tokens
// ============================================================================

describe("token binding [Node SQLite transport]: a binding-conflict fact expires both changes tokens", () => {
  for (const reader of ["owner", "grant"] as const)
    it(`[${reader}] a page cursor and a session token each expire after markReplicaBindingConflict`, async () => {
      const net = network();
      const d = transportDevice(net);
      for (const key of ["a", "b", "c"]) d.put(`text ${key}`, key);
      const read = () => d.receiver.readStore({ reader });
      const options = { instanceIds: [d.instance], limit: 1 };
      const page = read().changesSince("messages", options);
      expect(page.nextCursor).toBeDefined();
      const session = read().changesSince("messages", {
        ...options,
        limit: 100,
      }).nextChangesSince;
      expect(session).toBeDefined();
      // Both are valid before the fact.
      expect(() =>
        read().changesSince("messages", {
          ...options,
          cursor: page.nextCursor,
        }),
      ).not.toThrow();
      d.store.markReplicaBindingConflict({
        connectionId: d.instance,
        reason: "source_binding_conflict",
        evidence: {},
      });
      expect(() =>
        read().changesSince("messages", {
          ...options,
          cursor: page.nextCursor,
        }),
      ).toThrow(CursorExpiredError);
      expect(() =>
        read().changesSince("messages", { ...options, changesSince: session }),
      ).toThrow(CursorExpiredError);
    });
  it("the store's own tokens: an epoch bump between pages, and between session start and the first page", () => {
    const net = network();
    const d = transportDevice(net);
    for (const key of ["a", "b", "c"]) d.put(`text ${key}`, key);
    const options = { instanceIds: [d.instance], limit: 1 };
    const page = d.store.changesSince("messages", options);
    const session = d.store.changesSince("messages", {
      ...options,
      limit: 100,
    }).nextChangesSince;
    d.db.transaction(() => d.store.fenceReplicaConnection(d.instance))();
    expect(() =>
      d.store.changesSince("messages", { ...options, cursor: page.nextCursor }),
    ).toThrow(CursorExpiredError);
    expect(() =>
      d.store.changesSince("messages", { ...options, changesSince: session }),
    ).toThrow(CursorExpiredError);
  });
});
