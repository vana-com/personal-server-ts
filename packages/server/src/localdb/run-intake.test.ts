import { afterEach, describe, expect, it, vi } from "vitest";
import {
  connectionQueue,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import type {
  BeginRequest,
  IntakeDeclarations,
} from "../../../core/src/stream-sync/intake.js";
import { createRunIntakeStore } from "../../../core/src/localdb/run-intake.js";
import { createRunEndStore } from "../../../core/src/localdb/run-end.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { remoteFixture } from "./apply-fixture.js";

const owner = `0x${"12".repeat(20)}` as const;
const declaration: IntakeDeclarations = {
  connector: "fixture-source",
  version: "1",
  streams: [{ name: "items", semantics: "mutable_state", primaryKey: ["id"] }],
};
const request: BeginRequest = {
  connector: declaration.connector,
  artifactDigest: "fixture-artifact",
  owner: { address: owner, leaseId: null },
  observedAt: 40,
};
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
async function fixture() {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner,
    network: "test",
    deviceId: "intake",
  });
  drivers.push(db);
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const remote = await remoteFixture(keys);
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    keys,
    registry: remote.registry,
    blobs: remote.storage,
    queue: connectionQueue(),
    ownerAddress: owner,
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => 100,
    newOp: () => `intake-${++op}`,
  };
  return {
    ...remote,
    db,
    deps,
    store: createRunIntakeStore(deps),
    end: createRunEndStore(deps),
  };
}

describe("P03 run intake", () => {
  it("stages a batch and merges it at run end with first_o equal to run start", async () => {
    const f = await fixture();
    expect((await f.store.begin("run", request, declaration)).status).toBe(
      "collecting",
    );
    expect(
      await f.store.batch("run", {
        batch: 0,
        records: [{ stream: "items", data: { id: "a" } }],
      }),
    ).toEqual({ applied: true, accepted: 1, deletesSkipped: 0 });
    expect(await f.db.query("SELECT * FROM records")).toEqual([]);
    await f.end.end("run", {
      outcome: "retry_pending",
      coveredStreams: [],
      lastBatch: 0,
    });
    expect(await f.db.query("SELECT stamp_o,first_o FROM records")).toEqual([
      { stamp_o: 40, first_o: 40 },
    ]);
  });
});

it("refuses dotted connector keys before any key or registry bind", async () => {
  const f = await fixture();
  const read = vi.spyOn(f.registry, "read");
  const keys = vi.spyOn(f.deps.keys, "namespaceHmac");
  await expect(
    f.store.begin(
      "dot",
      { ...request, connector: "fixture.source" },
      { ...declaration, connector: "fixture.source" },
    ),
  ).rejects.toMatchObject({ code: "invalid_request", status: 400 });
  expect(read).not.toHaveBeenCalled();
  expect(keys).not.toHaveBeenCalled();
  expect(await f.db.query("SELECT * FROM runs")).toEqual([]);
});

it("orders concurrent batches, acknowledges replay, and rejects a gap", async () => {
  const f = await fixture();
  await f.store.begin("run", request, declaration);
  const batch = { batch: 0, records: [{ stream: "items", data: { id: "a" } }] };
  const results = await Promise.all([
    f.store.batch("run", batch),
    f.store.batch("run", batch),
  ]);
  expect(results.map((r) => r.applied)).toEqual([true, false]);
  await expect(
    f.store.batch("run", { batch: 2, records: [] }),
  ).rejects.toMatchObject({ code: "batch_gap", nextBatch: 1 });
  expect(await f.db.query("SELECT count(*) AS n FROM run_rows")).toEqual([
    { n: 1 },
  ]);
});

it("checks typed keys across a batch, staged runs, and stored records atomically", async () => {
  const f = await fixture();
  await f.store.begin("run", request, declaration);
  const record = (id: number | string) => ({ stream: "items", data: { id } });
  await expect(
    f.store.batch("run", { batch: 0, records: [record(1), record("1")] }),
  ).rejects.toMatchObject({
    code: "invalid_request",
    message: "key_type_conflict",
  });
  expect(await f.db.query("SELECT * FROM run_rows")).toEqual([]);
  await f.store.batch("run", { batch: 0, records: [record(1)] });
  await f.store.begin("other", request, declaration);
  await expect(
    f.store.batch("other", { batch: 0, records: [record("1")] }),
  ).rejects.toMatchObject({ message: "key_type_conflict" });
  await f.end.end("run", {
    outcome: "retry_pending",
    coveredStreams: [],
    lastBatch: 0,
  });
  await expect(
    f.store.batch("other", { batch: 0, records: [record("1")] }),
  ).rejects.toMatchObject({ message: "key_type_conflict" });
  expect(
    await f.db.query("SELECT last_batch FROM runs WHERE run_id='other'"),
  ).toEqual([{ last_batch: -1 }]);
});

it("stages deletes, upserts duplicate keys, and rejects the whole malformed batch", async () => {
  const f = await fixture();
  await f.store.begin("run", request, declaration);
  await expect(
    f.store.batch("run", {
      batch: 0,
      records: [
        { stream: "items", data: { id: "a" } },
        { stream: "items", data: {} },
      ],
    }),
  ).rejects.toMatchObject({ code: "invalid_request" });
  expect(await f.db.query("SELECT * FROM run_rows")).toEqual([]);
  expect(
    await f.store.batch("run", {
      batch: 0,
      records: [
        { stream: "items", data: { id: "a", version: 1 } },
        { stream: "items", data: { id: "a", version: 2 } },
        { stream: "items", op: "delete", data: { id: "b" } },
      ],
    }),
  ).toEqual({ applied: true, accepted: 3, deletesSkipped: 0 });
  expect(await f.db.query("SELECT count(*) AS n FROM run_rows")).toEqual([
    { n: 2 },
  ]);
});

it.each(["intent", "control", "stream", "generation"] as const)(
  "a %s fence drops staging and forces a full recollect",
  async (kind) => {
    const f = await fixture();
    await f.store.begin("run", request, declaration);
    await f.store.batch("run", {
      batch: 0,
      records: [{ stream: "items", data: { id: "a" } }],
    });
    const sql =
      kind === "intent"
        ? "INSERT INTO delete_intents VALUES ('fixture-source','delete','{}')"
        : kind === "control"
          ? "UPDATE connections SET control_state='deleted'"
          : kind === "stream"
            ? "UPDATE stream_state SET last_delete_version=1"
            : "UPDATE connections SET generation=3";
    await f.db.batch([{ sql }]);
    await expect(
      f.store.batch("run", { batch: 1, records: [] }),
    ).rejects.toMatchObject({ code: "connection_stopped" });
    expect(await f.db.query("SELECT * FROM run_rows")).toEqual([]);
    expect(await f.db.query("SELECT checkpoint FROM connections")).toEqual([
      { checkpoint: null },
    ]);
    expect(
      await f.db.query("SELECT complete,needs_full FROM stream_state"),
    ).toEqual([{ complete: 0, needs_full: 1 }]);
  },
);

it("checks a delete that arrives after preflight in the atomic write batch", async () => {
  const f = await fixture();
  await f.store.begin("run", request, declaration);
  const batch = f.db.batch.bind(f.db);
  let injected = false;
  vi.spyOn(f.db, "batch").mockImplementation(async (statements) => {
    if (
      !injected &&
      statements.some((s) =>
        s.sql.includes("CREATE TEMP TRIGGER intake_rows_check"),
      )
    ) {
      injected = true;
      await batch([{ sql: "UPDATE connections SET control_state='deleted'" }]);
    }
    return batch(statements);
  });
  await expect(
    f.store.batch("run", {
      batch: 0,
      records: [{ stream: "items", data: { id: "a" } }],
    }),
  ).rejects.toMatchObject({ code: "connection_stopped" });
  expect(injected).toBe(true);
  expect(await f.db.query("SELECT * FROM run_rows")).toEqual([]);
});

it("replays a live begin, refuses a changed request and a replay after restart", async () => {
  const f = await fixture();
  const first = await f.store.begin("run", request, declaration);
  expect(await f.store.begin("run", { ...request }, declaration)).toEqual(
    first,
  );
  await expect(
    f.store.begin("run", { ...request, wantFull: true }, declaration),
  ).rejects.toMatchObject({ code: "run_conflict" });
  await expect(
    createRunIntakeStore(f.deps).begin("run", request, declaration),
  ).rejects.toMatchObject({ code: "gone" });
});

it("retains offline collection as collecting, with a fresh run generation-unbound", async () => {
  const f = await fixture();
  f.registry.read = async () => {
    throw new Error("offline fixture");
  };
  const response = await f.store.begin("offline", request, declaration);
  expect(response).toMatchObject({ status: "collecting", discardReason: null });
  expect(await f.db.query("SELECT generation FROM runs")).toEqual([
    { generation: null },
  ]);
  await f.store.batch("offline", {
    batch: 0,
    records: [{ stream: "items", data: { id: "a" } }],
  });
});

it("filters full-stream cursors and pins basis/deletion snapshots at begin", async () => {
  const f = await fixture();
  await f.head("items", [{ id: "base" }]);
  await f.store.begin("first", request, declaration);
  await f.db.batch([
    {
      sql: "UPDATE connections SET checkpoint=?",
      params: [JSON.stringify({ items: "C1", snapshot: "old" })],
    },
  ]);
  const response = await f.store.begin("next", request, {
    ...declaration,
    streams: [
      ...declaration.streams,
      {
        name: "snapshot",
        semantics: "mutable_state",
        primaryKey: ["id"],
        incremental: false,
      },
    ],
  });
  expect(response.start).toEqual({
    collection_mode: "incremental",
    state: { items: "C1" },
  });
  expect(response.streams.map((s) => s.mode)).toEqual([
    "incremental",
    "full_refresh",
  ]);
  expect(
    await f.db.query(
      "SELECT basis_version,delete_snapshot FROM run_streams WHERE run_id='next' AND stream='items'",
    ),
  ).toEqual([{ basis_version: 1, delete_snapshot: 0 }]);
  expect(await f.db.query("SELECT o FROM runs WHERE run_id='next'")).toEqual([
    { o: 40 },
  ]);
});

it("only an explicit connect starts a deleted connection, bound to its new generation", async () => {
  const f = await fixture();
  f.setControl(2, true);
  await expect(
    f.store.begin("scheduled", request, declaration),
  ).rejects.toMatchObject({ code: "connection_stopped" });
  f.registry.post = async (post) => {
    f.reads.set(post.scope, {
      found: true,
      version: Number(post.expectedVersion),
      dataHash: post.dataHash,
      metadataHash: post.metadataHash,
      deleted: false,
    });
    return { kind: "committed" };
  };
  expect(
    (
      await f.store.begin(
        "connected",
        { ...request, connect: true },
        declaration,
      )
    ).start.collection_mode,
  ).toBe("full_refresh");
  expect(await f.db.query("SELECT generation FROM runs")).toEqual([
    { generation: 3 },
  ]);
  await f.store.batch("connected", { batch: 0, records: [] });
});

it("cannot lift an unfinished delete intent by asking to reconnect", async () => {
  const f = await fixture();
  await f.db.batch([
    {
      sql: "INSERT INTO delete_intents VALUES ('fixture-source','delete','{}')",
    },
  ]);
  await expect(
    f.store.begin("connected", { ...request, connect: true }, declaration),
  ).rejects.toMatchObject({ code: "connection_stopped" });
  expect(await f.db.query("SELECT count(*) AS n FROM delete_intents")).toEqual([
    { n: 1 },
  ]);
  expect(await f.db.query("SELECT * FROM runs")).toEqual([]);
});

it("rejects restricted scopes before syncing and clamps a future producer clock", async () => {
  const f = await fixture();
  const read = vi.spyOn(f.registry, "read");
  await expect(
    f.store.begin(
      "restricted",
      { ...request, streams: [{ name: "items", fields: ["id"] }] },
      declaration,
    ),
  ).rejects.toMatchObject({ code: "restricted_scope_unsupported" });
  expect(read).not.toHaveBeenCalled();
  await f.store.begin(
    "future",
    { ...request, observedAt: 900000 },
    declaration,
  );
  expect(await f.db.query("SELECT o FROM runs")).toEqual([{ o: 300100 }]);
});
