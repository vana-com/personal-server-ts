import { afterEach, describe, expect, it, vi } from "vitest";
import {
  connectionQueue,
  createRecordQuery,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import type {
  BeginRequest,
  IntakeDeclarations,
} from "../../../core/src/stream-sync/intake.js";
import {
  createRunIntakeStore,
  STAGED_KEY_CONFLICTS,
} from "../../../core/src/localdb/run-intake.js";
import { createRunEndStore } from "../../../core/src/localdb/run-end.js";
import { RegistryUnavailableError } from "../../../core/src/stream-sync/ports.js";
import { endRequest } from "../../../core/src/test-utils/run-end.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { remoteFixture } from "./apply-fixture.test-utils.js";

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
    await f.end.end("run", endRequest({ lastBatch: 0, live: ["items"] }));
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
  await f.end.end("run", endRequest({ lastBatch: 0, live: ["items"] }));
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
  // The control row is read once, by the begin that observed it.
  const { control: _observed, ...stored } = first;
  expect(await f.store.begin("run", { ...request }, declaration)).toEqual(
    stored,
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
    throw new RegistryUnavailableError("offline fixture");
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

describe("run intake staging cost", () => {
  // Staging a row checks that no staged row of the same connection shares its
  // key with a different primary-key hash. That check must search by key; a
  // scan makes every batch cost more than the one before it, so a large run
  // blocks the event loop for minutes.
  it("checks staged-row key conflicts by index search, never by scan", async () => {
    const f = await fixture();
    for (const conflict of STAGED_KEY_CONFLICTS) {
      const plan = await f.db.query<{ detail: string }>(
        `EXPLAIN QUERY PLAN SELECT ${conflict.replace(/NEW\.(\w+)/g, "'$1'")}`,
      );
      const details = plan.map((row) => row.detail);
      expect(details.some((detail) => /^SEARCH x\b/.test(detail))).toBe(true);
      expect(details.filter((detail) => /^SCAN x\b/.test(detail))).toEqual([]);
    }
  });

  it("stages equal batches in near-constant time", async () => {
    const f = await fixture();
    await f.store.begin("run", request, declaration);
    const rows = (batch: number) =>
      Array.from({ length: 4000 }, (_, i) => ({
        stream: "items",
        data: { id: `r${batch}-${i}`, text: "x".repeat(200) },
      }));
    const timed: number[] = [];
    for (let batch = 0; batch < 4; batch += 1) {
      const started = performance.now();
      await f.store.batch("run", { batch, records: rows(batch) });
      timed.push(performance.now() - started);
    }
    // The last two batches must both stay near the first; a scan makes them 4x and 6x it.
    expect(Math.min(timed[2]!, timed[3]!) / timed[0]!).toBeLessThan(2);
  }, 60_000);
});

describe("partial retry checkpoints", () => {
  it.each(["independent", "child", "parent"] as const)(
    "keeps finished records and resumes the pending stream with %s checkpoints",
    async (dependency) => {
      const f = await fixture();
      const declarations: IntakeDeclarations = {
        ...declaration,
        streams: [
          {
            name: "a",
            semantics: "mutable_state",
            primaryKey: ["id"],
            ...(dependency === "child" ? { stateParents: ["b"] } : {}),
          },
          {
            name: "b",
            semantics: "mutable_state",
            primaryKey: ["id"],
            ...(dependency === "parent" ? { stateParents: ["a"] } : {}),
          },
        ],
      };
      await f.store.begin("initial", request, declarations);
      await f.store.batch("initial", {
        batch: 0,
        records: [
          { stream: "a", data: { id: "one", value: "old" } },
          { stream: "b", data: { id: "two", value: "old" } },
        ],
      });
      await f.end.end(
        "initial",
        endRequest({
          lastBatch: 0,
          live: ["a", "b"],
          checkpoints: { a: "a0", b: "b0" },
        }),
      );
      const begin = await f.store.begin(
        "partial",
        { ...request, observedAt: 50 },
        declarations,
      );
      expect(begin.start.state).toEqual({ a: "a0", b: "b0" });
      await f.store.batch("partial", {
        batch: 0,
        records: [{ stream: "a", data: { id: "one", value: "finished" } }],
      });
      const response = await f.end.end(
        "partial",
        endRequest({
          lastBatch: 0,
          streams: ["a", "b"],
          live: ["a"],
          observe: { b: { retryableSkip: true } },
          checkpoints: { a: "a1", b: "retry-job" },
        }),
      );
      expect(response).toMatchObject({
        outcome: "partial",
        coveredStreams: ["a"],
      });
      const query = createRecordQuery(f.db);
      const connectionId = (
        await f.db.query<{ connection_id: string }>(
          "SELECT connection_id FROM connections",
        )
      )[0]!.connection_id;
      const read = async (stream: string) =>
        (await query.listRecords({ connectionId, stream })).records.map((r) =>
          JSON.parse(r.body),
        );
      expect(await read("a")).toEqual([{ id: "one", value: "finished" }]);
      expect(await read("b")).toEqual([{ id: "two", value: "old" }]);
      const checkpoint =
        dependency === "independent"
          ? { a: "a1", b: "retry-job" }
          : { a: "a0", b: "b0" };
      expect(
        JSON.parse(
          (
            await f.db.query<{ checkpoint: string }>(
              "SELECT checkpoint FROM connections",
            )
          )[0]!.checkpoint,
        ),
      ).toEqual(checkpoint);
      const resumed = await f.store.begin(
        "retry",
        { ...request, observedAt: 60 },
        declarations,
      );
      expect(resumed.start.state).toEqual(checkpoint);
      await f.store.batch("retry", {
        batch: 0,
        records: [{ stream: "b", data: { id: "two", value: "finished" } }],
      });
      expect(
        await f.end.end(
          "retry",
          endRequest({
            lastBatch: 0,
            streams: ["a", "b"],
            live: ["b"],
            checkpoints: { a: "a1", b: "b1" },
          }),
        ),
      ).toMatchObject({ outcome: "succeeded" });
      expect(await read("a")).toEqual([{ id: "one", value: "finished" }]);
      expect(await read("b")).toEqual([{ id: "two", value: "finished" }]);
      expect(
        JSON.parse(
          (
            await f.db.query<{ checkpoint: string }>(
              "SELECT checkpoint FROM connections",
            )
          )[0]!.checkpoint,
        ),
      ).toEqual({ a: "a1", b: "b1" });
    },
  );
});

describe("raw evidence capture", () => {
  it("persists selection and delete-then-upsert history without counting replay", async () => {
    const f = await fixture();
    await f.store.begin(
      "raw",
      { ...request, selectedStreams: ["items"] },
      declaration,
    );
    const batch = {
      batch: 0,
      records: [
        { stream: "items", op: "delete", data: { id: "a" } },
        { stream: "items", data: { id: "a" } },
      ],
    };
    await f.store.batch("raw", batch);
    await f.store.batch("raw", batch);
    expect(
      await f.db.query("SELECT selected_streams FROM runs WHERE run_id='raw'"),
    ).toEqual([{ selected_streams: '["items"]' }]);
    expect(
      await f.db.query(
        "SELECT pk_values,ever_deleted,upsert_events,delete_events FROM run_record_evidence WHERE run_id='raw'",
      ),
    ).toEqual([
      {
        pk_values: '["a"]',
        ever_deleted: 1,
        upsert_events: 1,
        delete_events: 1,
      },
    ]);
    expect(
      await f.db.query("SELECT op FROM run_rows WHERE run_id='raw'"),
    ).toEqual([{ op: "upsert" }]);
    await expect(
      f.store.batch("raw", {
        batch: 1,
        records: [
          { stream: "items", data: { id: "b" } },
          { stream: "unknown", data: {} },
        ],
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });
    expect(
      await f.db.query(
        "SELECT count(*) AS n FROM run_record_evidence WHERE run_id='raw'",
      ),
    ).toEqual([{ n: 1 }]);
  });
  it.each([["items", "items"], ["unknown"]])(
    "rejects invalid selected set %j",
    async (...names) => {
      const f = await fixture();
      await expect(
        f.store.begin(
          "raw",
          { ...request, selectedStreams: names },
          declaration,
        ),
      ).rejects.toMatchObject({ code: "invalid_request" });
      expect(await f.db.query("SELECT * FROM runs")).toEqual([]);
    },
  );
});

it("normalizes raw evidence before run-end fences and rejects invented history", async () => {
  const f = await fixture();
  await f.store.begin(
    "raw",
    { ...request, selectedStreams: ["items"] },
    declaration,
  );
  await f.store.batch("raw", {
    batch: 0,
    records: [
      { stream: "items", op: "delete", data: { id: "a" } },
      { stream: "items", data: { id: "a" } },
    ],
  });
  const raw = {
    wireDialect: "connector-end-evidence/1",
    lastBatch: 0,
    selectedStreams: ["items"],
    done: { status: "succeeded" },
    errors: [],
    records: {
      items: {
        liveKeys: [["a"]],
        deletedKeys: [],
        everDeletedKeys: [["a"]],
        upsertEvents: 1,
        deleteEvents: 1,
      },
    },
    checkpoints: {},
    preflightExcludedStreams: [],
    detailCoverage: {},
    invalidDetailCoverageStreams: [],
    wholeStreamEvidence: [],
  };
  await expect(
    f.end.end("raw", {
      ...raw,
      records: { items: { ...raw.records.items, deleteEvents: 2 } },
    }),
  ).rejects.toMatchObject({ code: "invalid_request" });
  await expect(
    f.end.end("raw", { ...raw, lastBatch: -1 }),
  ).rejects.toMatchObject({ code: "batch_gap", nextBatch: 1 });
  expect(await f.end.end("raw", raw)).toMatchObject({
    outcome: "succeeded",
    coveredStreams: ["items"],
  });
  expect(
    await f.db.query("SELECT raw_end FROM runs WHERE run_id='raw'"),
  ).toEqual([{ raw_end: JSON.stringify(raw) }]);
  expect(await f.db.query("SELECT body FROM records")).toEqual([
    { body: '{"id":"a"}' },
  ]);
});

it.each([
  "independent",
  "parent",
  "refused",
  "seed",
  "generation",
  "refused-child",
] as const)(
  "raw partial finish preserves held cursors with %s safety",
  async (safety) => {
    const f = await fixture();
    const decl: IntakeDeclarations = {
      ...declaration,
      streams: [
        { name: "a", semantics: "mutable_state", primaryKey: ["id"] },
        {
          name: "b",
          semantics: "mutable_state",
          primaryKey: ["id"],
          ...(safety === "parent" || safety === "refused-child"
            ? { stateParents: ["a"] }
            : {}),
        },
      ],
    };
    await f.store.begin("initial", request, decl);
    await f.store.batch("initial", {
      batch: 0,
      records: [
        { stream: "a", data: { id: "one" } },
        { stream: "b", data: { id: "two" } },
      ],
    });
    await f.end.end(
      "initial",
      endRequest({
        lastBatch: 0,
        live: ["a", "b"],
        checkpoints: { a: "a0", b: "b0" },
      }),
    );
    await f.store.begin(
      "raw",
      { ...request, selectedStreams: ["a", "b"], observedAt: 50 },
      decl,
    );
    await f.store.batch("raw", {
      batch: 0,
      records: [{ stream: "a", data: { id: "one" } }],
    });
    if (safety === "refused")
      await f.db.batch([
        { sql: "UPDATE stream_state SET floor_version='99' WHERE stream='a'" },
      ]);
    if (safety === "refused-child")
      await f.db.batch([
        { sql: "UPDATE stream_state SET floor_version='99' WHERE stream='b'" },
      ]);
    if (safety === "seed")
      await f.db.batch([
        {
          sql: "UPDATE run_streams SET seed='unresolved' WHERE run_id='raw' AND stream='a'",
        },
      ]);
    if (safety === "generation")
      await f.db.batch([
        { sql: "UPDATE connections SET generation=generation+1" },
      ]);
    const result = await f.end.end("raw", {
      wireDialect: "connector-end-evidence/1",
      lastBatch: 0,
      selectedStreams: ["b", "a"],
      done: { status: "succeeded" },
      errors:
        safety === "refused-child"
          ? []
          : [
              {
                kind: "skip_result",
                scope: { kind: "stream", stream: "b" },
                code: "fixture_skip",
                recoveryHint: { retryable: true },
              },
            ],
      records: {
        a: {
          liveKeys: [["one"]],
          deletedKeys: [],
          everDeletedKeys: [],
          upsertEvents: 1,
          deleteEvents: 0,
        },
      },
      checkpoints: { a: "a1", b: "must-not-advance" },
      preflightExcludedStreams: [],
      detailCoverage: {},
      invalidDetailCoverageStreams: [],
      wholeStreamEvidence: [],
    });
    const stored = (
      await f.db.query<{ checkpoint: string | null }>(
        "SELECT checkpoint FROM connections",
      )
    )[0]!.checkpoint;
    if (safety === "generation") expect(stored).toBeNull();
    else
      expect(JSON.parse(stored!)).toEqual({
        a: safety === "independent" ? "a1" : "a0",
        b: "b0",
      });
    expect(result.streamStatus?.b).toBe("held");
    if (safety === "independent")
      expect(result).toMatchObject({
        outcome: "partial",
        coveredStreams: ["a"],
        streamStatus: { a: "succeeded", b: "held" },
      });
    if (safety === "refused") expect(result.coveredStreams).toEqual([]);
  },
);

it("an empty explicit selection is a no-op for declared stream state", async () => {
  const f = await fixture();
  await f.store.begin("initial", request, declaration);
  await f.store.batch("initial", {
    batch: 0,
    records: [{ stream: "items", data: { id: "one" } }],
  });
  await f.end.end(
    "initial",
    endRequest({
      lastBatch: 0,
      live: ["items"],
      checkpoints: { items: "old" },
    }),
  );
  const before = await f.db.query("SELECT * FROM stream_state");
  await f.store.begin(
    "noop",
    { ...request, observedAt: 60, selectedStreams: [] },
    declaration,
  );
  await expect(
    f.store.batch("noop", {
      batch: 0,
      records: [{ stream: "items", data: { id: "two" } }],
    }),
  ).rejects.toMatchObject({ code: "invalid_request" });
  const result = await f.end.end("noop", {
    wireDialect: "connector-end-evidence/1",
    lastBatch: -1,
    selectedStreams: [],
    done: { status: "succeeded" },
    errors: [],
    records: {},
    checkpoints: {},
    preflightExcludedStreams: [],
    detailCoverage: {},
    invalidDetailCoverageStreams: [],
    wholeStreamEvidence: [],
  });
  expect(result).toMatchObject({
    outcome: "succeeded",
    coveredStreams: [],
    streamStatus: {},
  });
  expect(await f.db.query("SELECT * FROM stream_state")).toEqual(before);
});
