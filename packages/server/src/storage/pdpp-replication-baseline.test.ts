import Database from "better-sqlite3";
import { afterEach, beforeEach, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import {
  canonicalJson,
  decodeReplicaEnvelope,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import { planReplicaMerge } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import {
  hasCompletionDependencies,
  selectStreamCompletion,
} from "@opendatalabs/personal-server-ts-core/replication/completion";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import {
  replicaOperationDigest,
  type ReplicaPageOptions,
  type ReplicaPage,
} from "./pdpp-replication-sqlite.js";
import { liveSnapshotDigest } from "./pdpp-stream-completion.js";

const sourceId = "https://source.invalid/declaration";
const at = "2026-10-20T00:00:00.000Z";
const declaration = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const config = {
  owner: "owner",
  declarations: [{ sourceId, binding: declaration }],
};
const envelope = (key: string, text = "old", instance = "conn_a") => ({
  instance,
  stream: "messages",
  key,
  data: { id: key, text },
  emitted_at: at,
});
const mergeContext = {
  ...config,
  declarations: [{ ...config.declarations[0], validateData: () => true }],
};
let directory: string;
let path: string;
let db: Database.Database;
let store: ReturnType<typeof createReplicaRecordStore>;
const register = (instance = "conn_a") =>
  store.registerConnection({
    instance,
    sourceId,
    method: "collector",
    label: "A",
  });
const ingest = (
  key: string,
  text = "old",
  instance = "conn_a",
  generation = 1,
) =>
  store.ingestBatch(
    [envelope(key, text, instance)],
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation },
  );
function drain(
  read: (options: ReplicaPageOptions) => ReplicaPage,
  limit = 100,
): ReplicaOperation[] {
  const operations: ReplicaOperation[] = [];
  let afterSequence: number | undefined;
  for (;;) {
    const page = read({ limit, afterSequence });
    operations.push(...page.operations);
    if (!page.hasMore) return operations;
    afterSequence = page.nextAfterSequence;
  }
}
const complete = () =>
  store.completeStreams(
    {
      instance: "conn_a",
      sourceId,
      method: "collector",
      generation: 1,
      sourceCollectedAt: at,
      collectionTimeBasis: "host_run_finished",
      streams: [
        {
          stream: "messages",
          coverage: "full_stream",
          liveCount: 1,
          snapshotSha256: liveSnapshotDigest(
            {
              sourceId,
              instance: "conn_a",
              method: "collector",
              generation: 1,
              stream: "messages",
            },
            ["id"],
            [
              {
                recordKey: "a",
                dataJson: JSON.stringify({ id: "a", text: "old" }),
              },
            ],
          ),
        },
      ],
    },
    () => ["id"],
  );
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "pdpp-baseline-"));
  path = join(directory, "db.sqlite");
  db = new Database(path);
  store = createReplicaRecordStore(db);
  register();
});
afterEach(() => {
  if (db.open) store.close();
  rmSync(directory, { recursive: true, force: true });
});

it("pins existing rows before admitting newer tail revisions and resumes the same fence", () => {
  ingest("a");
  const old = store.getRecord("conn_a", "messages", "a");
  const fence = store.replication.beginBaseline(config);
  expect(store.getRecord("conn_a", "messages", "a")).toEqual(old);
  ingest("a", "new");
  expect(store.replication.beginBaseline(config)).toEqual(fence);
  const baseline = drain(store.replication.readBaselinePage);
  const tail = drain(store.replication.readTailPage);
  expect(baseline.find((op) => op.kind === "upsert")).toMatchObject({
    data: { text: "old" },
  });
  expect(tail.find((op) => op.kind === "upsert")).toMatchObject({
    data: { text: "new" },
  });
  expect(tail[0].revision.counter).toBeGreaterThan(fence.watermark);
  expect(() =>
    store.replication.beginBaseline({ ...config, owner: "other" }),
  ).toThrow("immutable");
  expect(() =>
    store.replication.readTailPage({ afterSequence: 0, limit: 1 }),
  ).toThrow("watermark");
  for (const operations of [baseline, tail])
    decodeReplicaEnvelope(
      canonicalJson({
        format: "vana-pdpp-replica",
        version: 1,
        owner: "owner",
        batchId: "batch",
        operations,
      }),
      config,
    );
});

it("pages a large frozen baseline while another DB handle updates, deletes, replaces, resets and deletes connections", () => {
  register("conn_reset");
  register("conn_delete");
  store.ingestBatch(
    Array.from({ length: 1205 }, (_, i) => envelope(String(i))),
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  ingest("a", "old", "conn_reset");
  ingest("a", "old", "conn_delete");
  const fence = store.replication.beginBaseline(config);
  const first = store.replication.readBaselinePage({ limit: 37 });
  const second = createReplicaRecordStore(new Database(path));
  try {
    second.ingestBatch(
      [envelope("0", "new")],
      () => "mutable_state",
      () => ["id"],
      { method: "collector", generation: 1 },
    );
    second.deleteRecord("conn_a", "messages", "1", at, "mutable_state");
    second.replaceStream({
      instance: "conn_a",
      stream: "messages",
      method: "collector",
      generation: 1,
      emittedAt: at,
      envelopes: [envelope("0", "replacement"), envelope("fresh")],
      primaryKey: ["id"],
    });
    second.resetInstanceBinding({
      instance: "conn_reset",
      expectedMethod: "collector",
      expectedGeneration: 1,
      nextMethod: "collector",
    });
    second.deleteConnection("conn_delete");
  } finally {
    second.close();
  }
  let cursor = first.nextAfterSequence;
  const baseline = [...first.operations];
  while (true) {
    const page = store.replication.readBaselinePage({
      afterSequence: cursor,
      limit: 37,
    });
    baseline.push(...page.operations);
    cursor = page.nextAfterSequence;
    if (!page.hasMore) break;
  }
  expect(baseline.filter((op) => op.kind === "upsert")).toHaveLength(1207);
  expect(
    baseline
      .filter((op) => op.kind === "upsert")
      .every((op) => op.data.text === "old"),
  ).toBe(true);
  expect(new Set(baseline.map((op) => op.revision.operationId)).size).toBe(
    baseline.length,
  );
  const tail = drain(store.replication.readTailPage);
  expect(tail.filter((op) => op.kind === "delete")).toHaveLength(1204);
  expect(tail.every((op) => op.revision.counter > fence.watermark)).toBe(true);
  const expected = planReplicaMerge(mergeContext, [...baseline, ...tail]);
  for (const arrival of [
    [...tail, ...baseline],
    [...baseline, ...tail].reverse(),
    [...tail.slice(10), ...baseline, ...tail.slice(0, 10)],
  ])
    expect(planReplicaMerge(mergeContext, arrival)).toEqual(expected);
  expect(
    expected.records
      .filter((r) => r.winner?.kind === "upsert")
      .map((r) => r.identity.recordKey)
      .sort(),
  ).toEqual(["0", "fresh"]);
  expect(
    db
      .prepare(
        "SELECT COUNT(*) AS n FROM pdpp_record_changes WHERE instance IN ('conn_reset', 'conn_delete')",
      )
      .get(),
  ).toEqual({ n: 0 });
  expect(tail.map((op) => op.kind)).toContain("connection-reset");
  expect(tail.map((op) => op.kind)).toContain("connection-delete");
}, 60000);

it("makes a later upsert win in every permutation, including after an explicit replace deletion", () => {
  ingest("a");
  store.replication.beginBaseline(config);
  store.replaceStream({
    instance: "conn_a",
    stream: "messages",
    method: "collector",
    generation: 1,
    emittedAt: at,
    envelopes: [],
    primaryKey: ["id"],
  });
  ingest("a", "new");
  const operations = [
    ...drain(store.replication.readBaselinePage),
    ...drain(store.replication.readTailPage),
  ];
  function permutations<T>(xs: T[]): T[][] {
    return xs.length < 2
      ? [xs]
      : xs.flatMap((x, i) =>
          permutations(xs.filter((_, j) => i !== j)).map((tail) => [
            x,
            ...tail,
          ]),
        );
  }
  expect(operations).toHaveLength(4);
  for (const permutation of permutations(operations))
    expect(
      planReplicaMerge(mergeContext, permutation).records[0].winner,
    ).toMatchObject({ kind: "upsert", data: { text: "new" } });
});

it("captures blob claims idempotently and retains verified bytes after reset and deletion", () => {
  const bytes = new Uint8Array([1, 2, 3]);
  const blob = store.storeBlobBytesForInstance({
    instance: "conn_a",
    method: "collector",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  store.replication.beginBaseline(config);
  const before = drain(store.replication.readBaselinePage);
  expect(before.find((op) => op.kind === "blob-claim")).toMatchObject({
    blob: { blobId: blob.blobId },
  });
  store.storeBlobBytesForInstance({
    instance: "conn_a",
    method: "collector",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  expect(drain(store.replication.readTailPage)).toEqual([]);
  store.resetInstanceBinding({
    instance: "conn_a",
    expectedMethod: "collector",
    expectedGeneration: 1,
    nextMethod: "collector",
  });
  store.storeBlobBytesForInstance({
    instance: "conn_a",
    method: "collector",
    generation: 2,
    bytes,
    mimeType: "application/octet-stream",
  });
  store.deleteConnection("conn_a");
  expect(drain(store.replication.readTailPage).map((op) => op.kind)).toEqual([
    "connection-reset",
    "blob-claim",
    "connection-delete",
  ]);
  expect(store.getBlobBytes(blob.blobId)).toBeUndefined();
  expect(store.replication.readPinnedBlobBytes(blob.blobId)).toEqual(bytes);
  expect(drain(store.replication.readBaselinePage)).toEqual(before);
});

it("captures connection registration once and makes lifecycle retries inert", () => {
  store.replication.beginBaseline(config);
  register("conn_b");
  register("conn_b");
  store.resetInstanceBinding({
    instance: "conn_b",
    expectedMethod: "collector",
    expectedGeneration: 1,
    nextMethod: "collector",
  });
  store.resetInstanceBinding({
    instance: "conn_b",
    expectedMethod: "collector",
    expectedGeneration: 1,
    nextMethod: "collector",
  });
  store.deleteConnection("conn_b");
  store.deleteConnection("conn_b");
  expect(
    drain(store.replication.readTailPage).map((op) => [op.kind, op.generation]),
  ).toEqual([
    ["connection-register", 1],
    ["connection-reset", 2],
    ["connection-delete", 3],
  ]);
});

it.each(["baseline", "tail", "replace"])(
  "pins exact completion dependency IDs and digests for %s and rejects every partial set",
  async (mode) => {
    ingest("a");
    if (mode === "baseline") complete();
    store.replication.beginBaseline(config);
    if (mode === "tail") complete();
    if (mode === "replace")
      store.replaceStream({
        instance: "conn_a",
        stream: "messages",
        method: "collector",
        generation: 1,
        emittedAt: at,
        envelopes: [envelope("a")],
        primaryKey: ["id"],
        sourceCollectedAt: at,
      });
    const operations = [
      ...drain(store.replication.readBaselinePage),
      ...drain(store.replication.readTailPage),
    ];
    const completion = operations.find((op) => op.kind === "stream-complete")!;
    expect(completion).toBeDefined();
    const deps = operations.filter((op) => op.kind !== "stream-complete");
    expect(completion.dependencies).toEqual(
      deps.map((op) => ({
        writerId: op.revision.writerId,
        operationId: op.revision.operationId,
        digest: replicaOperationDigest(op),
      })),
    );
    expect(await hasCompletionDependencies(completion, deps)).toBe(true);
    for (const dep of deps)
      expect(
        await hasCompletionDependencies(
          completion,
          deps.filter((op) => op !== dep),
        ),
      ).toBe(false);
    const altered = structuredClone(deps);
    altered[0].methodId = "other";
    expect(await hasCompletionDependencies(completion, altered)).toBe(false);
    expect(
      await hasCompletionDependencies(completion, [...deps, ...altered]),
    ).toBe(false);
    if (mode !== "replace") {
      const before = drain(store.replication.readTailPage);
      complete();
      expect(drain(store.replication.readTailPage)).toEqual(before);
    }
  },
);

it("rolls back an unbound or unknown-declaration baseline and leaves local reads unchanged", () => {
  ingest("a");
  const before = store.getRecord("conn_a", "messages", "a");
  expect(() =>
    store.replication.beginBaseline({ ...config, declarations: [] }),
  ).toThrow("declaration");
  expect(db.prepare("SELECT * FROM pdpp_replica_settings").all()).toEqual([]);
  expect(db.prepare("SELECT * FROM pdpp_replica_operations").all()).toEqual([]);
  expect(db.prepare("SELECT counter FROM pdpp_replica_clock").get()).toEqual({
    counter: 0,
  });
  expect(store.getRecord("conn_a", "messages", "a")).toEqual(before);
  db.prepare(
    "INSERT INTO pdpp_records(instance, stream, record_key, data, version, emitted_at) VALUES ('orphan','messages','x','{}',1,?)",
  ).run(at);
  expect(() => store.replication.beginBaseline(config)).toThrow("unbound");
});

it("persists checkpoint progress only on explicit acknowledgment and survives reopen", () => {
  ingest("a");
  const fence = store.replication.beginBaseline(config);
  const first = store.replication.readBaselinePage({ limit: 1 });
  expect(store.replication.readBaselinePage({ limit: 1 })).toEqual(first);
  store.replication.acknowledgeBaselinePage(0, first.nextAfterSequence);
  store.replication.acknowledgeBaselinePage(0, first.nextAfterSequence);
  expect(() =>
    store.replication.acknowledgeBaselinePage(0, fence.watermark),
  ).toThrow("conflict");
  const next = store.replication.readBaselinePage({ limit: 1 });
  store.close();
  db = new Database(path);
  store = createReplicaRecordStore(db);
  expect(store.replication.beginBaseline(config)).toEqual(fence);
  expect(store.replication.readBaselinePage({ limit: 1 })).toEqual(next);
  store.replication.acknowledgeBaselinePage(
    first.nextAfterSequence,
    next.nextAfterSequence,
  );
  expect(store.replication.readBaselinePage({ limit: 1 }).operations).toEqual(
    [],
  );
});

it.each([
  "ingest",
  "record-delete",
  "replace",
  "reset",
  "delete",
  "register",
  "blob",
  "complete",
])(
  "rolls back canonical state, replica evidence and revision allocation on %s capture failure",
  (action) => {
    ingest("a");
    store.replication.beginBaseline(config);
    const tables = [
      "pdpp_records",
      "pdpp_record_changes",
      "pdpp_instance_binding",
      "pdpp_blob_claims",
      "pdpp_blobs",
      "pdpp_blob_bytes",
      "pdpp_stream_completion",
      "pdpp_record_arrival",
      "pdpp_record_arrival_clock",
      "pdpp_write_clock",
      "pdpp_replica_own_writes",
      "pdpp_replica_operations",
      "pdpp_replica_clock",
      "pdpp_replica_blob_bytes",
    ];
    const snapshot = () =>
      tables.map((table) => db.prepare(`SELECT * FROM ${table}`).all());
    const before = snapshot();
    db.exec(
      "CREATE TRIGGER fail_capture BEFORE INSERT ON pdpp_replica_operations BEGIN SELECT RAISE(ABORT, 'injected capture failure'); END;",
    );
    const actions = {
      ingest: () => ingest("a", "new"),
      "record-delete": () =>
        store.deleteRecord("conn_a", "messages", "a", at, "mutable_state"),
      replace: () =>
        store.replaceStream({
          instance: "conn_a",
          stream: "messages",
          method: "collector",
          generation: 1,
          emittedAt: at,
          envelopes: [],
          primaryKey: ["id"],
        }),
      reset: () =>
        store.resetInstanceBinding({
          instance: "conn_a",
          expectedMethod: "collector",
          expectedGeneration: 1,
          nextMethod: "collector",
        }),
      delete: () => store.deleteConnection("conn_a"),
      register: () => register("conn_b"),
      blob: () =>
        store.storeBlobBytesForInstance({
          instance: "conn_a",
          method: "collector",
          generation: 1,
          bytes: new Uint8Array([4]),
          mimeType: "x/test",
        }),
      complete,
    };
    expect(actions[action]).toThrow("injected capture failure");
    expect(snapshot()).toEqual(before);
  },
);

// SIGKILL bypasses finally/close: SQLite must recover the committed prefix from WAL.
it.each(
  [
    "baseline",
    "update",
    "replace",
    "reset",
    "delete",
    "register",
    "blob",
    "complete",
    "checkpoint",
  ].flatMap((action) =>
    [false, true].map((afterCommit) => ({ action, afterCommit })),
  ),
)(
  "recovers $action after SIGKILL (committed=$afterCommit)",
  ({ action, afterCommit }) => {
    ingest("a");
    if (action !== "baseline") store.replication.beginBaseline(config);
    const baselineBefore =
      action === "baseline" ? [] : drain(store.replication.readBaselinePage);
    const recordBefore = store.getRecord("conn_a", "messages", "a");
    store.close();
    const storeUrl = new URL(
      "./pdpp-replica-canonical-port.ts",
      import.meta.url,
    ).href;
    const completionUrl = new URL(
      "./pdpp-stream-completion.ts",
      import.meta.url,
    ).href;
    const triggerTable =
      action === "baseline" || action === "checkpoint"
        ? "pdpp_replica_settings"
        : "pdpp_replica_operations";
    const event =
      action === "baseline" || action === "checkpoint" ? "UPDATE" : "INSERT";
    const operations = {
      baseline: `store.replication.beginBaseline(${JSON.stringify(config)})`,
      update: `store.ingestBatch([${JSON.stringify(envelope("a", "new"))}], () => 'mutable_state', () => ['id'], {method:'collector',generation:1})`,
      replace: `store.replaceStream({instance:'conn_a',stream:'messages',method:'collector',generation:1,emittedAt:'${at}',envelopes:[],primaryKey:['id']})`,
      reset: `store.resetInstanceBinding({instance:'conn_a',expectedMethod:'collector',expectedGeneration:1,nextMethod:'collector'})`,
      delete: `store.deleteConnection('conn_a')`,
      register: `store.registerConnection({instance:'conn_b',sourceId:'${sourceId}',method:'collector',label:'B'})`,
      blob: `store.storeBlobBytesForInstance({instance:'conn_a',method:'collector',generation:1,bytes:new Uint8Array([4]),mimeType:'x/test'})`,
      complete: `store.completeStreams({instance:'conn_a',sourceId:'${sourceId}',method:'collector',generation:1,sourceCollectedAt:'${at}',collectionTimeBasis:'host_run_finished',streams:[{stream:'messages',coverage:'full_stream',liveCount:1,snapshotSha256:liveSnapshotDigest({sourceId:'${sourceId}',instance:'conn_a',method:'collector',generation:1,stream:'messages'},['id'],[{recordKey:'a',dataJson:'{"id":"a","text":"old"}'}])}]},()=>['id'])`,
      checkpoint: `store.replication.acknowledgeBaselinePage(0,1)`,
    };
    const code = `import Database from 'better-sqlite3'; import {createReplicaRecordStore} from '${storeUrl}'; import {liveSnapshotDigest} from '${completionUrl}'; const db = new Database(${JSON.stringify(path)}); const store = createReplicaRecordStore(db); db.function('crash',()=>process.kill(process.pid,'SIGKILL')); ${afterCommit ? "" : `db.exec("CREATE TEMP TRIGGER crash BEFORE ${event} ON ${triggerTable} BEGIN SELECT crash(); END;");`} ${operations[action as keyof typeof operations]}; process.kill(process.pid,'SIGKILL');`;
    const child = spawnSync(
      process.execPath,
      ["--import", "tsx", "--input-type=module", "-e", code],
      { encoding: "utf8", timeout: 15000 },
    );
    expect(child.stderr).toBe("");
    expect(child.signal).toBe("SIGKILL");
    db = new Database(path);
    store = createReplicaRecordStore(db);
    if (action === "baseline") {
      expect(
        db.prepare("SELECT COUNT(*) AS n FROM pdpp_replica_operations").get(),
      ).toEqual({ n: afterCommit ? 2 : 0 });
      expect(store.replication.beginBaseline(config).watermark).toBe(2);
    } else {
      expect(drain(store.replication.readBaselinePage, 100)).toEqual(
        action === "checkpoint" && afterCommit
          ? baselineBefore.slice(1)
          : baselineBefore,
      );
      const tail = drain(store.replication.readTailPage);
      expect(tail).toHaveLength(afterCommit && action !== "checkpoint" ? 1 : 0);
      if (!afterCommit)
        expect(store.getRecord("conn_a", "messages", "a")).toEqual(
          recordBefore,
        );
    }
  },
);

it("remains inert before enablement and rejects declaration mismatches atomically after the fence", () => {
  ingest("a");
  expect(db.prepare("SELECT * FROM pdpp_replica_operations").all()).toEqual([]);
  expect(() => store.replication.readBaselinePage({ limit: 1 })).toThrow(
    "required",
  );
  expect(() => store.replication.readTailPage({ limit: 1 })).toThrow(
    "required",
  );
  store.replication.beginBaseline(config);
  const before = store.getRecord("conn_a", "messages", "b");
  expect(() =>
    store.ingestBatch(
      [envelope("b")],
      () => "append_only",
      () => ["id"],
      { method: "collector", generation: 1 },
    ),
  ).toThrow("declaration mismatch");
  expect(store.getRecord("conn_a", "messages", "b")).toEqual(before);
  expect(drain(store.replication.readTailPage)).toEqual([]);
});

it("exports existing tombstones, empty completions, resets and deleted connections without changing query state", () => {
  ingest("a");
  store.deleteRecord("conn_a", "messages", "a", at, "mutable_state");
  register("conn_reset");
  store.resetInstanceBinding({
    instance: "conn_reset",
    expectedMethod: "collector",
    expectedGeneration: 1,
    nextMethod: "collector",
  });
  ingest("b", "old", "conn_reset", 2);
  register("conn_deleted");
  store.deleteConnection("conn_deleted");
  store.completeStreams(
    {
      instance: "conn_a",
      sourceId,
      method: "collector",
      generation: 1,
      sourceCollectedAt: at,
      collectionTimeBasis: "host_run_finished",
      streams: [
        {
          stream: "messages",
          coverage: "full_stream",
          liveCount: 0,
          snapshotSha256: liveSnapshotDigest(
            {
              sourceId,
              instance: "conn_a",
              method: "collector",
              generation: 1,
              stream: "messages",
            },
            ["id"],
            [],
          ),
        },
      ],
    },
    () => ["id"],
  );
  const tables = [
    "pdpp_records",
    "pdpp_record_changes",
    "pdpp_stream_completion",
    "pdpp_instance_binding",
    "pdpp_write_clock",
  ];
  const snapshot = () =>
    tables.map((table) => db.prepare(`SELECT * FROM ${table}`).all());
  const before = snapshot();
  store.replication.beginBaseline(config);
  expect(snapshot()).toEqual(before);
  const operations = drain(store.replication.readBaselinePage);
  expect(operations.find((op) => op.kind === "delete")).toMatchObject({
    recordKey: "a",
  });
  expect(operations.find((op) => op.kind === "stream-complete")).toMatchObject({
    liveCount: 0,
  });
  const plan = planReplicaMerge(mergeContext, operations.reverse());
  expect(
    plan.records.find((row) => row.identity.connectionId === "conn_reset")
      ?.winner,
  ).toMatchObject({ generation: 2, kind: "upsert" });
  expect(
    plan.suppressed.some((issue) => issue.reason === "connection_deleted"),
  ).toBe(true);
  expect(plan.pending).toEqual([]);
});

it("uses strict bounds and durable immutable operations on readonly reopen", () => {
  ingest("a");
  store.replication.beginBaseline(config);
  for (const limit of [0, -1, 1.5, NaN, Infinity, 1001])
    expect(() => store.replication.readBaselinePage({ limit })).toThrow(
      RangeError,
    );
  for (const afterSequence of [
    -1,
    0.5,
    NaN,
    Infinity,
    Number.MAX_SAFE_INTEGER + 1,
  ])
    expect(() =>
      store.replication.readBaselinePage({ limit: 1, afterSequence }),
    ).toThrow(RangeError);
  for (const sql of [
    "DELETE FROM pdpp_replica_operations",
    "UPDATE pdpp_replica_operations SET digest='x'",
    "INSERT OR REPLACE INTO pdpp_replica_operations SELECT * FROM pdpp_replica_operations",
  ])
    expect(() => db.exec(sql)).toThrow("append-only");
  const before = drain(store.replication.readBaselinePage);
  store.close();
  db = new Database(path, { readonly: true });
  store = createReplicaRecordStore(db);
  expect(drain(store.replication.readBaselinePage)).toEqual(before);
});

it("serializes baseline creation against another handle's attempted write at the fence", () => {
  ingest("a");
  const second = createReplicaRecordStore(new Database(path, { timeout: 1 }));
  let attempts = 0;
  try {
    db.function("attempt_tail", () => {
      attempts++;
      expect(() =>
        second.ingestBatch(
          [envelope("a", "during")],
          () => "mutable_state",
          () => ["id"],
          { method: "collector", generation: 1 },
        ),
      ).toThrow("locked");
      return 0;
    });
    db.exec(
      "CREATE TEMP TRIGGER fence_probe AFTER INSERT ON pdpp_replica_baseline BEGIN SELECT attempt_tail(); END;",
    );
    store.replication.beginBaseline(config);
    expect(attempts).toBe(2);
    second.ingestBatch(
      [envelope("a", "after")],
      () => "mutable_state",
      () => ["id"],
      { method: "collector", generation: 1 },
    );
    expect(
      drain(store.replication.readBaselinePage).find(
        (op) => op.kind === "upsert",
      ),
    ).toMatchObject({ data: { text: "old" } });
    expect(drain(store.replication.readTailPage)).toMatchObject([
      { kind: "upsert", data: { text: "after" } },
    ]);
  } finally {
    second.close();
  }
});

it("rolls back every stream receipt and dependency cut when the second completion capture fails", () => {
  ingest("a");
  store.ingestBatch(
    [{ ...envelope("b"), stream: "profiles" }],
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  const fence = store.replication.beginBaseline({
    ...config,
    declarations: [
      ...config.declarations,
      { sourceId, binding: { ...declaration, stream: "profiles" } },
    ],
  });
  db.exec(
    "CREATE TRIGGER second_completion BEFORE INSERT ON pdpp_replica_operations WHEN json_extract(NEW.operation_json, '$.kind') = 'stream-complete' AND json_extract(NEW.operation_json, '$.declaration.stream') = 'profiles' BEGIN SELECT RAISE(ABORT, 'second completion failed'); END;",
  );
  const proofs = [
    ["messages", "a"],
    ["profiles", "b"],
  ].map(([stream, key]) => ({
    stream,
    coverage: "full_stream" as const,
    liveCount: 1,
    snapshotSha256: liveSnapshotDigest(
      {
        sourceId,
        instance: "conn_a",
        method: "collector",
        generation: 1,
        stream,
      },
      ["id"],
      [{ recordKey: key, dataJson: JSON.stringify({ id: key, text: "old" }) }],
    ),
  }));
  expect(() =>
    store.completeStreams(
      {
        instance: "conn_a",
        sourceId,
        method: "collector",
        generation: 1,
        sourceCollectedAt: at,
        collectionTimeBasis: "host_run_finished",
        streams: proofs,
      },
      () => ["id"],
    ),
  ).toThrow("second completion failed");
  expect(store.listStreamCompletions("conn_a")).toEqual([]);
  expect(drain(store.replication.readTailPage)).toEqual([]);
  expect(db.prepare("SELECT counter FROM pdpp_replica_clock").get()).toEqual({
    counter: fence.watermark,
  });
});

it("captures full referenced blob descriptors and requires the claim in completion dependencies", async () => {
  store.replication.beginBaseline(config);
  const bytes = new Uint8Array([8, 9]);
  const blob = store.storeBlobBytesForInstance({
    instance: "conn_a",
    method: "collector",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  const value = {
    ...envelope("a"),
    data: {
      id: "a",
      blob_ref: {
        blob_id: blob.blobId,
        mime_type: blob.mimeType,
        size_bytes: 2,
      },
    },
  };
  store.replaceStream({
    instance: "conn_a",
    stream: "messages",
    method: "collector",
    generation: 1,
    emittedAt: at,
    envelopes: [value],
    primaryKey: ["id"],
    sourceCollectedAt: at,
  });
  const tail = drain(store.replication.readTailPage);
  expect(tail.find((op) => op.kind === "upsert")).toMatchObject({
    blobs: [
      {
        blobId: blob.blobId,
        sha256: `sha256:${blob.sha256}`,
        mimeType: blob.mimeType,
        sizeBytes: 2,
      },
    ],
  });
  const completion = tail.find((op) => op.kind === "stream-complete")!;
  const all = [...drain(store.replication.readBaselinePage), ...tail];
  expect(await hasCompletionDependencies(completion, all)).toBe(true);
  expect(
    await hasCompletionDependencies(
      completion,
      all.filter((op) => op.kind !== "blob-claim"),
    ),
  ).toBe(false);
  expect(store.replication.readPinnedBlobBytes(blob.blobId)).toEqual(bytes);
});

it("binds even empty-stream completion to the retained declaration during envelope decode", () => {
  store.replaceStream({
    instance: "conn_a",
    stream: "messages",
    method: "collector",
    generation: 1,
    emittedAt: at,
    envelopes: [],
    primaryKey: ["id"],
    sourceCollectedAt: at,
  });
  store.replication.beginBaseline(config);
  const encoded = canonicalJson({
    format: "vana-pdpp-replica",
    version: 1,
    owner: "owner",
    batchId: "empty",
    operations: drain(store.replication.readBaselinePage),
  });
  expect(() =>
    decodeReplicaEnvelope(encoded, { owner: "owner", declarations: [] }),
  ).toThrow("declaration binding mismatch");
  expect(decodeReplicaEnvelope(encoded, config).operations).toHaveLength(2);
});

it("exports a durable completion invalidation when unchanged replace drops the local receipt", () => {
  ingest("a");
  complete();
  store.replication.beginBaseline(config);
  store.replaceStream({
    instance: "conn_a",
    stream: "messages",
    method: "collector",
    generation: 1,
    emittedAt: at,
    envelopes: [envelope("a")],
    primaryKey: ["id"],
  });
  expect(store.listStreamCompletions("conn_a")).toEqual([]);
  const invalidation = drain(store.replication.readTailPage);
  expect(invalidation).toMatchObject([
    { kind: "stream-invalidate", declaration },
  ]);
  const before = drain(store.replication.readBaselinePage);
  const events = [...before, ...invalidation].filter(
    (op) => op.kind === "stream-complete" || op.kind === "stream-invalidate",
  );
  expect(selectStreamCompletion(events)).toBeNull();
  expect(selectStreamCompletion([...events].reverse())).toBeNull();
  expect(selectStreamCompletion([...events, ...events].reverse())).toBeNull();
  store.close();
  db = new Database(path);
  store = createReplicaRecordStore(db);
  expect(drain(store.replication.readTailPage)).toEqual(invalidation);
});

it("preserves native versus producer-asserted completion proof provenance", () => {
  ingest("a");
  complete();
  store.replication.beginBaseline(config);
  const native = drain(store.replication.readBaselinePage).find(
    (op) => op.kind === "stream-complete",
  )!;
  store.replaceStream({
    instance: "conn_a",
    stream: "messages",
    method: "collector",
    generation: 1,
    emittedAt: at,
    envelopes: [envelope("a")],
    primaryKey: ["id"],
    sourceCollectedAt: at,
  });
  const legacy = drain(store.replication.readTailPage).find(
    (op) => op.kind === "stream-complete",
  )!;
  expect(native).toMatchObject({
    proof: {
      kind: "native",
      collectionTimeBasis: "host_run_finished",
      snapshotSha256: native.snapshotSha256,
    },
  });
  expect(legacy).toMatchObject({
    proof: {
      kind: "producer-asserted",
      collectionTimeBasis: null,
      snapshotSha256: null,
    },
  });
  const merged = planReplicaMerge(mergeContext, [
    ...drain(store.replication.readBaselinePage),
    ...drain(store.replication.readTailPage),
  ]);
  expect(merged.records).toHaveLength(1);
  expect(merged.records[0].winner).toMatchObject({
    kind: "upsert",
    recordKey: "a",
    data: { id: "a", text: "old" },
  });
});

it("keeps canonical blob reference decisions unchanged during baseline and tail capture", () => {
  const refs = [
    undefined,
    null,
    0,
    false,
    "literal",
    [],
    {},
    { blob_id: null },
    { blob_id: 123 },
    { blob_id: "" },
  ];
  for (const [i, blob_ref] of refs.entries()) {
    const value = { ...envelope(String(i)), data: { id: String(i), blob_ref } };
    expect(
      store.ingestBatch(
        [value],
        () => "mutable_state",
        () => ["id"],
        { method: "collector", generation: 1 },
      ).accepted,
    ).toBe(1);
  }
  expect(() => store.replication.beginBaseline(config)).not.toThrow();
  for (const [i, blob_ref] of refs.entries()) {
    const value = {
      ...envelope(String(i)),
      data: { id: String(i), blob_ref, text: "new" },
    };
    expect(
      store.ingestBatch(
        [value],
        () => "mutable_state",
        () => ["id"],
        { method: "collector", generation: 1 },
      ).accepted,
    ).toBe(1);
    expect(store.getRecord("conn_a", "messages", String(i))).toMatchObject({
      data: JSON.parse(JSON.stringify(value.data)),
    });
  }
  const tail = drain(store.replication.readTailPage);
  expect(tail).toHaveLength(refs.length);
  expect(
    tail.every((op) => op.kind === "upsert" && op.blobs.length === 0),
  ).toBe(true);
  const unclaimed = {
    ...envelope("unclaimed"),
    data: { id: "unclaimed", blob_ref: { blob_id: "sha256:unclaimed" } },
  };
  expect(
    store.ingestBatch(
      [unclaimed],
      () => "mutable_state",
      () => ["id"],
      { method: "collector", generation: 1 },
    ).rejected,
  ).toHaveLength(1);
  expect(drain(store.replication.readTailPage)).toEqual(tail);
});

it("does not revive a matching old completion after changed-then-reverted data", () => {
  ingest("a");
  complete();
  store.replication.beginBaseline(config);
  const original = drain(store.replication.readBaselinePage).find(
    (op) => op.kind === "stream-complete",
  )!;
  ingest("a", "changed");
  ingest("a", "old");
  const events = () =>
    [
      ...drain(store.replication.readBaselinePage),
      ...drain(store.replication.readTailPage),
    ].filter(
      (op) => op.kind === "stream-complete" || op.kind === "stream-invalidate",
    );
  expect(selectStreamCompletion(events())).toBeNull();
  expect(selectStreamCompletion(events().reverse())).toBeNull();
  complete();
  const latest = selectStreamCompletion(events())!;
  expect(latest.snapshotSha256).toBe(original.snapshotSha256);
  expect(latest.revision.counter).toBeGreaterThan(original.revision.counter);
  expect(selectStreamCompletion(events().reverse())).toEqual(latest);
});
