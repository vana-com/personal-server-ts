import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import {
  CursorExpiredError,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import type { Grant } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { pdppRecordsRoutes } from "../routes/pdpp-records.js";
import { pdppBlobsRoutes } from "../routes/pdpp-blobs.js";
import { liveSnapshotDigest } from "./pdpp-stream-completion.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import { createReplicaVisibilityView } from "./pdpp-replica-visibility-view.js";
import { binaryWriter, deleteBinary } from "./pdpp-binary-chunks.js";

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
const config = { owner: "owner", declarations: [{ sourceId, binding }] };
const declarations: MergeContext["declarations"] = [
  { sourceId, binding, validateData: (data) => typeof data.id === "string" },
];
const directories: string[] = [];
const devices: ReturnType<typeof device>[] = [];
function device(
  registered = true,
  entries = declarations,
  /** The bindings it writes under; it trusts every one of `entries`. */
  current = entries,
) {
  const directory = mkdtempSync(join(tmpdir(), "pdpp-receiver-"));
  directories.push(directory);
  const path = join(directory, "db.sqlite");
  let db = new Database(path);
  let store = createReplicaRecordStore(db);
  if (registered)
    store.registerConnection({
      instance: "conn_a",
      sourceId,
      method: "collector",
      label: "A",
    });
  store.replication.beginBaseline({
    ...config,
    declarations: current.map(({ sourceId, binding }) => ({
      sourceId,
      binding,
    })),
  });
  let known = entries;
  const receiver = () =>
    createReplicaReceiver({
      db,
      store,
      owner: "owner",
      authenticate: (credential: unknown) =>
        credential === "replica-secret" ? "owner" : undefined,
      declarations: () => known,
    });
  const result = {
    path,
    get db() {
      return db;
    },
    get store() {
      return store;
    },
    get receiver() {
      return receiver();
    },
    declare(entries: MergeContext["declarations"]) {
      known = entries;
    },
    reopen() {
      if (db.open) store.close();
      db = new Database(path);
      store = createReplicaRecordStore(db);
    },
    close() {
      if (db.open) store.close();
    },
  };
  devices.push(result);
  return result;
}
afterEach(() => {
  for (const d of devices.splice(0)) d.close();
  for (const path of directories.splice(0))
    rmSync(path, { recursive: true, force: true });
});
function batch(operations: ReplicaOperation[], owner = "owner") {
  return {
    format: "vana-pdpp-replica",
    version: 1,
    owner,
    batchId: "test-batch",
    operations,
  };
}
function send(d: ReturnType<typeof device>, operations: ReplicaOperation[]) {
  return d.receiver.import({
    credential: "replica-secret",
    envelope: batch(operations),
  });
}
function all(d: ReturnType<typeof device>) {
  return [
    ...d.store.replication.readBaselinePage({ limit: 1000 }).operations,
    ...d.store.replication.readTailPage({ limit: 1000 }).operations,
  ];
}
function put(d: ReturnType<typeof device>, text: string) {
  d.store.ingestBatch(
    [
      {
        instance: "conn_a",
        stream: "messages",
        key: "a",
        data: { id: "a", text },
        emitted_at: at,
      },
    ],
    () => binding.semantics,
    () => ["id"],
    { method: "collector", generation: 1 },
  );
}
const value = (d: ReturnType<typeof device>) =>
  d.store.getRecord("conn_a", "messages", "a");
const upsert = (counter = 20): ReplicaOperation => ({
  kind: "upsert",
  owner: "owner",
  sourceId,
  connectionId: "conn_a",
  methodId: "collector",
  generation: 1,
  revision: { counter, writerId: "remote", operationId: `op-${counter}` },
  declaration: binding,
  recordKey: "a",
  emittedAt: at,
  data: { id: "a", text: `remote-${counter}` },
  blobs: [],
});
const registration = (): ReplicaOperation => ({
  kind: "connection-register",
  owner: "owner",
  sourceId,
  connectionId: "conn_a",
  methodId: "collector",
  generation: 1,
  revision: { counter: 1, writerId: "remote", operationId: "register" },
});

it("converges two fresh SQLite devices under reversed bidirectional delivery without echo", () => {
  const a = device(),
    b = device();
  put(a, "from-a");
  put(b, "from-b");
  const fromA = all(a),
    fromB = all(b);
  const journalA = a.db.prepare("SELECT * FROM pdpp_replica_own_writes").all();
  const journalB = b.db.prepare("SELECT * FROM pdpp_replica_own_writes").all();
  send(a, [...fromB].reverse());
  send(b, [...fromA].reverse());
  expect(value(a)?.data).toEqual(value(b)?.data);
  expect(a.db.prepare("SELECT * FROM pdpp_replica_own_writes").all()).toEqual(
    journalA,
  );
  expect(b.db.prepare("SELECT * FROM pdpp_replica_own_writes").all()).toEqual(
    journalB,
  );
  const retained = b.db
    .prepare("SELECT operation_json FROM pdpp_replica_received")
    .all() as { operation_json: string }[];
  expect(
    retained
      .map((row) => JSON.parse(row.operation_json))
      .sort((x, y) => x.revision.counter - y.revision.counter),
  ).toEqual([...fromA].sort((x, y) => x.revision.counter - y.revision.counter));
  expect(a.store.replication.readTailPage({ limit: 100 }).operations).toEqual(
    fromA.filter((op) => op.kind !== "connection-register"),
  );
  expect(b.store.replication.readTailPage({ limit: 100 }).operations).toEqual(
    fromB.filter((op) => op.kind !== "connection-register"),
  );
  const history = b.db.prepare("SELECT * FROM pdpp_record_changes").all();
  send(b, fromA);
  b.reopen();
  send(b, fromA);
  expect(b.db.prepare("SELECT * FROM pdpp_record_changes").all()).toEqual(
    history,
  );
  expect(value(a)?.data).toEqual(value(b)?.data);
});

it("retains absent predecessor and declaration dependencies across restart", () => {
  const d = device(true, []);
  expect(send(d, [upsert()]).pending.length).toBeGreaterThan(0);
  expect(value(d)).toBeUndefined();
  d.reopen();
  d.declare(declarations);
  d.receiver.retry({ credential: "replica-secret" });
  expect(value(d)?.data).toEqual({ id: "a", text: "remote-20" });
  expect(d.store.replication.readTailPage({ limit: 100 }).operations).toEqual(
    [],
  );
});

it("retains missing local mapping and never creates authority from imported registration", () => {
  const d = device(false);
  expect(send(d, [registration(), upsert()]).pending.length).toBeGreaterThan(0);
  expect(value(d)).toBeUndefined();
  d.reopen();
  expect(value(d)).toBeUndefined();
  d.store.registerConnection({
    instance: "conn_a",
    sourceId,
    method: "collector",
    label: "A",
  });
  d.receiver.retry({ credential: "replica-secret" });
  expect(value(d)?.data).toEqual({ id: "a", text: "remote-20" });
});

it.each(["collector-secret", undefined, { owner: "owner", replication: true }])(
  "rejects non-replica credential %j",
  (credential) => {
    const d = device();
    expect(() =>
      d.receiver.import({ credential, envelope: batch([upsert()]) }),
    ).toThrow();
    expect(value(d)).toBeUndefined();
  },
);

it("rejects cross-owner replay and a mismatched method without changing canonical data", () => {
  const d = device();
  expect(() =>
    d.receiver.import({
      credential: "replica-secret",
      envelope: batch([upsert()], "someone-else"),
    }),
  ).toThrow();
  expect(() =>
    d.receiver.import({
      credential: "replica-secret",
      envelope: batch([{ ...upsert(), owner: "someone-else" }]),
    }),
  ).toThrow();
  expect(() => send(d, [{ ...upsert(), methodId: "other" }])).toThrow();
  expect(value(d)).toBeUndefined();
});

it("applies tombstones and later resurrection under reordered batches", () => {
  const d = device();
  const original = upsert(20);
  const deletion: ReplicaOperation = {
    ...original,
    kind: "delete",
    revision: { counter: 21, writerId: "remote", operationId: "delete" },
    deletedAt: at,
  };
  // The strict wire contract cannot carry upsert-only fields on a tombstone.
  delete (deletion as unknown as Record<string, unknown>).data;
  delete (deletion as unknown as Record<string, unknown>).blobs;
  send(d, [deletion]);
  send(d, [original]);
  expect(value(d)).toBeUndefined();
  send(d, [upsert(22)]);
  expect(value(d)?.data.text).toBe("remote-22");
  expect(d.store.replication.readTailPage({ limit: 100 }).operations).toEqual(
    [],
  );
});

it("keeps future generations pending until reset evidence and suppresses old generations", () => {
  const d = device();
  const future = { ...upsert(20), generation: 3 };
  expect(send(d, [future]).pending.length).toBeGreaterThan(0);
  d.reopen();
  const reset = (generation: number): ReplicaOperation => ({
    kind: "connection-reset",
    owner: "owner",
    sourceId,
    connectionId: "conn_a",
    methodId: "collector",
    generation,
    previousGeneration: generation - 1,
    revision: {
      counter: generation,
      writerId: "remote",
      operationId: `reset-${generation}`,
    },
  });
  expect(send(d, [reset(3)]).pending.length).toBeGreaterThan(0);
  send(d, [reset(2)]);
  expect(value(d)?.data.text).toBe("remote-20");
  send(d, [upsert(100)]);
  expect(value(d)?.data.text).toBe("remote-20");
});

it("requires verified claimed blob bytes before exposing an imported record", async () => {
  const source = device(),
    target = device();
  const bytes = new Uint8Array([8, 9]);
  const blob = source.store.storeBlobBytesForInstance({
    instance: "conn_a",
    method: "collector",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  source.store.ingestBatch(
    [
      {
        instance: "conn_a",
        stream: "messages",
        key: "a",
        emitted_at: at,
        data: {
          id: "a",
          blob_ref: {
            blob_id: blob.blobId,
            mime_type: blob.mimeType,
            size_bytes: 2,
          },
        },
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  const operations = all(source);
  const record = operations.filter((op) => op.kind === "upsert");
  expect(send(target, record).pending.length).toBeGreaterThan(0);
  expect(value(target)).toBeUndefined();
  const claimless = device();
  expect(
    claimless.receiver.import({
      credential: "replica-secret",
      envelope: batch(record),
      blobs: [{ blobId: blob.blobId, bytes }],
    }).pending.length,
  ).toBeGreaterThan(0);
  expect(value(target)).toBeUndefined();
  expect(value(claimless)).toBeUndefined();
  expect(send(target, operations).pending.length).toBeGreaterThan(0);
  expect(value(target)).toBeUndefined();
  target.reopen();
  expect(() =>
    target.receiver.import({
      credential: "replica-secret",
      envelope: batch(operations),
      blobs: [{ blobId: blob.blobId, bytes: new Uint8Array([1, 2]) }],
    }),
  ).toThrow();
  expect(value(target)).toBeUndefined();
  target.receiver.import({
    credential: "replica-secret",
    envelope: batch(operations),
    blobs: [{ blobId: blob.blobId, bytes }],
  });
  expect(value(target)?.data.id).toBe("a");
  expect(target.store.getBlobBytes(blob.blobId)).toEqual(bytes);
  const grant: Grant = {
    version: "0.2.0",
    grant_id: "blob-grant",
    issued_at: at,
    subject: { id: "owner" },
    client: { client_id: "client" },
    source: { kind: "provider_native", id: sourceId },
    source_declaration: { version: "1" },
    purpose_code: "test",
    access_mode: "continuous",
    streams: [
      { name: "messages", instance_ids: ["conn_a"], fields: ["blob_ref"] },
    ],
  };
  const blobs = pdppBlobsRoutes({
    store: target.store,
    auth: createFixtureAuthorizationService({
      client: {
        active: true,
        tokenKind: "client",
        subjectId: "owner",
        clientId: "client",
        grant,
      },
    }),
    declarations: createStreamDeclarationRegistry([
      {
        name: "messages",
        semantics: "mutable_state",
        primaryKey: ["id"],
        cursorField: "emitted_at",
        requiredFields: ["id"],
        declaredFields: ["id", "blob_ref"],
      },
    ]),
    instancesForSubject: () => ["conn_a"],
    readBlobBytes: async (id) => {
      const stored = target.store.getBlobBytes(id);
      return stored ? new Uint8Array(stored) : undefined;
    },
  });
  const response = await blobs.request(`/${blob.blobId}`, {
    headers: { Authorization: "Bearer client" },
  });
  expect(response.status).toBe(200);
  expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes);
  expect((await blobs.request(`/${blob.blobId}`)).status).toBe(401);

  expect(
    target.store.replication.readTailPage({ limit: 100 }).operations,
  ).toEqual([]);
});

it("quarantines append-only conflicting content instead of selecting a winner", () => {
  const appendBinding = { ...binding, semantics: "append_only" as const };
  const entries = [
    { sourceId, binding: appendBinding, validateData: () => true },
  ];
  const d = device(true, entries);
  const first = { ...upsert(20), declaration: appendBinding };
  const second = { ...upsert(21), declaration: appendBinding };
  send(d, [first]);
  expect(value(d)?.data.text).toBe("remote-20");
  const plan = send(d, [second]);
  expect(
    plan.conflicts.some(
      (issue) => issue.reason === "append_only_content_conflict",
    ),
  ).toBe(true);
  expect(value(d)).toBeUndefined();
  d.reopen();
  send(d, [first]);
  expect(value(d)).toBeUndefined();
});

it("rolls back imported evidence when canonical merge fails then safely retries", () => {
  const d = device();
  d.db.exec(
    "CREATE TEMP TRIGGER fail_merge BEFORE INSERT ON pdpp_records BEGIN SELECT RAISE(ABORT, 'injected merge failure'); END",
  );
  expect(() => send(d, [upsert()])).toThrow("injected merge failure");
  expect(value(d)).toBeUndefined();
  d.reopen();
  send(d, [upsert()]);
  expect(value(d)?.data.text).toBe("remote-20");
  const before = d.db.prepare("SELECT * FROM pdpp_record_changes").all();
  // Simulate losing the acknowledgement by reopening immediately after commit.
  d.reopen();
  send(d, [upsert()]);
  expect(d.db.prepare("SELECT * FROM pdpp_record_changes").all()).toEqual(
    before,
  );
  expect(d.store.replication.readTailPage({ limit: 100 }).operations).toEqual(
    [],
  );
});

it("rejects invalid schema data and record keys before touching canonical rows", () => {
  const d = device();
  for (const op of [
    { ...upsert(), data: { id: 7 } },
    { ...upsert(21), recordKey: "different" },
  ]) {
    expect(
      send(d, [op]).rejected.some(
        (issue) => issue.reason === "invalid_record_data",
      ),
    ).toBe(true);
    expect(value(d)).toBeUndefined();
  }
});

it("connection deletion dominates reordered record imports and survives restart", () => {
  const d = device();
  send(d, [upsert()]);
  expect(value(d)?.data.text).toBe("remote-20");
  const deletion: ReplicaOperation = {
    ...registration(),
    kind: "connection-delete",
    generation: 2,
    revision: {
      counter: 30,
      writerId: "remote",
      operationId: "connection-delete",
    },
  };
  send(d, [deletion]);
  expect(value(d)).toBeUndefined();
  d.reopen();
  send(d, [upsert(100)]);
  expect(value(d)).toBeUndefined();
});

it("detects operation-ID equivocation instead of silently replacing evidence", () => {
  const d = device();
  const first = upsert();
  send(d, [first]);
  const plan = send(d, [{ ...first, data: { id: "a", text: "equivocated" } }]);
  expect(
    plan.conflicts.some(
      (issue) => issue.reason === "operation_id_equivocation",
    ),
  ).toBe(true);
  expect(value(d)).toBeUndefined();
  d.reopen();
  expect(
    send(d, [first]).conflicts.some(
      (issue) => issue.reason === "operation_id_equivocation",
    ),
  ).toBe(true);
  const outbound = all(d);
  expect(() => put(d, "collector-cannot-repair")).toThrow(
    "replica_integrity_quarantine",
  );
  expect(value(d)).toBeUndefined();
  expect(all(d)).toEqual(outbound);
});

it("advances the local Lamport clock beyond observed imported revisions", () => {
  const d = device();
  send(d, [upsert(1000)]);
  put(d, "new-local");
  const tail = d.store.replication.readTailPage({ limit: 100 }).operations;
  const local = tail.find((op) => op.kind === "upsert");
  expect(local?.revision.counter).toBeGreaterThan(1000);
  expect(local?.revision.writerId).not.toBe("remote");
  expect(value(d)?.data.text).toBe("new-local");
});

it("serves imported canonical records through the existing grant-relative HTTP read and authorization path", async () => {
  const d = device();
  send(d, [upsert()]);
  const grant: Grant = {
    version: "0.2.0",
    grant_id: "replica-read",
    issued_at: at,
    subject: { id: "owner" },
    client: { client_id: "client" },
    source: { kind: "provider_native", id: sourceId },
    source_declaration: { version: "1" },
    purpose_code: "test",
    access_mode: "continuous",
    streams: [{ name: "messages", instance_ids: ["conn_a"], fields: ["text"] }],
  };
  const app = pdppRecordsRoutes({
    store: d.store,
    auth: createFixtureAuthorizationService({
      client: {
        active: true,
        tokenKind: "client",
        subjectId: "owner",
        clientId: "client",
        grant,
      },
    }),
    declarations: createStreamDeclarationRegistry([
      {
        name: "messages",
        semantics: "mutable_state",
        primaryKey: ["id"],
        cursorField: "emitted_at",
        requiredFields: ["id"],
        declaredFields: ["id", "text"],
      },
    ]),
    instancesForSubject: () => ["conn_a"],
  });
  const response = await app.request("/streams/messages/records", {
    headers: { Authorization: "Bearer client" },
  });
  expect(response.status).toBe(200);
  const body = await response.json();
  expect(JSON.stringify(body)).toContain("remote-20");
  const denied = await app.request("/streams/messages/records");
  expect(denied.status).toBe(401);
  const restricted = pdppRecordsRoutes({
    store: d.store,
    auth: createFixtureAuthorizationService({
      client: {
        active: true,
        tokenKind: "client",
        subjectId: "owner",
        clientId: "client",
        grant: { ...grant, streams: [] },
      },
    }),
    declarations: createStreamDeclarationRegistry([]),
    instancesForSubject: () => ["conn_a"],
  });
  expect(
    (
      await restricted.request("/streams/messages/records", {
        headers: { Authorization: "Bearer client" },
      })
    ).status,
  ).not.toBe(200);
});

it.each([false, true])(
  "recovers a process crash around canonical commit (committed=%s)",
  (afterCommit) => {
    const d = device();
    // Initialize receiver schema before opening the independent process.
    d.receiver.retry({ credential: "replica-secret" });
    d.close();
    const storeUrl = new URL(
      "./pdpp-replica-canonical-port.ts",
      import.meta.url,
    ).href;
    const receiverUrl = new URL(
      "./pdpp-replication-receiver.ts",
      import.meta.url,
    ).href;
    const code = `import Database from 'better-sqlite3'; import {createReplicaRecordStore} from '${storeUrl}'; import {createReplicaReceiver} from '${receiverUrl}'; const db=new Database(${JSON.stringify(d.path)}); const store=createReplicaRecordStore(db); const receiver=createReplicaReceiver({db,store,owner:'owner',authenticate:()=> 'owner',declarations:()=>[{sourceId:${JSON.stringify(sourceId)},binding:${JSON.stringify(binding)},validateData:()=>true}]}); db.function('crash',()=>process.kill(process.pid,'SIGKILL')); ${afterCommit ? "" : 'db.exec("CREATE TEMP TRIGGER crash BEFORE INSERT ON pdpp_records BEGIN SELECT crash(); END");'} receiver.import({credential:'replica-secret',envelope:${JSON.stringify(batch([upsert()]))}}); process.kill(process.pid,'SIGKILL');`;
    const child = spawnSync(
      process.execPath,
      ["--import", "tsx", "--input-type=module", "-e", code],
      { encoding: "utf8", timeout: 15000 },
    );
    expect(child.stderr).toBe("");
    expect(child.signal).toBe("SIGKILL");
    d.reopen();
    expect(value(d)?.data.text).toBe(afterCommit ? "remote-20" : undefined);
    const before = d.db.prepare("SELECT * FROM pdpp_record_changes").all();
    send(d, [upsert()]);
    expect(value(d)?.data.text).toBe("remote-20");
    if (afterCommit)
      expect(d.db.prepare("SELECT * FROM pdpp_record_changes").all()).toEqual(
        before,
      );
    expect(d.store.replication.readTailPage({ limit: 100 }).operations).toEqual(
      [],
    );
  },
);

it("holds completion until its exact record dependencies arrive across restart", () => {
  const source = device(),
    target = device();
  source.store.replaceStream({
    instance: "conn_a",
    stream: "messages",
    method: "collector",
    generation: 1,
    emittedAt: at,
    envelopes: [
      {
        instance: "conn_a",
        stream: "messages",
        key: "a",
        data: { id: "a", text: "snapshot" },
        emitted_at: at,
      },
    ],
    primaryKey: ["id"],
    sourceCollectedAt: at,
  });
  const operations = all(source);
  const completion = operations.find((op) => op.kind === "stream-complete")!;
  expect(completion).toBeDefined();
  send(target, [completion]);
  expect(target.store.listStreamCompletions("conn_a")).toEqual([]);
  target.reopen();
  send(
    target,
    operations.filter((op) => op.kind !== "stream-complete").reverse(),
  );
  expect(target.store.listStreamCompletions("conn_a")).toHaveLength(1);
  expect(value(target)?.data.text).toBe("snapshot");
  expect(
    target.store.replication.readTailPage({ limit: 100 }).operations,
  ).toEqual([]);
});

it("requires replica authority on retry and rejects a mapping with a different source", () => {
  const d = device();
  send(d, [upsert()]);
  expect(() => d.receiver.retry({ credential: "collector-secret" })).toThrow();
  expect(() =>
    send(d, [{ ...upsert(21), sourceId: "https://other.invalid/source" }]),
  ).toThrow();
  expect(value(d)?.data.text).toBe("remote-20");
});

it("requires an established baseline for the same verified owner", () => {
  const d = device();
  const other = createReplicaReceiver({
    db: d.db,
    store: d.store,
    owner: "someone-else",
    authenticate: () => "someone-else",
    declarations: () => declarations,
  });
  expect(() =>
    other.import({
      credential: "valid-other-replica",
      envelope: batch([{ ...upsert(), owner: "someone-else" }], "someone-else"),
    }),
  ).toThrow("baseline");
  expect(value(d)).toBeUndefined();
});

it("does not let a local collector restore an append-only quarantined record, including after restart", () => {
  const appendBinding = { ...binding, semantics: "append_only" as const };
  const d = device(true, [
    { sourceId, binding: appendBinding, validateData: () => true },
  ]);
  send(d, [
    { ...upsert(20), declaration: appendBinding },
    { ...upsert(21), declaration: appendBinding },
  ]);
  expect(value(d)).toBeUndefined();
  const before = d.db.prepare("SELECT * FROM pdpp_replica_own_writes").all();
  const outbound = d.store.replication.readTailPage({ limit: 100 }).operations;
  for (const restart of [false, true]) {
    if (restart) d.reopen();
    try {
      d.store.ingestBatch(
        [
          {
            instance: "conn_a",
            stream: "messages",
            key: "a",
            data: { id: "a", text: "collector-repair" },
            emitted_at: at,
          },
        ],
        () => "append_only",
        () => ["id"],
        { method: "collector", generation: 1 },
      );
    } catch {
      // Refusing a local write is an acceptable enforcement of quarantine.
    }
    expect(value(d)).toBeUndefined();
    expect(d.db.prepare("SELECT * FROM pdpp_replica_own_writes").all()).toEqual(
      before,
    );
    expect(d.store.replication.readTailPage({ limit: 100 }).operations).toEqual(
      outbound,
    );
  }
});

it("keeps a committed completion receipt unchanged when replay follows unrelated local writes", () => {
  const source = device(),
    target = device();
  source.store.replaceStream({
    instance: "conn_a",
    stream: "messages",
    method: "collector",
    generation: 1,
    emittedAt: at,
    envelopes: [
      {
        instance: "conn_a",
        stream: "messages",
        key: "a",
        data: { id: "a", text: "snapshot" },
        emitted_at: at,
      },
    ],
    primaryKey: ["id"],
    sourceCollectedAt: at,
  });
  const operations = all(source);
  send(target, operations);
  const before = target.store.listStreamCompletions("conn_a");
  expect(before).toHaveLength(1);
  target.store.registerConnection({
    instance: "conn_unrelated",
    sourceId,
    method: "collector",
    label: "Unrelated",
  });
  target.store.ingestBatch(
    [
      {
        instance: "conn_unrelated",
        stream: "messages",
        key: "other",
        data: { id: "other", text: "unrelated" },
        emitted_at: at,
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  send(target, operations);
  expect(target.store.listStreamCompletions("conn_a")).toEqual(before);
  target.reopen();
  send(target, operations);
  expect(target.store.listStreamCompletions("conn_a")).toEqual(before);
});

it("does not expose a pending record when persisted received blob bytes are corrupt after restart", () => {
  const source = device(),
    target = device();
  const bytes = new Uint8Array([8, 9]);
  const blob = source.store.storeBlobBytesForInstance({
    instance: "conn_a",
    method: "collector",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  source.store.ingestBatch(
    [
      {
        instance: "conn_a",
        stream: "messages",
        key: "a",
        data: {
          id: "a",
          blob_ref: {
            blob_id: blob.blobId,
            mime_type: blob.mimeType,
            size_bytes: 2,
          },
        },
        emitted_at: at,
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  send(target, all(source));
  target.db
    .prepare(
      "INSERT INTO pdpp_replica_received_bytes (blob_id, bytes) VALUES (?, ?)",
    )
    .run(blob.blobId, new Uint8Array([1, 2]));
  target.reopen();
  const plan = target.receiver.retry({ credential: "replica-secret" });
  expect(plan.pending.length).toBeGreaterThan(0);
  expect(value(target)).toBeUndefined();
  expect(target.store.getBlobBytes(blob.blobId)).toBeUndefined();
  expect(
    target.store.replication.readTailPage({ limit: 100 }).operations,
  ).toEqual([]);
});

function completedReplica() {
  const source = device();
  source.store.replaceStream({
    instance: "conn_a",
    stream: "messages",
    method: "collector",
    generation: 1,
    emittedAt: at,
    envelopes: [
      {
        instance: "conn_a",
        stream: "messages",
        key: "a",
        data: { id: "a", text: "snapshot" },
        emitted_at: at,
      },
    ],
    primaryKey: ["id"],
    sourceCollectedAt: at,
  });
  return all(source);
}

it("keeps unknown-declaration invalidation pending without erasing a trusted completion", () => {
  const d = device();
  send(d, completedReplica());
  const receipt = d.store.listStreamCompletions("conn_a");
  expect(receipt).toHaveLength(1);
  const invalidation: ReplicaOperation = {
    ...registration(),
    kind: "stream-invalidate",
    revision: { counter: 100, writerId: "unknown", operationId: "invalidate" },
    declaration: { ...binding, digest: `sha256:${"c".repeat(64)}` },
  };
  const plan = send(d, [invalidation]);
  expect(
    plan.pending.some((issue) => issue.reason === "missing_declaration"),
  ).toBe(true);
  expect(d.store.listStreamCompletions("conn_a")).toEqual(receipt);
  d.reopen();
  d.receiver.retry({ credential: "replica-secret" });
  expect(d.store.listStreamCompletions("conn_a")).toEqual(receipt);
});

it("makes competing known declaration shapes unavailable instead of overwriting one by iteration order", () => {
  const operations = completedReplica();
  const d = device();
  send(d, operations);
  // Another shape of the stream (its semantics), not another version.
  const competing = {
    ...binding,
    digest: `sha256:${"c".repeat(64)}`,
    semantics: "append_only" as const,
  };
  d.declare([
    ...declarations,
    { sourceId, binding: competing, validateData: () => true },
  ]);
  const second = operations
    .filter((op) => op.kind === "upsert" || op.kind === "stream-complete")
    .map((op) => ({
      ...op,
      declaration: competing,
      revision: {
        ...op.revision,
        writerId: "competing",
        operationId: `competing-${op.revision.operationId}`,
      },
    }));
  send(d, second);
  expect(value(d)).toBeUndefined();
  expect(d.store.listStreamCompletions("conn_a")).toEqual([]);
});

it("takes a newer version's records and completion after a peer rebinds the stream", () => {
  const source = device();
  const replace = (text: string) =>
    source.store.replaceStream({
      instance: "conn_a",
      stream: "messages",
      method: "collector",
      generation: 1,
      emittedAt: at,
      envelopes: [
        {
          instance: "conn_a",
          stream: "messages",
          key: "a",
          data: { id: "a", text },
          emitted_at: at,
        },
      ],
      primaryKey: ["id"],
      sourceCollectedAt: at,
    });
  replace("snapshot");
  const before = all(source);
  const upgraded = {
    ...binding,
    digest: `sha256:${"c".repeat(64)}`,
    version: "2",
  };
  source.store.replication.beginBaseline({
    owner: "owner",
    declarations: [{ sourceId, binding: upgraded }],
  });
  replace("upgraded");
  const after = all(source).slice(before.length);
  // The rebinding journaled nothing; the new writes name the new version.
  const versions = after.flatMap((op) =>
    "declaration" in op ? [op.declaration.version] : [],
  );
  expect(versions.length).toBeGreaterThan(1);
  expect(new Set(versions)).toEqual(new Set(["2"]));
  const trusting = [
    ...declarations,
    {
      sourceId,
      binding: upgraded,
      validateData: (data: Record<string, unknown>) =>
        typeof data.id === "string",
    },
  ];
  const inOrder = device(true, trusting, declarations);
  send(inOrder, before);
  expect(value(inOrder)?.data.text).toBe("snapshot");
  expect(inOrder.store.listStreamCompletions("conn_a")).toHaveLength(1);
  send(inOrder, after);
  const reversed = device(true, trusting, declarations);
  send(reversed, after);
  send(reversed, before);
  // `writeSeq` counts local writes, so it depends on arrival order.
  const completions = (d: { store: typeof source.store }) =>
    d.store
      .listStreamCompletions("conn_a")
      .map(({ writeSeq: _local, ...completion }) => completion);
  for (const d of [inOrder, reversed]) {
    expect(value(d)?.data.text).toBe("upgraded");
    expect(completions(d)).toEqual(completions(source));
  }
});

it("makes a completion unavailable, not the import a failure, when live rows do not fit its declaration's key", () => {
  const operations = completedReplica();
  const d = device();
  send(
    d,
    operations.filter((op) => op.kind !== "stream-complete"),
  );
  expect(value(d)?.data.text).toBe("snapshot");
  // A second trusted declaration of the stream keys rows by a field the
  // stored rows lack, so their snapshot digest cannot be computed.
  const keyed = {
    ...binding,
    digest: `sha256:${"c".repeat(64)}`,
    primaryKey: ["other"],
  };
  d.declare([
    ...declarations,
    { sourceId, binding: keyed, validateData: () => true },
  ]);
  const completion = operations.find((op) => op.kind === "stream-complete")!;
  expect(() =>
    send(d, [
      {
        ...completion,
        declaration: keyed,
        revision: { ...completion.revision, operationId: "keyed-complete" },
      },
    ]),
  ).not.toThrow();
  expect(d.store.listStreamCompletions("conn_a")).toEqual([]);
  expect(value(d)?.data.text).toBe("snapshot");
});

describe("binding-conflict precedence, as in the engine", () => {
  // Evidence for conn_a names another method; the host then maps conn_a.
  const foreign = (op: ReplicaOperation): ReplicaOperation => ({
    ...op,
    methodId: "other",
  });
  function provisionOver(
    operations: ReplicaOperation[],
    local?: (d: ReturnType<typeof device>) => void,
  ) {
    const d = device(false);
    send(d, operations.map(foreign));
    d.store.registerConnection({
      instance: "conn_a",
      sourceId,
      method: "collector",
      label: "A",
    });
    local?.(d);
    d.receiver.retry({ credential: "replica-secret" });
    expect(d.store.replicaBindingConflict("conn_a")).toBe(true);
    return d;
  }
  it("never applies a deletion that names another binding", () => {
    const d = provisionOver(
      [
        registration(),
        {
          ...registration(),
          kind: "connection-delete",
          revision: { counter: 2, writerId: "remote", operationId: "delete" },
        },
      ],
      (d) => put(d, "local"),
    );
    expect(d.store.getInstanceBinding("conn_a").deletedAt).toBeNull();
    expect(
      d.db
        .prepare(
          "SELECT record_key FROM pdpp_records WHERE instance = 'conn_a' AND deleted = 1",
        )
        .all(),
    ).toEqual([]);
    expect(value(d)?.data.text).toBe("local");
    d.reopen();
    expect(d.store.getInstanceBinding("conn_a").deletedAt).toBeNull();
    expect(
      d.receiver
        .readStore({ reader: "owner" })
        .getRecord("conn_a", "messages", "a")?.data.text,
    ).toBe("local");
  });
  it("applies a deletion under the mapping that follows one naming another binding", () => {
    const deletion = (counter: number): ReplicaOperation => ({
      ...registration(),
      kind: "connection-delete",
      revision: {
        counter,
        writerId: "remote",
        operationId: `delete-${counter}`,
      },
    });
    // provisionOver renames the first deletion's method; the second keeps
    // the mapping's.
    const d = provisionOver([registration(), deletion(2)]);
    expect(d.store.getInstanceBinding("conn_a").deletedAt).toBeNull();
    send(d, [deletion(3)]);
    d.receiver.retry({ credential: "replica-secret" });
    expect(d.store.getInstanceBinding("conn_a").deletedAt).toBe(
      "replica-deleted",
    );
    expect(d.store.replicaBindingConflict("conn_a")).toBe(true);
  });
  it("applies an operation-ID equivocation's terminal quarantine", () => {
    const record = upsert();
    const d = provisionOver([
      registration(),
      record,
      { ...record, data: { id: "a", text: "twin" } },
    ]);
    expect(
      d.db
        .prepare("SELECT instance FROM pdpp_replica_quarantined_connections")
        .all(),
    ).toEqual([{ instance: "conn_a" }]);
  });
});

it.each([false, true])(
  "does not permanently delete a binding on cross-kind operation equivocation (deleteFirst=%s)",
  (deleteFirst) => {
    const d = device();
    const record = upsert();
    const deletion: ReplicaOperation = {
      ...registration(),
      kind: "connection-delete",
      revision: record.revision,
    };
    send(d, [deleteFirst ? deletion : record]);
    const plan = send(d, [deleteFirst ? record : deletion]);
    expect(
      plan.conflicts.some(
        (issue) => issue.reason === "operation_id_equivocation",
      ),
    ).toBe(true);
    expect(value(d)).toBeUndefined();
    expect(d.store.getInstanceBinding("conn_a").deletedAt).toBeNull();
    const before = d.db.prepare("SELECT * FROM pdpp_replica_own_writes").all();
    try {
      put(d, "local");
    } catch {
      /* Quarantine may explicitly refuse the write. */
    }
    expect(value(d)).toBeUndefined();
    expect(d.db.prepare("SELECT * FROM pdpp_replica_own_writes").all()).toEqual(
      before,
    );
    d.reopen();
    expect(d.store.getInstanceBinding("conn_a").deletedAt).toBeNull();
  },
);

it.each(["empty", "tombstone-only"])(
  "allocates a fresh reset fence for an imported reset of a %s connection",
  (mode) => {
    const d = device();
    if (mode === "tombstone-only") {
      put(d, "old");
      d.store.deleteRecord("conn_a", "messages", "a", at, "mutable_state");
    }
    const options = { instanceIds: ["conn_a"], limit: 100 };
    const before = d.store.changesSince("messages", options);
    const clock = (
      d.db.prepare("SELECT value FROM pdpp_write_clock").get() as {
        value: number;
      }
    ).value;
    const reset: ReplicaOperation = {
      ...registration(),
      kind: "connection-reset",
      generation: 2,
      previousGeneration: 1,
      revision: { counter: 100, writerId: "remote", operationId: "reset" },
    };
    send(d, [reset]);
    expect(d.store.getInstanceBinding("conn_a").resetClock).toBeGreaterThan(
      clock,
    );
    expect(() =>
      d.store.changesSince("messages", {
        ...options,
        changesSince: before.nextChangesSince,
      }),
    ).toThrow();
  },
);

it("keeps a committed connection deletion fence unchanged on duplicate replay after unrelated writes", () => {
  const d = device();
  put(d, "a");
  const deletion: ReplicaOperation = {
    ...registration(),
    kind: "connection-delete",
    revision: { counter: 100, writerId: "remote", operationId: "delete" },
  };
  send(d, [deletion]);
  const before = d.store.getInstanceBinding("conn_a");
  d.store.registerConnection({
    instance: "other",
    sourceId,
    method: "collector",
    label: "Other",
  });
  d.store.ingestBatch(
    [
      {
        instance: "other",
        stream: "messages",
        key: "b",
        data: { id: "b" },
        emitted_at: at,
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  send(d, [deletion]);
  expect(d.store.getInstanceBinding("conn_a")).toEqual(before);
});

it("allocates imported arrival order after repeated unchanged local collector observations", () => {
  const d = device();
  for (let i = 0; i < 5; i++) put(d, "unchanged");
  expect(d.store.listArrivalOrder("conn_a", "messages")).toEqual(["a"]);
  const record: ReplicaOperation = {
    ...upsert(100),
    recordKey: "b",
    data: { id: "b", text: "imported" },
  };
  send(d, [record]);
  expect(d.store.listArrivalOrder("conn_a", "messages")).toEqual(["a", "b"]);
  const before = d.db.prepare("SELECT * FROM pdpp_record_arrival").all();
  send(d, [record]);
  expect(d.db.prepare("SELECT * FROM pdpp_record_arrival").all()).toEqual(
    before,
  );
});

function certifyEmpty(d: ReturnType<typeof device>, stream = "messages") {
  return d.store.completeStreams(
    {
      instance: "conn_a",
      sourceId,
      method: "collector",
      generation: 1,
      sourceCollectedAt: at,
      collectionTimeBasis: "host_run_finished",
      streams: [
        {
          stream,
          coverage: "full_stream",
          liveCount: 0,
          snapshotSha256: liveSnapshotDigest(
            {
              sourceId,
              instance: "conn_a",
              method: "collector",
              generation: 1,
              stream,
            },
            ["id"],
            [],
          ),
        },
      ],
    },
    () => ["id"],
  );
}
function appendQuarantineDevice() {
  const appendBinding = { ...binding, semantics: "append_only" as const };
  const d = device(true, [
    { sourceId, binding: appendBinding, validateData: () => true },
    {
      sourceId,
      binding: { ...binding, stream: "profiles" },
      validateData: () => true,
    },
  ]);
  send(d, [
    { ...upsert(20), declaration: appendBinding },
    { ...upsert(21), declaration: appendBinding },
  ]);
  expect(value(d)).toBeUndefined();
  return d;
}
it("refuses native empty completion certification for an append-only quarantined stream", () => {
  const d = appendQuarantineDevice();
  const before = all(d);
  try {
    certifyEmpty(d);
  } catch {
    /* Refusal may throw. */
  }
  expect(d.store.listStreamCompletions("conn_a")).toEqual([]);
  d.reopen();
  try {
    certifyEmpty(d);
  } catch {
    /* The durable fence must survive restart. */
  }
  expect(d.store.listStreamCompletions("conn_a")).toEqual([]);
  expect(all(d)).toEqual(before);
  certifyEmpty(d, "profiles");
  expect(
    d.store.listStreamCompletions("conn_a").map((receipt) => receipt.stream),
  ).toEqual(["profiles"]);
});
it("refuses replace-stream empty snapshot certification for an append-only quarantined stream", () => {
  const d = appendQuarantineDevice();
  const before = all(d);
  try {
    d.store.replaceStream({
      instance: "conn_a",
      stream: "messages",
      method: "collector",
      generation: 1,
      emittedAt: at,
      envelopes: [],
      primaryKey: ["id"],
      sourceCollectedAt: at,
    });
  } catch {
    /* Refusal may throw. */
  }
  expect(d.store.listStreamCompletions("conn_a")).toEqual([]);
  expect(value(d)).toBeUndefined();
  expect(all(d)).toEqual(before);
});
it("refuses native empty completion certification for an operation-ID quarantined connection", () => {
  const d = device();
  const record = upsert();
  send(d, [record]);
  send(d, [
    { ...registration(), kind: "connection-delete", revision: record.revision },
  ]);
  expect(d.store.getInstanceBinding("conn_a").deletedAt).toBeNull();
  const before = all(d);
  try {
    certifyEmpty(d);
  } catch {
    /* Refusal may throw. */
  }
  expect(d.store.listStreamCompletions("conn_a")).toEqual([]);
  expect(all(d)).toEqual(before);
});

it("does not reveal quarantined append-only content through a pre-conflict pagination horizon", () => {
  const appendBinding = { ...binding, semantics: "append_only" as const };
  const d = device(true, [
    { sourceId, binding: appendBinding, validateData: () => true },
  ]);
  d.store.ingestBatch(
    ["a", "b"].map((id) => ({
      instance: "conn_a",
      stream: "messages",
      key: id,
      data: { id, text: `original-${id}` },
      emitted_at: at,
    })),
    () => "append_only",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  const options = { instanceIds: ["conn_a"], limit: 1, order: "asc" as const };
  const first = d.store.listRecords("messages", options);
  expect(first.data.map((row) => row.recordKey)).toEqual(["a"]);
  expect(first.nextCursor).toBeDefined();
  const conflict: ReplicaOperation = {
    ...upsert(100),
    declaration: appendBinding,
    recordKey: "b",
    data: { id: "b", text: "conflicting-b" },
  };
  send(d, [conflict]);
  expect(d.store.getRecord("conn_a", "messages", "b")).toBeUndefined();
  let continued;
  try {
    continued = d.store.listRecords("messages", {
      ...options,
      cursor: first.nextCursor,
    });
  } catch (error) {
    // The key quarantine raised the connection's integrity epoch.
    expect(error).toBeInstanceOf(CursorExpiredError);
  }
  expect(continued?.data.some((row) => row.recordKey === "b") ?? false).toBe(
    false,
  );
  expect(
    d.store
      .listRecords("messages", { ...options, limit: 100 })
      .data.map((row) => row.recordKey),
  ).toEqual(["a"]);
  const fence = d.store.getInstanceBinding("conn_a").resetClock;
  d.store.registerConnection({
    instance: "other",
    sourceId,
    method: "collector",
    label: "Other",
  });
  d.store.ingestBatch(
    [
      {
        instance: "other",
        stream: "messages",
        key: "c",
        data: { id: "c" },
        emitted_at: at,
      },
    ],
    () => "append_only",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  send(d, [conflict]);
  expect(d.store.getInstanceBinding("conn_a").resetClock).toBe(fence);
});

function pendingReceiver(
  d: ReturnType<typeof device>,
  enabled = true,
  visibilityPolicy?: {
    owner: "include-pending" | "confirmed-only";
    grant: "confirmed-only";
  },
) {
  return createReplicaReceiver({
    db: d.db,
    store: d.store,
    owner: "owner",
    enabled,
    visibilityPolicy,
    authenticate: (c) => (c === "replica-secret" ? "owner" : undefined),
    declarations: () => declarations,
  });
}
function stagePending(
  d: ReturnType<typeof device>,
  operations = [registration(), upsert()],
  id = "pending",
) {
  const receiver = pendingReceiver(d);
  receiver.stage({
    credential: "replica-secret",
    id,
    envelope: batch(operations),
  });
  return receiver;
}
const preview = (
  receiver: ReturnType<typeof createReplicaReceiver>,
  reader: "owner" | "grant" = "owner",
) =>
  receiver.readVisibleRecords({
    reader,
    connectionId: "conn_a",
    stream: "messages",
  });

it("isolates pending from canonical, grants, exports and clocks; restores on reopen and atomically promotes exactly once", () => {
  const d = device();
  const before = {
    clock: d.db.prepare("SELECT * FROM pdpp_replica_clock").all(),
    write: d.db.prepare("SELECT * FROM pdpp_write_clock").all(),
    journal: all(d),
  };
  let receiver = stagePending(d);
  expect(preview(receiver)).toMatchObject([
    { data: { text: "remote-20" }, confirmation: "not yet confirmed" },
  ]);
  expect(preview(receiver, "grant")).toEqual([]);
  expect(value(d)).toBeUndefined();
  expect(d.db.prepare("SELECT * FROM pdpp_replica_clock").all()).toEqual(
    before.clock,
  );
  expect(d.db.prepare("SELECT * FROM pdpp_write_clock").all()).toEqual(
    before.write,
  );
  expect(all(d)).toEqual(before.journal);
  d.reopen();
  receiver = pendingReceiver(d);
  expect(preview(receiver)).toHaveLength(1);
  d.db.exec(
    "CREATE TEMP TRIGGER reject_promotion BEFORE INSERT ON pdpp_records BEGIN SELECT RAISE(ABORT,'interrupt'); END",
  );
  expect(() =>
    receiver.promote({ credential: "replica-secret", id: "pending" }),
  ).toThrow("interrupt");
  expect(value(d)).toBeUndefined();
  expect(preview(receiver)).toHaveLength(1);
  d.db.exec("DROP TRIGGER reject_promotion");
  receiver.promote({ credential: "replica-secret", id: "pending" });
  expect(preview(receiver, "grant")).toMatchObject([
    { data: { text: "remote-20" } },
  ]);
  expect(preview(receiver)[0].confirmation).toBeUndefined();
  const history = d.db.prepare("SELECT * FROM pdpp_record_changes").all();
  receiver.promote({ credential: "replica-secret", id: "pending" });
  expect(d.db.prepare("SELECT * FROM pdpp_record_changes").all()).toEqual(
    history,
  );
});

it("quarantines divergent pending batches without changing canonical state", () => {
  const d = device();
  put(d, "local");
  const receiver = stagePending(d);
  expect(preview(receiver)[0].data.text).toBe("remote-20");
  receiver.quarantine({
    credential: "replica-secret",
    id: "pending",
    reason: "finalized mismatch",
  });
  expect(preview(receiver)[0].data.text).toBe("local");
  expect(() =>
    receiver.promote({ credential: "replica-secret", id: "pending" }),
  ).toThrow("quarantined");
  expect(value(d)?.data.text).toBe("local");
});

it("pending Lamport never advances local edits; preview agrees with eventual canonical merge", () => {
  const d = device();
  const receiver = stagePending(d, [registration(), upsert(100)]);
  put(d, "local-after-preview");
  const local = all(d).find((op) => op.kind === "upsert");
  expect(local?.revision.counter).toBeLessThan(100);
  expect(preview(receiver)[0].data.text).toBe("remote-100");
  receiver.promote({ credential: "replica-secret", id: "pending" });
  expect(value(d)?.data).toEqual(preview(receiver)[0].data);
});

// Origin: #440 journey "#9/#21". Promotion marks the key dirty when the
// blob bytes arrive, then again through the canonical upsert. SQLite lets an
// outer upsert's ON CONFLICT override a trigger body's OR IGNORE.
it("promotes a pending blob-backed edit of an existing canonical key", () => {
  const d = device();
  put(d, "local");
  const bytes = new TextEncoder().encode("edited attachment");
  const blobId = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  const blob = {
    blobId,
    sha256: blobId,
    mimeType: "text/plain",
    sizeBytes: bytes.length,
  };
  const receiver = pendingReceiver(d);
  receiver.stage({
    credential: "replica-secret",
    id: "pending",
    blobs: [{ blobId, bytes }],
    envelope: batch([
      registration(),
      {
        ...registration(),
        kind: "blob-claim",
        blob,
        revision: { counter: 99, writerId: "remote", operationId: "claim" },
      } as ReplicaOperation,
      {
        ...upsert(100),
        blobs: [blob],
        data: {
          id: "a",
          text: "edited",
          blob_ref: {
            blob_id: blobId,
            mime_type: "text/plain",
            size_bytes: 17,
          },
        },
      },
    ]),
  });
  expect(preview(receiver)[0].data.text).toBe("edited");
  expect(value(d)?.data.text).toBe("local");
  receiver.promote({ credential: "replica-secret", id: "pending" });
  expect(value(d)?.data.text).toBe("edited");
  expect(preview(receiver, "grant")[0].data.text).toBe("edited");
  expect(d.store.getBlobBytes(blobId)).toEqual(bytes);
});

// Structural guard for the case above: an outer statement's conflict clause
// overrides any conflict clause in a trigger body, so view triggers must
// guard their inserts with NOT EXISTS instead.
it("keeps conflict clauses out of every view trigger body", () => {
  const d = device();
  // With the conflict-fact table the view also installs its local projection.
  d.db.exec(
    "CREATE TABLE IF NOT EXISTS pdpp_replica_binding_conflicts (instance TEXT PRIMARY KEY, reason TEXT NOT NULL, evidence_json TEXT NOT NULL)",
  );
  // View triggers are TEMP triggers of the enabling connection.
  const before = new Set(
    (
      d.db
        .prepare("SELECT name FROM sqlite_temp_master WHERE type='trigger'")
        .all() as {
        name: string;
      }[]
    ).map((row) => row.name),
  );
  pendingReceiver(d);
  const triggers = (
    d.db
      .prepare("SELECT name,sql FROM sqlite_temp_master WHERE type='trigger'")
      .all() as { name: string; sql: string }[]
  ).filter((row) => !before.has(row.name));
  expect(triggers.length).toBeGreaterThan(20);
  expect(
    triggers
      .filter(({ sql }) =>
        /\b(?:INSERT|UPDATE)\s+OR\s+(?:IGNORE|REPLACE|ABORT|FAIL|ROLLBACK)\b|\bREPLACE\s+INTO\b/i.test(
          sql,
        ),
      )
      .map((row) => row.name),
  ).toEqual([]);
});

it("flag off preserves exact canonical pages and cursors and does not stage", () => {
  const d = device();
  put(d, "local");
  const receiver = pendingReceiver(d, false);
  receiver.stage({
    credential: "replica-secret",
    id: "off",
    envelope: batch([registration(), upsert()]),
  });
  const options = {
    stream: "messages",
    instanceIds: ["conn_a"],
    limit: 1,
    order: "asc" as const,
  };
  expect(receiver.readRecords({ ...options, reader: "owner" })).toEqual(
    d.store.listRecords(options.stream, options),
  );
  expect(preview(receiver)).toEqual([value(d)]);
  expect(
    d.db.prepare("SELECT * FROM pdpp_replica_pending_batches").all(),
  ).toEqual([]);
});

it("only owner mode previews pending rows", () => {
  const d = device();
  const second = {
    ...upsert(21),
    recordKey: "b",
    data: { id: "b", text: "second" },
  } as ReplicaOperation;
  stagePending(d, [registration(), upsert(), second]);
  const receiver = pendingReceiver(d, true, {
    owner: "include-pending",
    grant: "confirmed-only",
  });
  expect(preview(receiver)).toHaveLength(2);
  expect(preview(receiver, "grant")).toEqual([]);
  const options = {
    reader: "grant" as const,
    stream: "messages",
    instanceIds: ["conn_a"],
    limit: 1,
    order: "asc" as const,
  };
  expect(receiver.readRecords(options).data).toEqual([]);
});

it("only enables pending preview when the runtime value is true", () => {
  const d = device();
  const receiver = pendingReceiver(d);
  receiver.stage({
    credential: "replica-secret",
    id: "pending",
    envelope: batch([registration(), upsert()]),
  });
  receiver.setPendingEnabled("false" as unknown as boolean);
  expect(
    receiver.readRecords({
      reader: "owner",
      stream: "messages",
      instanceIds: ["conn_a"],
      limit: 10,
      order: "asc",
    }).data,
  ).toEqual([]);
});

it("pending reset and deletion follow canonical lifecycle semantics without mutating the binding", () => {
  const d = device();
  put(d, "local");
  const reset: ReplicaOperation = {
    kind: "connection-reset",
    owner: "owner",
    sourceId,
    connectionId: "conn_a",
    methodId: "collector",
    generation: 2,
    previousGeneration: 1,
    revision: { counter: 30, writerId: "remote", operationId: "reset-pending" },
  };
  const next = { ...upsert(31), generation: 2 } as ReplicaOperation;
  const receiver = stagePending(d, [registration(), reset, next]);
  expect(preview(receiver)).toMatchObject([{ data: { text: "remote-31" } }]);
  expect(value(d)?.data.text).toBe("local");
  expect(d.store.getInstanceBinding("conn_a").generation).toBe(1);
  const deletion: ReplicaOperation = {
    kind: "connection-delete",
    owner: "owner",
    sourceId,
    connectionId: "conn_a",
    methodId: "collector",
    generation: 2,
    revision: {
      counter: 32,
      writerId: "remote",
      operationId: "delete-pending",
    },
  };
  receiver.stage({
    credential: "replica-secret",
    id: "delete",
    envelope: batch([deletion]),
  });
  expect(preview(receiver)).toMatchObject([
    {
      deleted: true,
      data: {},
      confirmation: "not yet confirmed",
      visibility: "pending",
    },
  ]);
  expect(value(d)?.data.text).toBe("local");
  expect(d.store.getInstanceBinding("conn_a").deletedAt).toBeNull();
});

it("policy gates pending binary metadata, bytes and reverse references until promotion", () => {
  const source = device(),
    target = device();
  const bytes = new Uint8Array([4, 5, 6]);
  const blob = source.store.storeBlobBytesForInstance({
    instance: "conn_a",
    method: "collector",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  source.store.ingestBatch(
    [
      {
        instance: "conn_a",
        stream: "messages",
        key: "a",
        emitted_at: at,
        data: {
          id: "a",
          text: "binary",
          blob_ref: {
            blob_id: blob.blobId,
            sha256: blob.sha256,
            size_bytes: blob.sizeBytes,
            mime_type: blob.mimeType,
          },
        },
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  const receiver = pendingReceiver(target);
  receiver.stage({
    credential: "replica-secret",
    id: "binary",
    envelope: batch(all(source)),
    blobs: [{ blobId: blob.blobId, bytes }],
  });
  const owner = receiver.readStore({ reader: "owner" }),
    grant = receiver.readStore();
  // copy-assertion-ok: User-required data-model confirmation value.
  expect(owner.getRecord("conn_a", "messages", "a")?.confirmation).toBe(
    "not yet confirmed",
  );
  expect(Array.from(owner.getBlobBytes(blob.blobId)!)).toEqual(
    Array.from(bytes),
  );
  expect(owner.getBlobMeta(blob.blobId)).toEqual(blob);
  expect(owner.findBlobReferences(blob.blobId)).toEqual([
    { instance: "conn_a", stream: "messages", recordKey: "a" },
  ]);
  expect(grant.getBlobBytes(blob.blobId)).toBeUndefined();
  expect(grant.getBlobMeta(blob.blobId)).toBeUndefined();
  expect(grant.findBlobReferences(blob.blobId)).toEqual([]);
  expect(target.store.getBlobBytes(blob.blobId)).toBeUndefined();
  receiver.promote({ credential: "replica-secret", id: "binary" });
  expect(Array.from(grant.getBlobBytes(blob.blobId)!)).toEqual(
    Array.from(bytes),
  );
  expect(
    owner.getRecord("conn_a", "messages", "a")?.confirmation,
  ).toBeUndefined();
  expect(
    target.db.prepare("SELECT * FROM pdpp_replica_pending_bytes").all(),
  ).toEqual([]);
});

for (const delivery of ["replayed claim", "unrelated connection"] as const)
  it(`re-derives a pending blob record when its bytes arrive later (${delivery})`, () => {
    const source = device(),
      target = device();
    for (const d of [source, target])
      d.store.registerConnection({
        instance: "conn_b",
        sourceId,
        method: "collector",
        label: "B",
      });
    const bytes = new Uint8Array([4, 2, 4, 2]);
    const store = (instance: string) =>
      source.store.storeBlobBytesForInstance({
        instance,
        method: "collector",
        generation: 1,
        bytes,
        mimeType: "application/octet-stream",
      });
    const blob = store("conn_a");
    expect(store("conn_b")).toEqual(blob);
    const ref = {
      blob_id: blob.blobId,
      sha256: blob.sha256,
      size_bytes: blob.sizeBytes,
      mime_type: blob.mimeType,
    };
    const ingest = (instance: string, rows: Record<string, unknown>[]) =>
      source.store.ingestBatch(
        rows.map((data) => ({
          instance,
          stream: "messages",
          key: data.id as string,
          emitted_at: at,
          data,
        })),
        () => "mutable_state",
        () => ["id"],
        { method: "collector", generation: 1 },
      );
    ingest("conn_a", [
      { id: "a", text: "binary", blob_ref: ref },
      { id: "c1", text: "plain" },
      { id: "c2", text: "plain" },
    ]);
    ingest("conn_b", [{ id: "b", text: "other", blob_ref: ref }]);
    const ops = all(source);
    const a = ops.filter((op) => op.connectionId === "conn_a");
    const b = ops.filter((op) => op.connectionId === "conn_b");
    const claimA = a.filter((op) => op.kind === "blob-claim");
    expect(claimA).toHaveLength(1);
    const receiver = pendingReceiver(target);
    if (delivery === "replayed claim") {
      // The claim is retained without bytes; only the upserts are pending.
      receiver.import({
        credential: "replica-secret",
        envelope: batch(a.filter((op) => op.kind !== "upsert")),
      });
      receiver.stage({
        credential: "replica-secret",
        id: "late-bytes",
        envelope: batch(a.filter((op) => op.kind === "upsert")),
      });
    } else
      receiver.stage({
        credential: "replica-secret",
        id: "late-bytes",
        envelope: batch(a),
      });
    const owner = receiver.readStore({ reader: "owner" }),
      grant = receiver.readStore();
    expect(owner.getRecord("conn_a", "messages", "a")).toBeUndefined();
    expect(preview(receiver).map((row) => row.recordKey)).toEqual(["c1", "c2"]);
    const page = (cursor?: string) =>
      receiver.readRecords({
        reader: "owner",
        stream: "messages",
        instanceIds: ["conn_a"],
        limit: 1,
        order: "asc",
        cursor,
      });
    const before = page();
    expect(before.data.map((row) => row.recordKey)).toEqual(["c1"]);
    expect(before.nextCursor).toBeDefined();

    receiver.import({
      credential: "replica-secret",
      envelope: batch(delivery === "replayed claim" ? claimA : b),
      blobs: [{ blobId: blob.blobId, bytes }],
    });
    receiver.retry({ credential: "replica-secret" });

    // copy-assertion-ok: User-required data-model confirmation value.
    expect(owner.getRecord("conn_a", "messages", "a")).toMatchObject({
      data: { id: "a", text: "binary" },
      visibility: "pending",
      confirmation: "not yet confirmed",
    });
    expect(preview(receiver).map((row) => row.recordKey)).toEqual([
      "a",
      "c1",
      "c2",
    ]);
    expect(owner.findBlobReferences(blob.blobId)).toContainEqual({
      instance: "conn_a",
      stream: "messages",
      recordKey: "a",
    });
    expect(grant.getRecord("conn_a", "messages", "a")).toBeUndefined();
    // The page changed under the old cursor: it expires instead of skipping "a".
    expect(() => page(before.nextCursor)).toThrow(/expired/);
    const after = page();
    expect(after.data.map((row) => row.recordKey)).toEqual(["a"]);
    expect(page(after.nextCursor).data.map((row) => row.recordKey)).toEqual([
      "c1",
    ]);
  });

it("hides a pending blob record again when the only batch carrying its bytes is quarantined", () => {
  const source = device(),
    target = device();
  for (const d of [source, target])
    d.store.registerConnection({
      instance: "conn_b",
      sourceId,
      method: "collector",
      label: "B",
    });
  const bytes = new Uint8Array([6, 6, 6]);
  for (const instance of ["conn_a", "conn_b"]) {
    const blob = source.store.storeBlobBytesForInstance({
      instance,
      method: "collector",
      generation: 1,
      bytes,
      mimeType: "application/octet-stream",
    });
    source.store.ingestBatch(
      [
        {
          instance,
          stream: "messages",
          key: instance,
          emitted_at: at,
          data: { id: instance, blob_ref: { blob_id: blob.blobId } },
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "collector", generation: 1 },
    );
  }
  const ops = all(source);
  const blobId = (
    ops.find((op) => op.kind === "blob-claim") as { blob: { blobId: string } }
  ).blob.blobId;
  const receiver = pendingReceiver(target);
  receiver.stage({
    credential: "replica-secret",
    id: "carrier",
    envelope: batch(ops.filter((op) => op.connectionId === "conn_b")),
    blobs: [{ blobId, bytes }],
  });
  receiver.stage({
    credential: "replica-secret",
    id: "dependent",
    envelope: batch(ops.filter((op) => op.connectionId === "conn_a")),
  });
  const owner = receiver.readStore({ reader: "owner" });
  expect(owner.getRecord("conn_a", "messages", "conn_a")).toMatchObject({
    visibility: "pending",
  });
  receiver.quarantine({
    credential: "replica-secret",
    id: "carrier",
    reason: "finalized commitment conflict",
  });
  expect(owner.getRecord("conn_a", "messages", "conn_a")).toBeUndefined();
  expect(owner.getBlobBytes(blobId)).toBeUndefined();
});

// Received bytes above 1 MiB and every staged transport blob are chunked (#439).
for (const delivery of [
  "replayed claim",
  "unrelated connection",
  "pending carrier",
] as const)
  it(`re-derives a pending blob record when chunked bytes arrive or leave (${delivery})`, () => {
    const source = device(),
      target = device();
    for (const d of [source, target])
      d.store.registerConnection({
        instance: "conn_b",
        sourceId,
        method: "collector",
        label: "B",
      });
    const bytes = new Uint8Array(1024 * 1024 + 4096).map((_, i) => i % 251);
    const store = (instance: string) =>
      source.store.storeBlobBytesForInstance({
        instance,
        method: "collector",
        generation: 1,
        bytes,
        mimeType: "application/octet-stream",
      });
    const blob = store("conn_a");
    expect(store("conn_b")).toEqual(blob);
    const ref = {
      blob_id: blob.blobId,
      sha256: blob.sha256,
      size_bytes: blob.sizeBytes,
      mime_type: blob.mimeType,
    };
    const ingest = (instance: string, rows: Record<string, unknown>[]) =>
      source.store.ingestBatch(
        rows.map((data) => ({
          instance,
          stream: "messages",
          key: data.id as string,
          emitted_at: at,
          data,
        })),
        () => "mutable_state",
        () => ["id"],
        { method: "collector", generation: 1 },
      );
    ingest("conn_a", [
      { id: "a", text: "binary", blob_ref: ref },
      { id: "c1", text: "plain" },
      { id: "c2", text: "plain" },
    ]);
    ingest("conn_b", [{ id: "b", text: "other", blob_ref: ref }]);
    const ops = all(source);
    const a = ops.filter((op) => op.connectionId === "conn_a");
    const b = ops.filter((op) => op.connectionId === "conn_b");
    const claimA = a.filter((op) => op.kind === "blob-claim");
    const receiver = pendingReceiver(target);
    if (delivery === "replayed claim") {
      receiver.import({
        credential: "replica-secret",
        envelope: batch(a.filter((op) => op.kind !== "upsert")),
      });
      receiver.stage({
        credential: "replica-secret",
        id: "late-bytes",
        envelope: batch(a.filter((op) => op.kind === "upsert")),
      });
    } else
      receiver.stage({
        credential: "replica-secret",
        id: "late-bytes",
        envelope: batch(a),
      });
    const owner = receiver.readStore({ reader: "owner" });
    const page = (cursor?: string) =>
      receiver.readRecords({
        reader: "owner",
        stream: "messages",
        instanceIds: ["conn_a"],
        limit: 1,
        order: "asc",
        cursor,
      });
    expect(owner.getRecord("conn_a", "messages", "a")).toBeUndefined();
    expect(preview(receiver).map((row) => row.recordKey)).toEqual(["c1", "c2"]);
    const before = page();
    expect(before.data.map((row) => row.recordKey)).toEqual(["c1"]);

    if (delivery === "pending carrier") {
      const writer = binaryWriter(target.db, "staging", "carrier-stage");
      writer.write(bytes);
      writer.finish();
      receiver.stage({
        credential: "replica-secret",
        id: "carrier",
        envelope: batch(b),
        stagedBlobs: [
          {
            blobId: blob.blobId,
            key: "carrier-stage",
            sizeBytes: blob.sizeBytes,
          },
        ],
      });
    } else
      receiver.import({
        credential: "replica-secret",
        envelope: batch(delivery === "replayed claim" ? claimA : b),
        blobs: [{ blobId: blob.blobId, bytes }],
      });
    receiver.retry({ credential: "replica-secret" });
    // The bytes that arrived are chunks, not legacy rows.
    const namespace = delivery === "pending carrier" ? "pending" : "received";
    expect(
      target.db
        .prepare(
          "SELECT count(*) AS n FROM pdpp_binary_manifests WHERE namespace=?",
        )
        .get(namespace),
    ).toEqual({ n: 1 });
    expect(
      target.db
        .prepare(
          "SELECT (SELECT count(*) FROM pdpp_replica_received_bytes)+(SELECT count(*) FROM pdpp_replica_pending_bytes) AS n",
        )
        .get(),
    ).toEqual({ n: 0 });

    // copy-assertion-ok: User-required data-model confirmation value.
    expect(owner.getRecord("conn_a", "messages", "a")).toMatchObject({
      data: { id: "a", text: "binary" },
      visibility: "pending",
      confirmation: "not yet confirmed",
    });
    expect(preview(receiver).map((row) => row.recordKey)).toEqual([
      "a",
      "c1",
      "c2",
    ]);
    expect(owner.getBlobBytes(blob.blobId)?.byteLength).toBe(bytes.length);
    expect(() => page(before.nextCursor)).toThrow(/expired/);

    if (delivery === "unrelated connection") return;
    // The chunks leave: the carrier batch is quarantined, or the received
    // chunks are lost.
    if (delivery === "pending carrier")
      receiver.quarantine({
        credential: "replica-secret",
        id: "carrier",
        reason: "finalized commitment conflict",
      });
    else {
      target.db.transaction(() =>
        deleteBinary(target.db, "received", blob.blobId),
      )();
      receiver.retry({ credential: "replica-secret" });
    }
    expect(owner.getRecord("conn_a", "messages", "a")).toBeUndefined();
    expect(preview(receiver).map((row) => row.recordKey)).toEqual(["c1", "c2"]);
    expect(owner.getBlobBytes(blob.blobId)).toBeUndefined();
  });

it("quarantine removes owner binary access and malformed stage bytes never enter pending storage", () => {
  const source = device(),
    target = device();
  const bytes = new Uint8Array([7, 8, 9]);
  const blob = source.store.storeBlobBytesForInstance({
    instance: "conn_a",
    method: "collector",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  source.store.ingestBatch(
    [
      {
        instance: "conn_a",
        stream: "messages",
        key: "a",
        emitted_at: at,
        data: { id: "a", blob_ref: { blob_id: blob.blobId } },
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  const receiver = pendingReceiver(target);
  const input = {
    credential: "replica-secret",
    id: "binary",
    envelope: batch(all(source)),
    blobs: [{ blobId: blob.blobId, bytes }],
  };
  expect(() =>
    receiver.stage({
      ...input,
      blobs: [{ blobId: blob.blobId, bytes: new Uint8Array([0]) }],
    }),
  ).toThrow("corrupt replica blob bytes");
  expect(preview(receiver)).toEqual([]);
  receiver.stage(input);
  expect(
    Array.from(
      receiver.readStore({ reader: "owner" }).getBlobBytes(blob.blobId)!,
    ),
  ).toEqual(Array.from(bytes));
  receiver.quarantine({
    credential: "replica-secret",
    id: "binary",
    reason: "finalized commitment conflict",
  });
  expect(
    receiver.readStore({ reader: "owner" }).getBlobBytes(blob.blobId),
  ).toBeUndefined();
  expect(
    receiver.readStore({ reader: "owner" }).getBlobMeta(blob.blobId),
  ).toBeUndefined();
});

for (const order of ["asc", "desc"] as const)
  it(`matches SQLite binary tuple ordering for pending Unicode/case keys and timestamps (${order})`, () => {
    const target = device(),
      canonical = device();
    const keys = ["a", "A", "é", "z", "\uE000", "😀", "offset"];
    const operations = [
      registration(),
      ...keys.map(
        (key, index) =>
          ({
            ...upsert(30 + index),
            recordKey: key,
            data: { id: key, text: key },
            emittedAt: key === "offset" ? "2026-10-20T00:00:00+00:00" : at,
          }) as ReplicaOperation,
      ),
    ];
    send(canonical, operations);
    const receiver = stagePending(target, operations);
    const options = { instanceIds: ["conn_a"], limit: 100, order };
    const expected = canonical.store
      .listRecords("messages", options)
      .data.map((row) => [row.emittedAt, row.recordKey]);
    if (order === "asc")
      expect(
        preview(receiver).map((row) => [row.emittedAt, row.recordKey]),
      ).toEqual(expected);
    const actual: string[][] = [];
    let cursor: string | undefined;
    do {
      const page = receiver.readRecords({
        ...options,
        reader: "owner",
        stream: "messages",
        limit: 2,
        cursor,
      });
      actual.push(...page.data.map((row) => [row.emittedAt, row.recordKey]));
      cursor = page.nextCursor;
    } while (cursor);
    expect(actual).toEqual(expected);
    expect(new Set(actual.map((row) => row[1])).size).toBe(keys.length);
  });

it("keeps cross-connection operation-ID equivocation in owner preview merge evidence", () => {
  const d = device();
  const record = upsert(200);
  const collision = {
    ...record,
    connectionId: "other",
    data: { id: "a", text: "conflict" },
  } as ReplicaOperation;
  const receiver = stagePending(d, [registration(), record, collision]);
  expect(preview(receiver)).toEqual([]);
  expect(preview(receiver, "grant")).toEqual([]);
});

it("applies foreign pending identity conflicts to confirmed owner rows without changing grant rows", () => {
  const d = device();
  const record = upsert(200);
  send(d, [registration(), record]);
  const collision = {
    ...record,
    connectionId: "other",
    data: { id: "a", text: "conflict" },
  } as ReplicaOperation;
  const receiver = stagePending(d, [collision]);
  expect(preview(receiver)).toEqual([]);
  expect(preview(receiver, "grant")).toHaveLength(1);
  expect(
    receiver.readStore({ reader: "owner" }).listRecords("messages", {
      instanceIds: ["conn_a"],
      order: "asc",
      limit: 10,
    }).data,
  ).toEqual([]);
  expect(
    receiver.readStore({ reader: "owner" }).listStreams(["conn_a"]),
  ).toEqual([]);
});

it("does not let an unrelated pending connection conflict withdraw owner rows", () => {
  const d = device();
  const record = upsert(200);
  send(d, [registration(), record]);
  const foreign = { ...upsert(300), connectionId: "other" } as ReplicaOperation;
  const collision = {
    ...foreign,
    kind: "upsert",
    data: { id: "a", text: "conflict" },
  } as ReplicaOperation;
  const receiver = stagePending(d, [foreign, collision]);
  expect(preview(receiver)).toHaveLength(1);
  expect(preview(receiver)[0].data.text).toBe("remote-200");
});

for (const owner of ["confirmed-only", "include-pending"] as const)
  for (const grant of ["confirmed-only"] as const)
    it(`keeps two-connection record identities scoped in ${owner}/${grant} mode`, () => {
      const d = device();
      d.store.registerConnection({
        instance: "conn_b",
        sourceId,
        method: "collector",
        label: "B",
      });
      const regB = {
        ...registration(),
        connectionId: "conn_b",
        revision: { counter: 1, writerId: "B", operationId: "register-b" },
      } as ReplicaOperation;
      const bRow = {
        ...upsert(100),
        connectionId: "conn_b",
        recordKey: "b",
        data: { id: "b", text: "B" },
      } as ReplicaOperation;
      send(d, [registration(), regB, upsert(), bRow]);
      const aPending = {
        ...upsert(201),
        recordKey: "p",
        data: { id: "p", text: "A pending" },
      } as ReplicaOperation;
      const bPending = {
        ...upsert(202),
        connectionId: "conn_b",
        recordKey: "foreign",
        data: { id: "foreign", text: "B pending" },
      } as ReplicaOperation;
      const receiver = pendingReceiver(d, true, { owner, grant });
      receiver.stage({
        credential: "replica-secret",
        id: "two-connections",
        envelope: batch([aPending, bPending]),
      });
      for (const reader of ["owner", "grant"] as const) {
        const view = receiver.readStore({ reader });
        const rows = view.listRecords("messages", {
          instanceIds: ["conn_a"],
          limit: 100,
          order: "asc",
        }).data;
        expect(rows.map((row) => row.recordKey)).toEqual(
          reader === "owner" && owner === "include-pending"
            ? ["a", "p"]
            : ["a"],
        );
        expect(rows.every((row) => row.instance === "conn_a")).toBe(true);
        expect(view.getRecord("conn_a", "messages", "foreign")).toBeUndefined();
      }
    });

it("refuses a changed stage attempt without rewriting a confirmed batch state", () => {
  const d = device();
  const receiver = stagePending(d);
  receiver.promote({ credential: "replica-secret", id: "pending" });
  expect(() =>
    receiver.stage({
      credential: "replica-secret",
      id: "pending",
      envelope: batch([registration(), upsert(999)]),
    }),
  ).toThrow();
  expect(
    d.db
      .prepare(
        "SELECT state FROM pdpp_replica_pending_batches WHERE id='pending'",
      )
      .get(),
  ).toEqual({ state: "confirmed" });
  expect(preview(receiver)).toHaveLength(1);
});

it("F1 expires owner pages when canonical or pending snapshot changes", () => {
  const d = device();
  d.store.ingestBatch(
    ["a", "b"].map((key) => ({
      instance: "conn_a",
      stream: "messages",
      key,
      data: { id: key },
      emitted_at: at,
    })),
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  const receiver = stagePending(d, [
    { ...upsert(50), recordKey: "z", data: { id: "z" } },
  ]);
  const options = {
    reader: "owner" as const,
    stream: "messages",
    instanceIds: ["conn_a"],
    limit: 1,
    order: "asc" as const,
  };
  const first = receiver.readRecords(options);
  expect(first.nextCursor).toBeDefined();
  put(d, "changed-after-page");
  expect(() =>
    receiver.readRecords({ ...options, cursor: first.nextCursor }),
  ).toThrow(/expired/);
  const current = receiver.readRecords(options);
  receiver.quarantine({
    credential: "replica-secret",
    id: "pending",
    reason: "test",
  });
  expect(() =>
    receiver.readRecords({ ...options, cursor: current.nextCursor }),
  ).toThrow(/expired/);
});

it("F2 exposes pending record removals with the confirmation marker", () => {
  const d = device();
  put(d, "confirmed");
  const {
    data: _data,
    blobs: _blobs,
    ...op
  } = upsert(50) as Extract<ReplicaOperation, { kind: "upsert" }>;
  const deletion = { ...op, kind: "delete", deletedAt: at } as ReplicaOperation;
  const receiver = stagePending(d, [registration(), deletion]);
  const owner = receiver.readStore({ reader: "owner" });
  expect(owner.getRecord("conn_a", "messages", "a")).toMatchObject({
    deleted: true,
    confirmation: "not yet confirmed",
    visibility: "pending",
  });
  expect(
    owner.listRecords("messages", {
      instanceIds: ["conn_a"],
      limit: 10,
      order: "asc",
    }).data,
  ).toMatchObject([{ deleted: true, confirmation: "not yet confirmed" }]);
  expect(
    receiver.readStore().getRecord("conn_a", "messages", "a")?.data.text,
  ).toBe("confirmed");
});

it("F3 bounded preview point, page, and summary work is independent of confirmed history and pending backlog", () => {
  const work: number[] = [];
  for (const size of [250, 1000]) {
    const d = device();
    d.store.ingestBatch(
      Array.from({ length: size }, (_, n) => ({
        instance: "conn_a",
        stream: "messages",
        key: String(n),
        data: { id: String(n) },
        emitted_at: at,
      })),
      () => "mutable_state",
      () => ["id"],
      { method: "collector", generation: 1 },
    );
    const receiver = stagePending(d);
    for (let n = 0; n < size / 10; n++)
      receiver.stage({
        credential: "replica-secret",
        id: `backlog-${n}`,
        envelope: batch([
          {
            ...upsert(n + 100),
            recordKey: `pending-${n}`,
            data: { id: `pending-${n}` },
          } as ReplicaOperation,
        ]),
      });
    const prepare = d.db.prepare.bind(d.db);
    let observedRows = 0;
    d.db.prepare = ((sql: string) => {
      const statement = prepare(sql);
      return new Proxy(statement, {
        get(target, property) {
          if (property === "all")
            return (...args: unknown[]) => {
              const rows = target.all(...args);
              observedRows += rows.length;
              return rows;
            };
          if (property === "get")
            return (...args: unknown[]) => {
              const row = target.get(...args);
              if (row !== undefined) observedRows++;
              return row;
            };
          if (property === "iterate")
            return function* (...args: unknown[]) {
              for (const row of target.iterate(...args)) {
                observedRows++;
                yield row;
              }
            };
          const value = Reflect.get(target, property);
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
    }) as typeof d.db.prepare;
    const owner = receiver.readStore({ reader: "owner" });
    expect(owner.getRecord("conn_a", "messages", "a")?.data.text).toBe(
      "remote-20",
    );
    expect(
      owner.listRecords("messages", {
        instanceIds: ["conn_a"],
        limit: 10,
        order: "asc",
      }).data,
    ).toHaveLength(10);
    expect(owner.listStreams(["conn_a"])[0].recordCount).toBe(
      size + 1 + size / 10,
    );
    work.push(observedRows);
  }
  // The sparse preview reads two keysets (canonical and overlay) and two stream
  // summaries; the constant must not grow with confirmed history or backlog.
  expect(work[0]).toBeLessThanOrEqual(30);
  expect(work[1]).toBeLessThanOrEqual(30);
  expect(work[1]).toBe(work[0]);
}, 20000);

it("two devices resolve conflicting pending values by the existing tuple order and recover on quarantine", () => {
  const a = device(),
    b = device();
  const left = {
    ...upsert(50),
    revision: { counter: 50, writerId: "device-a", operationId: "edit" },
    data: { id: "a", text: "left" },
  } as ReplicaOperation;
  const right = {
    ...upsert(50),
    revision: { counter: 50, writerId: "device-b", operationId: "edit" },
    data: { id: "a", text: "right" },
  } as ReplicaOperation;
  for (const [d, ops] of [
    [a, [left, right]],
    [b, [right, left]],
  ] as const) {
    put(d, "confirmed");
    const r = stagePending(
      d,
      [
        registration(),
        ops[0],
        {
          ...upsert(60),
          recordKey: "z",
          data: { id: "z" },
        } as ReplicaOperation,
      ],
      "first",
    );
    r.stage({
      credential: "replica-secret",
      id: "second",
      envelope: batch([ops[1]]),
    });
    expect(preview(r)[0]).toMatchObject({
      data: { text: "right" },
      confirmation: "not yet confirmed",
    });
    const pageOptions = {
      reader: "owner" as const,
      stream: "messages",
      instanceIds: ["conn_a"],
      limit: 1,
      order: "asc" as const,
    };
    const page = r.readRecords(pageOptions);
    expect(page.nextCursor).toBeDefined();
    const winningId = ops[0] === right ? "first" : "second";
    r.quarantine({
      credential: "replica-secret",
      id: winningId,
      reason: "unfinalized fork",
    });
    expect(() =>
      r.readRecords({ ...pageOptions, cursor: page.nextCursor }),
    ).toThrow(/expired/);
    expect(preview(r)[0]).toMatchObject({
      data: { text: "left" },
      confirmation: "not yet confirmed",
    });
  }
});

it("F1 resumes equal timestamp/key tuples across connections in both reader views and orders", () => {
  const d = device();
  d.store.registerConnection({
    instance: "conn_b",
    sourceId,
    method: "collector",
    label: "B",
  });
  for (const instance of ["conn_a", "conn_b"])
    d.store.ingestBatch(
      ["a", "b"].map((key) => ({
        instance,
        stream: "messages",
        key,
        data: { id: key },
        emitted_at: at,
      })),
      () => "mutable_state",
      () => ["id"],
      { method: "collector", generation: 1 },
    );
  const receiver = pendingReceiver(d);
  for (const reader of ["owner", "grant"] as const)
    for (const order of ["asc", "desc"] as const) {
      const rows: string[] = [];
      let cursor: string | undefined;
      do {
        const page = receiver.readRecords({
          reader,
          stream: "messages",
          instanceIds: ["conn_b", "conn_a"],
          limit: 1,
          order,
          cursor,
        });
        rows.push(
          ...page.data.map((row) => `${row.recordKey}:${row.instance}`),
        );
        cursor = page.nextCursor;
      } while (cursor && rows.length < 10);
      const expected = ["a:conn_a", "a:conn_b", "b:conn_a", "b:conn_b"];
      expect(rows).toEqual(order === "asc" ? expected : expected.reverse());
    }
});

it("F1 expires confirmed app pages on canonical changes and binds cursors to reader and connection scope", () => {
  const d = device();
  d.store.ingestBatch(
    ["a", "b"].map((key) => ({
      instance: "conn_a",
      stream: "messages",
      key,
      data: { id: key },
      emitted_at: at,
    })),
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  const receiver = pendingReceiver(d);
  const options = {
    stream: "messages",
    instanceIds: ["conn_a"],
    limit: 1,
    order: "asc" as const,
    reader: "grant" as const,
  };
  const first = receiver.readRecords(options);
  expect(first.nextCursor).toBeDefined();
  expect(() =>
    receiver.readRecords({
      ...options,
      reader: "owner",
      cursor: first.nextCursor,
    }),
  ).toThrow(/expired/);
  expect(() =>
    receiver.readRecords({
      ...options,
      instanceIds: ["conn_a", "conn_b"],
      cursor: first.nextCursor,
    }),
  ).toThrow(/expired/);
  put(d, "updated");
  expect(() =>
    receiver.readRecords({ ...options, cursor: first.nextCursor }),
  ).toThrow(/expired/);
});

it.each(["connection-reset", "connection-delete"] as const)(
  "F2 preserves removal markers for pending-only records during %s and restores on quarantine",
  (kind) => {
    const d = device();
    const receiver = stagePending(d);
    const lifecycle = {
      ...registration(),
      kind,
      generation: 2,
      ...(kind === "connection-reset" ? { previousGeneration: 1 } : {}),
      revision: { counter: 50, writerId: "remote", operationId: "lifecycle" },
    } as ReplicaOperation;
    receiver.stage({
      credential: "replica-secret",
      id: "lifecycle",
      envelope: batch([lifecycle]),
    });
    const owner = receiver.readStore({ reader: "owner" });
    expect(owner.getRecord("conn_a", "messages", "a")).toMatchObject({
      deleted: true,
      data: {},
      confirmation: "not yet confirmed",
      visibility: "pending",
    });
    expect(owner.listStreams(["conn_a"])).toMatchObject([
      {
        recordCount: 0,
        confirmation: "not yet confirmed",
        visibility: "pending",
      },
    ]);
    receiver.quarantine({
      credential: "replica-secret",
      id: "lifecycle",
      reason: "fork",
    });
    expect(owner.getRecord("conn_a", "messages", "a")).toMatchObject({
      deleted: false,
      data: { text: "remote-20" },
      visibility: "pending",
    });
    receiver.quarantine({
      credential: "replica-secret",
      id: "pending",
      reason: "fork",
    });
    expect(owner.getRecord("conn_a", "messages", "a")).toBeUndefined();
    expect(owner.listStreams(["conn_a"])).toEqual([]);
  },
);

it("F3 recovers the materialized view and pending withdrawal across restart and canonical writes without an attached receiver", () => {
  const d = device();
  const receiver = stagePending(d, [registration(), upsert(100)]);
  const options = {
    stream: "messages",
    instanceIds: ["conn_a"],
    limit: 1,
    order: "asc" as const,
    reader: "owner" as const,
  };
  receiver.stage({
    credential: "replica-secret",
    id: "other",
    envelope: batch([
      { ...upsert(101), recordKey: "z", data: { id: "z" } } as ReplicaOperation,
    ]),
  });
  const before = receiver.readRecords(options);
  d.reopen();
  put(d, "canonical-during-detach");
  const restarted = pendingReceiver(d);
  expect(() =>
    restarted.readRecords({ ...options, cursor: before.nextCursor }),
  ).toThrow(/expired/);
  expect(
    restarted
      .readStore({ reader: "owner" })
      .getRecord("conn_a", "messages", "a")?.data.text,
  ).toBe("remote-100");
  restarted.quarantine({
    credential: "replica-secret",
    id: "pending",
    reason: "fork",
  });
  expect(
    restarted
      .readStore({ reader: "owner" })
      .getRecord("conn_a", "messages", "a")?.data.text,
  ).toBe("canonical-during-detach");
  d.reopen();
  expect(
    pendingReceiver(d)
      .readStore({ reader: "owner" })
      .getRecord("conn_a", "messages", "a")?.data.text,
  ).toBe("canonical-during-detach");
});

it("F3 page continuation seeks the full indexed tuple in canonical and preview tables", () => {
  const d = device();
  d.store.ingestBatch(
    Array.from({ length: 100 }, (_, n) => ({
      instance: "conn_a",
      stream: "messages",
      key: String(n).padStart(3, "0"),
      data: { id: String(n).padStart(3, "0") },
      emitted_at: at,
    })),
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  const receiver = stagePending(d);
  const prepare = d.db.prepare.bind(d.db);
  const plans: string[] = [];
  d.db.prepare = ((sql: string) => {
    const statement = prepare(sql);
    if (!sql.startsWith("SELECT * FROM (")) return statement;
    return new Proxy(statement, {
      get(target, property) {
        if (property === "all")
          return (...args: unknown[]) => {
            plans.push(
              ...(
                prepare(`EXPLAIN QUERY PLAN ${sql}`).all(...args) as {
                  detail: string;
                }[]
              ).map((row) => row.detail),
            );
            return target.all(...args);
          };
        const value = Reflect.get(target, property);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  }) as typeof d.db.prepare;
  for (const reader of ["owner", "grant"] as const) {
    const options = {
      stream: "messages",
      instanceIds: ["conn_a"],
      limit: 10,
      order: "asc" as const,
      reader,
    };
    const page = receiver.readRecords(options);
    receiver.readRecords({ ...options, cursor: page.nextCursor });
  }
  // Owner continuation seeks the canonical keyset and the sparse overlay; the
  // confirmed-only grant continuation seeks the canonical keyset.
  expect(
    plans.filter((plan) =>
      /SEARCH .*\(instance=\? AND stream=\? AND \(emitted_key,record_key\)>\(\?,\?\)\)/.test(
        plan,
      ),
    ),
  ).toHaveLength(3);
  expect(
    plans.filter((plan) =>
      /^SCAN (r|pdpp_records|pdpp_replica_view)$/.test(plan),
    ),
  ).toEqual([]);
});

it("F1 pending-only stage and quarantine expire owner pages while confirmed app pages continue", () => {
  const d = device();
  d.store.ingestBatch(
    ["a", "b", "c"].map((key) => ({
      instance: "conn_a",
      stream: "messages",
      key,
      data: { id: key },
      emitted_at: at,
    })),
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  const receiver = pendingReceiver(d);
  const options = {
    stream: "messages",
    instanceIds: ["conn_a"],
    limit: 1,
    order: "asc" as const,
  };
  const app = receiver.readRecords({ ...options, reader: "grant" });
  const owner = receiver.readRecords({ ...options, reader: "owner" });
  receiver.stage({
    credential: "replica-secret",
    id: "pending",
    envelope: batch([
      registration(),
      { ...upsert(50), recordKey: "z", data: { id: "z" } } as ReplicaOperation,
    ]),
  });
  expect(() =>
    receiver.readRecords({
      ...options,
      reader: "owner",
      cursor: owner.nextCursor,
    }),
  ).toThrow(/expired/);
  const appSecond = receiver.readRecords({
    ...options,
    reader: "grant",
    cursor: app.nextCursor,
  });
  expect(appSecond.data[0].recordKey).toBe("b");
  const ownerCurrent = receiver.readRecords({ ...options, reader: "owner" });
  receiver.quarantine({
    credential: "replica-secret",
    id: "pending",
    reason: "fork",
  });
  expect(() =>
    receiver.readRecords({
      ...options,
      reader: "owner",
      cursor: ownerCurrent.nextCursor,
    }),
  ).toThrow(/expired/);
  expect(
    receiver.readRecords({
      ...options,
      reader: "grant",
      cursor: appSecond.nextCursor,
    }).data[0].recordKey,
  ).toBe("c");
});

it("F3 redundant compatible registration staging reconciles only affected keys", () => {
  const work: number[] = [];
  for (const size of [20, 200]) {
    const d = device();
    d.store.ingestBatch(
      Array.from({ length: size }, (_, n) => ({
        instance: "conn_a",
        stream: "messages",
        key: String(n),
        data: { id: String(n) },
        emitted_at: at,
      })),
      () => "mutable_state",
      () => ["id"],
      { method: "collector", generation: 1 },
    );
    const receiver = pendingReceiver(d);
    const prepare = d.db.prepare.bind(d.db);
    let observed = 0;
    d.db.prepare = ((sql: string) => {
      const statement = prepare(sql);
      return new Proxy(statement, {
        get(target, property) {
          if (property === "all")
            return (...args: unknown[]) => {
              const rows = target.all(...args);
              observed += rows.length;
              return rows;
            };
          if (property === "get")
            return (...args: unknown[]) => {
              const row = target.get(...args);
              if (row !== undefined) observed++;
              return row;
            };
          const value = Reflect.get(target, property);
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
    }) as typeof d.db.prepare;
    receiver.stage({
      credential: "replica-secret",
      id: "pending",
      envelope: batch([registration(), upsert(50)]),
    });
    work.push(observed);
  }
  expect(work[1]).toBe(work[0]);
  expect(work[1]).toBeLessThan(40);
});

it.each(["pending", "confirmed"] as const)(
  "retry revalidates trusted declarations for %s rows and restores visibility",
  (state) => {
    const d = device();
    let allowed = true;
    let trusted: MergeContext["declarations"] = [
      {
        sourceId,
        binding,
        validateData: (data) => allowed && typeof data.id === "string",
      },
    ];
    const receiver = createReplicaReceiver({
      db: d.db,
      store: d.store,
      owner: "owner",
      enabled: true,
      authenticate: (credential) =>
        credential === "replica-secret" ? "owner" : undefined,
      declarations: () => trusted,
    });
    if (state === "pending")
      receiver.stage({
        credential: "replica-secret",
        id: "pending",
        envelope: batch([registration(), upsert()]),
      });
    else
      receiver.import({
        credential: "replica-secret",
        envelope: batch([registration(), upsert()]),
      });
    const owner = receiver.readStore({ reader: "owner" });
    const assertVisible = () => {
      expect(owner.getRecord("conn_a", "messages", "a")).toMatchObject({
        deleted: false,
        data: { text: "remote-20" },
      });
      expect(owner.getRecord("conn_a", "messages", "a")?.confirmation).toBe(
        state === "pending" ? "not yet confirmed" : undefined,
      );
      expect(
        receiver.readStore().getRecord("conn_a", "messages", "a")?.data.text,
      ).toBe(state === "confirmed" ? "remote-20" : undefined);
    };
    const assertWithdrawn = () => {
      expect(owner.getRecord("conn_a", "messages", "a")).toBeUndefined();
      expect(
        owner.listRecords("messages", {
          instanceIds: ["conn_a"],
          limit: 10,
          order: "asc",
        }).data,
      ).toEqual([]);
      expect(owner.listStreams(["conn_a"])).toEqual([]);
      expect(
        receiver.readStore().getRecord("conn_a", "messages", "a"),
      ).toBeUndefined();
    };
    assertVisible();
    allowed = false;
    receiver.reconcileDeclarations({ credential: "replica-secret" });
    assertWithdrawn();
    allowed = true;
    receiver.reconcileDeclarations({ credential: "replica-secret" });
    assertVisible();
    const original = trusted;
    trusted = [];
    receiver.reconcileDeclarations({ credential: "replica-secret" });
    assertWithdrawn();
    trusted = original;
    receiver.reconcileDeclarations({ credential: "replica-secret" });
    assertVisible();
  },
);

// The hardening lane owns migration 18 and the fact writer. This exact fixture
// composes its read seam without implementing source-identity decisions here.
function installBindingConflictFixture(d: ReturnType<typeof device>) {
  d.db
    .exec(`CREATE TABLE IF NOT EXISTS pdpp_replica_binding_conflicts (instance TEXT PRIMARY KEY, reason TEXT NOT NULL, evidence_json TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_pdpp_replica_own_writes_local_key ON pdpp_replica_own_writes(connection_id,generation,stream,record_key,sequence DESC);`);
  return (instance = "conn_a") => {
    d.db
      .prepare(
        "INSERT INTO pdpp_replica_binding_conflicts VALUES (?, 'source_binding_conflict', '{}')",
      )
      .run(instance);
  };
}

it.each([false, true])(
  "account conflict exposes only the local journal value to owners with pending enabled=%s",
  (enabled) => {
    const d = device();
    const conflict = installBindingConflictFixture(d);
    put(d, "known-local");
    const local = value(d)!;
    const receiver = pendingReceiver(d, true, {
      owner: "confirmed-only",
      grant: "confirmed-only",
    });
    receiver.import({
      credential: "replica-secret",
      envelope: batch([
        registration(),
        upsert(500),
        {
          ...upsert(501),
          recordKey: "received-only",
          data: { id: "received-only" },
        } as ReplicaOperation,
      ]),
    });
    receiver.stage({
      credential: "replica-secret",
      id: "pending",
      envelope: batch([upsert(600)]),
    });
    receiver.setPendingEnabled(enabled);
    const canonicalBefore = d.db.prepare("SELECT * FROM pdpp_records").all();
    const historyBefore = d.db
      .prepare("SELECT * FROM pdpp_record_changes")
      .all();
    conflict();
    const owner = receiver.readStore({ reader: "owner" });
    expect(owner.getRecord("conn_a", "messages", "a")).toEqual({
      ...local,
      visibility: "conflicted",
      status: "account conflict",
    });
    expect(
      owner.getRecord("conn_a", "messages", "received-only"),
    ).toBeUndefined();
    expect(
      owner.listRecords("messages", {
        instanceIds: ["conn_a"],
        limit: 1,
        order: "asc",
      }).data,
    ).toEqual([
      { ...local, visibility: "conflicted", status: "account conflict" },
    ]);
    expect(owner.listStreams(["conn_a"])).toMatchObject([
      { recordCount: 1, visibility: "conflicted", status: "account conflict" },
    ]);
    expect(owner.connectionVisibility("conn_a")).toEqual({
      state: "conflicted",
      reason: "source_binding",
    });
    const grant = receiver.readStore();
    expect(grant.getRecord("conn_a", "messages", "a")).toBeUndefined();
    expect(
      grant.listRecords("messages", {
        instanceIds: ["conn_a"],
        limit: 10,
        order: "asc",
      }).data,
    ).toEqual([]);
    expect(grant.listStreams(["conn_a"])).toEqual([]);
    expect(d.db.prepare("SELECT * FROM pdpp_records").all()).toEqual(
      canonicalBefore,
    );
    expect(d.db.prepare("SELECT * FROM pdpp_record_changes").all()).toEqual(
      historyBefore,
    );
  },
);

it("account conflict keeps local tombstones, current-generation identity, and installation provenance authoritative", () => {
  const d = device();
  const conflict = installBindingConflictFixture(d);
  put(d, "deleted-local");
  d.store.deleteRecord("conn_a", "messages", "a", at, "mutable_state");
  const receiver = pendingReceiver(d);
  receiver.import({
    credential: "replica-secret",
    envelope: batch([registration(), upsert(500)]),
  });
  conflict();
  expect(
    receiver
      .readStore({ reader: "owner" })
      .getRecord("conn_a", "messages", "a"),
  ).toBeUndefined();
  d.store.resetInstanceBinding({
    instance: "conn_a",
    expectedMethod: "collector",
    expectedGeneration: 1,
    nextMethod: "collector",
  });
  d.store.ingestBatch(
    [
      {
        instance: "conn_a",
        stream: "messages",
        key: "b",
        data: { id: "b", text: "current-local" },
        emitted_at: at,
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 2 },
  );
  const local = d.store.getRecord("conn_a", "messages", "b")!;
  d.db
    .prepare(
      `INSERT INTO pdpp_replica_own_writes(operation_id,writer_id,source_id,connection_id,method,generation,stream,record_key,operation,value_json,blob_ids_json)
    SELECT 'foreign-journal-writer','foreign',source_id,connection_id,method,generation,stream,record_key,operation,json_set(value_json,'$.data.text','foreign'),blob_ids_json FROM pdpp_replica_own_writes WHERE record_key='b' ORDER BY sequence DESC LIMIT 1`,
    )
    .run();
  receiver.retry({ credential: "replica-secret" });
  const owner = receiver.readStore({ reader: "owner" });
  expect(owner.getRecord("conn_a", "messages", "a")).toBeUndefined();
  expect(owner.getRecord("conn_a", "messages", "b")).toEqual({
    ...local,
    visibility: "conflicted",
    status: "account conflict",
  });
  d.reopen();
  expect(
    pendingReceiver(d)
      .readStore({ reader: "owner" })
      .getRecord("conn_a", "messages", "b"),
  ).toEqual({ ...local, visibility: "conflicted", status: "account conflict" });
});

it("account conflict grants no local provenance to unbound legacy journal rows", () => {
  const d = device(false);
  const conflict = installBindingConflictFixture(d);
  d.store.ingestBatch(
    [
      {
        instance: "legacy",
        stream: "messages",
        key: "a",
        data: { id: "a" },
        emitted_at: at,
      },
    ],
    () => "mutable_state",
    () => ["id"],
  );
  const receiver = pendingReceiver(d);
  conflict("legacy");
  expect(
    receiver
      .readStore({ reader: "owner" })
      .getRecord("legacy", "messages", "a"),
  ).toBeUndefined();
  expect(
    receiver.readStore({ reader: "owner" }).listStreams(["legacy"]),
  ).toEqual([]);
});

it("account conflict local blobs follow local journal references and corruption quarantine always wins at read time", () => {
  const d = device();
  const conflict = installBindingConflictFixture(d);
  const bytes = new Uint8Array([1, 7, 9]);
  const blob = d.store.storeBlobBytesForInstance({
    instance: "conn_a",
    method: "collector",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  d.store.ingestBatch(
    [
      {
        instance: "conn_a",
        stream: "messages",
        key: "a",
        data: { id: "a", blob_ref: { blob_id: blob.blobId } },
        emitted_at: at,
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  const receiver = pendingReceiver(d);
  receiver.import({
    credential: "replica-secret",
    envelope: batch([registration(), upsert(500)]),
  });
  conflict();
  const owner = receiver.readStore({ reader: "owner" });
  expect(owner.findBlobReferences(blob.blobId)).toEqual([
    { instance: "conn_a", stream: "messages", recordKey: "a" },
  ]);
  expect(owner.getBlobMeta(blob.blobId)).toEqual(blob);
  expect([...owner.getBlobBytes(blob.blobId)!]).toEqual([...bytes]);
  expect(receiver.readStore().findBlobReferences(blob.blobId)).toEqual([]);
  expect(receiver.readStore().getBlobMeta(blob.blobId)).toBeUndefined();
  expect(receiver.readStore().getBlobBytes(blob.blobId)).toBeUndefined();
  d.db
    .prepare(
      "INSERT INTO pdpp_replica_quarantined_keys VALUES ('conn_a',1,'messages','a')",
    )
    .run();
  expect(owner.getRecord("conn_a", "messages", "a")).toBeUndefined();
  expect(
    owner.listRecords("messages", {
      instanceIds: ["conn_a"],
      limit: 10,
      order: "asc",
    }).data,
  ).toEqual([]);
  expect(owner.findBlobReferences(blob.blobId)).toEqual([]);
  expect(owner.getBlobBytes(blob.blobId)).toBeUndefined();
});

it.each(["owner", "grant"] as const)(
  "corruption quarantine filters stale %s materializations on point, page, and blob reads",
  (reader) => {
    const d = device();
    put(d, "local");
    const receiver = stagePending(d);
    const read = receiver.readStore({ reader });
    expect(read.getRecord("conn_a", "messages", "a")).toBeDefined();
    d.db
      .prepare(
        "INSERT INTO pdpp_replica_quarantined_keys VALUES ('conn_a',1,'messages','a')",
      )
      .run();
    expect(read.getRecord("conn_a", "messages", "a")).toBeUndefined();
    expect(
      read.listRecords("messages", {
        instanceIds: ["conn_a"],
        limit: 10,
        order: "asc",
      }).data,
    ).toEqual([]);
  },
);

it.each(["owner", "grant"] as const)(
  "F1 %s cursor ignores unrelated connection canonical and pending mutations",
  (reader) => {
    const d = device();
    d.store.registerConnection({
      instance: "conn_b",
      sourceId,
      method: "collector",
      label: "B",
    });
    d.store.ingestBatch(
      ["a", "b", "c", "d"].map((key) => ({
        instance: "conn_a",
        stream: "messages",
        key,
        data: { id: key },
        emitted_at: at,
      })),
      () => "mutable_state",
      () => ["id"],
      { method: "collector", generation: 1 },
    );
    const receiver = pendingReceiver(d);
    const options = {
      reader,
      stream: "messages",
      instanceIds: ["conn_a"],
      limit: 1,
      order: "asc" as const,
    };
    const first = receiver.readRecords(options);
    d.store.ingestBatch(
      [
        {
          instance: "conn_b",
          stream: "messages",
          key: "other",
          data: { id: "other" },
          emitted_at: at,
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "collector", generation: 1 },
    );
    const second = receiver.readRecords({
      ...options,
      cursor: first.nextCursor,
    });
    expect(second.data[0].recordKey).toBe("b");
    receiver.stage({
      credential: "replica-secret",
      id: "unrelated",
      envelope: batch([
        {
          ...upsert(90),
          connectionId: "conn_b",
          recordKey: "remote",
          data: { id: "remote" },
        } as ReplicaOperation,
      ]),
    });
    const third = receiver.readRecords({
      ...options,
      cursor: second.nextCursor,
    });
    expect(third.data[0].recordKey).toBe("c");
    receiver.quarantine({
      credential: "replica-secret",
      id: "unrelated",
      reason: "fork",
    });
    expect(
      receiver.readRecords({ ...options, cursor: third.nextCursor }).data[0]
        .recordKey,
    ).toBe("d");
  },
);

it("corruption quarantine excludes retained canonical rows from flag-off stream summaries", () => {
  const d = device();
  d.store.ingestBatch(
    ["a", "b"].map((key) => ({
      instance: "conn_a",
      stream: "messages",
      key,
      data: { id: key },
      emitted_at: at,
    })),
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  const receiver = pendingReceiver(d, false);
  d.db
    .prepare(
      "INSERT INTO pdpp_replica_quarantined_keys VALUES ('conn_a',1,'messages','a')",
    )
    .run();
  expect(
    receiver.readStore({ reader: "owner" }).listStreams(["conn_a"]),
  ).toMatchObject([{ recordCount: 1 }]);
  expect(receiver.readStore().listStreams(["conn_a"])).toMatchObject([
    { recordCount: 1 },
  ]);
});

it.each(["owner", "grant"] as const)(
  "F1 mixed-scope %s pages ignore hidden conflicted received and pending churn",
  (reader) => {
    const d = device();
    const conflict = installBindingConflictFixture(d);
    put(d, "known-local");
    d.store.registerConnection({
      instance: "conn_b",
      sourceId,
      method: "collector",
      label: "B",
    });
    d.store.ingestBatch(
      ["b", "c", "d", "e", "f"].map((key) => ({
        instance: "conn_b",
        stream: "messages",
        key,
        data: { id: key },
        emitted_at: at,
      })),
      () => "mutable_state",
      () => ["id"],
      { method: "collector", generation: 1 },
    );
    const receiver = pendingReceiver(d);
    conflict();
    const options = {
      reader,
      stream: "messages",
      instanceIds: ["conn_a", "conn_b"],
      limit: 1,
      order: "asc" as const,
    };
    let page = receiver.readRecords(options);
    const ownerBefore = receiver.readRecords({ ...options, reader: "owner" });
    receiver.import({
      credential: "replica-secret",
      envelope: batch([registration(), upsert(500)]),
    });
    page = receiver.readRecords({ ...options, cursor: page.nextCursor });
    receiver.stage({
      credential: "replica-secret",
      id: "hidden",
      envelope: batch([upsert(600)]),
    });
    page = receiver.readRecords({ ...options, cursor: page.nextCursor });
    receiver.quarantine({
      credential: "replica-secret",
      id: "hidden",
      reason: "fork",
    });
    page = receiver.readRecords({ ...options, cursor: page.nextCursor });
    // A real local-journal mutation changes the owner projection, while remaining
    // invisible to the app. The fixture appends through the installation writer.
    d.db
      .prepare(
        `INSERT INTO pdpp_replica_own_writes(operation_id,writer_id,source_id,connection_id,method,generation,stream,record_key,operation,value_json,blob_ids_json)
    SELECT 'next-local-value',writer_id,source_id,connection_id,method,generation,stream,record_key,operation,json_set(value_json,'$.data.text','new-local','$.version',2),blob_ids_json FROM pdpp_replica_own_writes WHERE connection_id='conn_a' ORDER BY sequence DESC LIMIT 1`,
      )
      .run();
    expect(() =>
      receiver.readRecords({
        ...options,
        reader: "owner",
        cursor: ownerBefore.nextCursor,
      }),
    ).toThrow(/expired/);
    if (reader === "grant")
      expect(
        receiver.readRecords({ ...options, cursor: page.nextCursor }).data[0]
          .recordKey,
      ).toBe("f");
  },
);

it("canonical change feeds validate original scope, exclude all conflicted history, and apply the shared quarantine predicate", () => {
  const d = device();
  const conflict = installBindingConflictFixture(d);
  d.store.ingestBatch(
    ["a", "healthy"].map((key) => ({
      instance: "conn_a",
      stream: "messages",
      key,
      data: { id: key },
      emitted_at: at,
    })),
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  d.store.registerConnection({
    instance: "conn_b",
    sourceId,
    method: "collector",
    label: "B",
  });
  d.store.ingestBatch(
    [
      {
        instance: "conn_b",
        stream: "messages",
        key: "b",
        data: { id: "b" },
        emitted_at: at,
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  const receiver = pendingReceiver(d);
  d.db
    .prepare(
      "INSERT INTO pdpp_replica_quarantined_keys VALUES ('conn_a',1,'messages','a')",
    )
    .run();
  const options = { instanceIds: ["conn_a", "conn_b"], limit: 10 };
  expect(
    receiver
      .readStore()
      .changesSince("messages", options)
      .data.map((row) => row.recordKey),
  ).toEqual(["b", "healthy"]);
  const old = receiver
    .readStore()
    .changesSince("messages", { ...options, limit: 1 });
  conflict();
  const clock = d.db
    .prepare(
      "UPDATE pdpp_write_clock SET value=value+1 WHERE id=1 RETURNING value",
    )
    .get() as { value: number };
  d.db
    .prepare(
      "UPDATE pdpp_instance_binding SET reset_clock=? WHERE instance='conn_a'",
    )
    .run(clock.value);
  for (const reader of ["owner", "grant"] as const) {
    const read = receiver.readStore({ reader });
    expect(() =>
      read.changesSince("messages", { ...options, cursor: old.nextCursor }),
    ).toThrow(/expired/);
    expect(
      read.changesSince("messages", options).data.map((row) => row.recordKey),
    ).toEqual(["b"]);
    const hidden = read.changesSince("messages", {
      instanceIds: ["conn_a"],
      limit: 10,
    });
    expect(hidden.data).toEqual([]);
    expect(hidden.nextChangesSince).toBeDefined();
  }
  expect(
    d.store.changesSinceForInstances(
      "messages",
      { instanceIds: ["conn_a"], limit: 10 },
      ["conn_b"],
    ).data,
  ).toEqual([]);
});

/** conn_a's "a" and conn_b's "b" reference one blob; legacy rows hold up to 1 MiB. */
function sharedBlob(form: "legacy" | "chunks") {
  const source = device(),
    target = device();
  for (const d of [source, target])
    d.store.registerConnection({
      instance: "conn_b",
      sourceId,
      method: "collector",
      label: "B",
    });
  const size = form === "legacy" ? 3 : 1024 * 1024 + 4096;
  const bytes = new Uint8Array(size).map((_, i) => (i + 1) % 251);
  let blob!: ReturnType<typeof source.store.storeBlobBytesForInstance>;
  for (const [instance, key] of [
    ["conn_a", "a"],
    ["conn_b", "b"],
  ]) {
    blob = source.store.storeBlobBytesForInstance({
      instance,
      method: "collector",
      generation: 1,
      bytes,
      mimeType: "application/octet-stream",
    });
    source.store.ingestBatch(
      [
        {
          instance,
          stream: "messages",
          key,
          emitted_at: at,
          data: {
            id: key,
            blob_ref: {
              blob_id: blob.blobId,
              sha256: blob.sha256,
              size_bytes: blob.sizeBytes,
              mime_type: blob.mimeType,
            },
          },
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "collector", generation: 1 },
    );
  }
  const ops = all(source);
  const receiver = pendingReceiver(target);
  return {
    target,
    receiver,
    owner: receiver.readStore({ reader: "owner" }),
    bytes,
    blob,
    a: ops.filter((op) => op.connectionId === "conn_a"),
    b: ops.filter((op) => op.connectionId === "conn_b"),
    /** Stage conn_b's batch as a carrier of the bytes, as a legacy row or chunks. */
    carry(id: string) {
      if (form === "legacy")
        receiver.stage({
          credential: "replica-secret",
          id,
          envelope: batch(this.b),
          blobs: [{ blobId: blob.blobId, bytes }],
        });
      else {
        const writer = binaryWriter(target.db, "staging", `${id}-stage`);
        writer.write(bytes);
        writer.finish();
        receiver.stage({
          credential: "replica-secret",
          id,
          envelope: batch(this.b),
          stagedBlobs: [
            { blobId: blob.blobId, key: `${id}-stage`, sizeBytes: size },
          ],
        });
      }
    },
    rederive() {
      receiver.reconcileDeclarations({ credential: "replica-secret" });
    },
  };
}
/** Flip one byte of a stored copy, keeping its length; returns the restore. */
function tamper(
  d: ReturnType<typeof device>,
  copy:
    | { table: "pdpp_replica_received_bytes"; blobId: string }
    | { table: "pdpp_replica_pending_bytes"; blobId: string; batchId: string }
    | { table: "pdpp_binary_chunks"; namespace: string; id: string },
) {
  const [select, update, args] =
    copy.table === "pdpp_binary_chunks"
      ? [
          "SELECT bytes FROM pdpp_binary_chunks WHERE namespace=? AND blob_id=? AND position=0",
          "UPDATE pdpp_binary_chunks SET bytes=? WHERE namespace=? AND blob_id=? AND position=0",
          [copy.namespace, copy.id],
        ]
      : copy.table === "pdpp_replica_pending_bytes"
        ? [
            "SELECT bytes FROM pdpp_replica_pending_bytes WHERE blob_id=? AND batch_id=?",
            "UPDATE pdpp_replica_pending_bytes SET bytes=? WHERE blob_id=? AND batch_id=?",
            [copy.blobId, copy.batchId],
          ]
        : [
            "SELECT bytes FROM pdpp_replica_received_bytes WHERE blob_id=?",
            "UPDATE pdpp_replica_received_bytes SET bytes=? WHERE blob_id=?",
            [copy.blobId],
          ];
  const { bytes } = d.db.prepare(select).get(...args) as { bytes: Buffer };
  const changed = Buffer.from(bytes);
  changed[0] ^= 0xff;
  expect(d.db.prepare(update).run(changed, ...args).changes).toBe(1);
  return () => d.db.prepare(update).run(bytes, ...args);
}

it.each([
  ["canonical", "legacy", "owner"],
  ["canonical", "legacy", "grant"],
  ["canonical", "chunks", "owner"],
  ["canonical", "chunks", "grant"],
  ["materialized", "chunks", "owner"],
  ["materialized", "chunks", "grant"],
] as const)(
  "preserves byte integrity for %s blobs stored as %s read by %s",
  (origin, form, reader) => {
    const source = device();
    const target = origin === "canonical" ? source : device();
    installBindingConflictFixture(target);
    // Store writes keep a legacy row up to 1 MiB; materialization always chunks.
    const bytes = new Uint8Array(
      form === "legacy" ? 3 : 1024 * 1024 + 4096,
    ).map((_, i) => (i + 4) % 251);
    const blob = source.store.storeBlobBytesForInstance({
      instance: "conn_a",
      method: "collector",
      generation: 1,
      bytes,
      mimeType: "application/octet-stream",
    });
    source.store.ingestBatch(
      [
        {
          instance: "conn_a",
          stream: "messages",
          key: "a",
          emitted_at: at,
          data: {
            id: "a",
            blob_ref: {
              blob_id: blob.blobId,
              sha256: blob.sha256,
              size_bytes: blob.sizeBytes,
              mime_type: blob.mimeType,
            },
          },
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "collector", generation: 1 },
    );
    const receiver = pendingReceiver(target);
    if (origin === "materialized")
      receiver.import({
        credential: "replica-secret",
        envelope: batch(all(source)),
        blobs: [{ blobId: blob.blobId, bytes }],
      });
    const read = receiver.readStore({ reader });
    expect(Array.from(read.getBlobBytes(blob.blobId)!)).toEqual(
      Array.from(bytes),
    );
    const restore =
      form === "legacy"
        ? (() => {
            const before = target.db
              .prepare("SELECT bytes FROM pdpp_blob_bytes WHERE blob_id=?")
              .get(blob.blobId) as { bytes: Buffer };
            const changed = Buffer.from(before.bytes);
            changed[0] ^= 0xff;
            expect(
              target.db
                .prepare("UPDATE pdpp_blob_bytes SET bytes=? WHERE blob_id=?")
                .run(changed, blob.blobId).changes,
            ).toBe(1);
            return () =>
              target.db
                .prepare("UPDATE pdpp_blob_bytes SET bytes=? WHERE blob_id=?")
                .run(before.bytes, blob.blobId);
          })()
        : tamper(target, {
            table: "pdpp_binary_chunks",
            namespace: "canonical",
            id: blob.blobId,
          });
    expect(read.getBlobBytes(blob.blobId)).toBeUndefined();
    restore();
    expect(Array.from(read.getBlobBytes(blob.blobId)!)).toEqual(
      Array.from(bytes),
    );
  },
);

it.each([
  ["received", "legacy"],
  ["received", "chunks"],
  ["pending", "legacy"],
  ["pending", "chunks"],
] as const)(
  "preserves byte integrity for owner-visible %s bytes stored as %s",
  (origin, form) => {
    const f = sharedBlob(form);
    if (origin === "received") {
      f.receiver.import({
        credential: "replica-secret",
        envelope: batch(f.a.filter((op) => op.kind !== "upsert")),
        blobs: [{ blobId: f.blob.blobId, bytes: f.bytes }],
      });
      f.receiver.stage({
        credential: "replica-secret",
        id: "dependent",
        envelope: batch(f.a.filter((op) => op.kind === "upsert")),
      });
    } else f.carry("carrier");
    expect(Array.from(f.owner.getBlobBytes(f.blob.blobId)!)).toEqual(
      Array.from(f.bytes),
    );
    const restore = tamper(
      f.target,
      origin === "received"
        ? form === "legacy"
          ? { table: "pdpp_replica_received_bytes", blobId: f.blob.blobId }
          : {
              table: "pdpp_binary_chunks",
              namespace: "received",
              id: f.blob.blobId,
            }
        : form === "legacy"
          ? {
              table: "pdpp_replica_pending_bytes",
              blobId: f.blob.blobId,
              batchId: "carrier",
            }
          : {
              table: "pdpp_binary_chunks",
              namespace: "pending",
              id: JSON.stringify(["carrier", f.blob.blobId]),
            },
    );
    expect(f.owner.getBlobBytes(f.blob.blobId)).toBeUndefined();
    restore();
    expect(Array.from(f.owner.getBlobBytes(f.blob.blobId)!)).toEqual(
      Array.from(f.bytes),
    );
  },
);

it.each(["legacy", "chunks"] as const)(
  "hides a pending blob record and its bytes when its retained received copy is corrupt, as promotion would (%s)",
  (form) => {
    const f = sharedBlob(form);
    f.receiver.import({
      credential: "replica-secret",
      envelope: batch(f.a.filter((op) => op.kind !== "upsert")),
      blobs: [{ blobId: f.blob.blobId, bytes: f.bytes }],
    });
    f.receiver.stage({
      credential: "replica-secret",
      id: "dependent",
      envelope: batch(f.a.filter((op) => op.kind === "upsert")),
    });
    // Another pending batch holds a valid copy.
    f.carry("carrier");
    expect(f.owner.getRecord("conn_a", "messages", "a")).toBeDefined();
    expect(f.owner.getBlobBytes(f.blob.blobId)?.byteLength).toBe(
      f.bytes.length,
    );
    const restore = tamper(
      f.target,
      form === "legacy"
        ? { table: "pdpp_replica_received_bytes", blobId: f.blob.blobId }
        : {
            table: "pdpp_binary_chunks",
            namespace: "received",
            id: f.blob.blobId,
          },
    );
    f.rederive();
    // Promotion refuses a corrupt retained copy, so the preview must not
    // show the record; nor may it advertise bytes it cannot serve.
    expect(f.owner.getRecord("conn_a", "messages", "a")).toBeUndefined();
    expect(f.owner.getBlobBytes(f.blob.blobId)).toBeUndefined();
    restore();
    f.rederive();
    expect(f.owner.getRecord("conn_a", "messages", "a")).toBeDefined();
    expect(Array.from(f.owner.getBlobBytes(f.blob.blobId)!)).toEqual(
      Array.from(f.bytes),
    );
  },
);

it.each(["legacy", "chunks"] as const)(
  "serves pending custody from a copy that verifies when another pending copy is corrupt (%s)",
  (form) => {
    const f = sharedBlob(form);
    f.receiver.stage({
      credential: "replica-secret",
      id: "dependent",
      envelope: batch(f.a),
    });
    f.carry("carrier-1");
    f.carry("carrier-2");
    tamper(
      f.target,
      form === "legacy"
        ? {
            table: "pdpp_replica_pending_bytes",
            blobId: f.blob.blobId,
            batchId: "carrier-1",
          }
        : {
            table: "pdpp_binary_chunks",
            namespace: "pending",
            id: JSON.stringify(["carrier-1", f.blob.blobId]),
          },
    );
    f.rederive();
    expect(f.owner.getRecord("conn_a", "messages", "a")).toBeDefined();
    expect(Array.from(f.owner.getBlobBytes(f.blob.blobId)!)).toEqual(
      Array.from(f.bytes),
    );
  },
);

// A legacy row's size is length(bytes), so only a chunk manifest can hold a
// malformed size. It must count as a present, failing copy, never as absent.
it.each([
  ["received", -1],
  ["received", 1.5],
  ["received", 2 ** 53],
  ["canonical", -1],
  ["canonical", 1.5],
  ["canonical", 2 ** 53],
] as const)(
  "a retained %s manifest with malformed size %s vetoes a valid pending copy",
  (namespace, malformed) => {
    const f = sharedBlob("chunks");
    if (namespace === "received") {
      f.receiver.import({
        credential: "replica-secret",
        envelope: batch(f.a.filter((op) => op.kind !== "upsert")),
        blobs: [{ blobId: f.blob.blobId, bytes: f.bytes }],
      });
      f.receiver.stage({
        credential: "replica-secret",
        id: "dependent",
        envelope: batch(f.a.filter((op) => op.kind === "upsert")),
      });
    } else {
      // Canonical chunks only: the store's own write of a blob over 1 MiB.
      f.target.store.storeBlobBytesForInstance({
        instance: "conn_a",
        method: "collector",
        generation: 1,
        bytes: f.bytes,
        mimeType: f.blob.mimeType,
      });
      f.receiver.stage({
        credential: "replica-secret",
        id: "dependent",
        envelope: batch(f.a),
      });
    }
    f.carry("carrier");
    expect(f.owner.getRecord("conn_a", "messages", "a")).toBeDefined();
    const size = (value: number) =>
      f.target.db
        .prepare(
          "UPDATE pdpp_binary_manifests SET size_bytes=? WHERE namespace=? AND blob_id=?",
        )
        .run(value, namespace, f.blob.blobId).changes;
    expect(size(malformed)).toBe(1);
    f.rederive();
    expect(f.owner.getRecord("conn_a", "messages", "a")).toBeUndefined();
    expect(f.owner.getBlobBytes(f.blob.blobId)).toBeUndefined();
    size(f.bytes.length);
    f.rederive();
    expect(f.owner.getRecord("conn_a", "messages", "a")).toBeDefined();
    expect(f.owner.getBlobBytes(f.blob.blobId)?.byteLength).toBe(
      f.bytes.length,
    );
  },
);

// A repair write adds a legacy row in a namespace whose manifest is
// malformed. The read side vetoes on the manifest even beside a legacy row,
// so the write clears the malformed manifest in its own transaction.
it.each([
  ["received", -1],
  ["received", 1.5],
  ["received", 2 ** 53],
  ["canonical", -1],
  ["canonical", 1.5],
  ["canonical", 2 ** 53],
] as const)(
  "a repair write over a malformed %s manifest (size %s) clears it in the same transaction, so the repaired bytes serve",
  (namespace, malformed) => {
    const source = device(),
      target = device();
    const bytes = new Uint8Array([1, 2, 3]);
    const blob = source.store.storeBlobBytesForInstance({
      instance: "conn_a",
      method: "collector",
      generation: 1,
      bytes,
      mimeType: "application/octet-stream",
    });
    source.store.ingestBatch(
      [
        {
          instance: "conn_a",
          stream: "messages",
          key: "a",
          emitted_at: at,
          data: {
            id: "a",
            blob_ref: {
              blob_id: blob.blobId,
              sha256: blob.sha256,
              size_bytes: blob.sizeBytes,
              mime_type: blob.mimeType,
            },
          },
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "collector", generation: 1 },
    );
    const ops = all(source);
    const receiver = pendingReceiver(target);
    // Transport import: staged chunks become received and canonical chunks.
    const writer = binaryWriter(target.db, "staging", "transport");
    writer.write(bytes);
    writer.finish();
    receiver.import({
      credential: "replica-secret",
      envelope: batch(ops),
      stagedBlobs: [{ blobId: blob.blobId, key: "transport", sizeBytes: 3 }],
    });
    const served = () =>
      (["owner", "grant"] as const).map(
        (reader) =>
          receiver.readStore({ reader }).getBlobBytes(blob.blobId)?.length,
      );
    expect(served()).toEqual([3, 3]);
    if (namespace === "canonical") {
      // Promotion stores a blob this small inline; store it chunked, as
      // canonical storage holds a blob over 1 MiB.
      target.db
        .prepare("DELETE FROM pdpp_blob_bytes WHERE blob_id=?")
        .run(blob.blobId);
      const chunked = binaryWriter(target.db, "canonical", blob.blobId);
      chunked.write(bytes);
      chunked.finish();
      expect(served()).toEqual([3, 3]);
    }
    const size = (value: number) =>
      target.db
        .prepare(
          "UPDATE pdpp_binary_manifests SET size_bytes=? WHERE namespace=? AND blob_id=?",
        )
        .run(value, namespace, blob.blobId).changes;
    expect(size(malformed)).toBe(1);
    expect(served()).toEqual([undefined, undefined]);
    // Supported writes of the same valid bytes add a legacy row and clear the
    // malformed manifest.
    if (namespace === "received")
      receiver.import({
        credential: "replica-secret",
        envelope: batch(ops),
        blobs: [{ blobId: blob.blobId, bytes }],
      });
    else
      target.store.storeBlobBytesForInstance({
        instance: "conn_a",
        method: "collector",
        generation: 1,
        bytes,
        mimeType: "application/octet-stream",
      });
    expect(
      target.db
        .prepare(
          `SELECT count(*) AS n FROM ${namespace === "received" ? "pdpp_replica_received_bytes" : "pdpp_blob_bytes"} WHERE blob_id=?`,
        )
        .get(blob.blobId),
    ).toEqual({ n: 1 });
    expect(size(3)).toBe(0);
    expect(served()).toEqual([3, 3]);
  },
);

it("refuses a forged chunk manifest size before allocating it", () => {
  const f = sharedBlob("chunks");
  f.receiver.import({
    credential: "replica-secret",
    envelope: batch(f.a.filter((op) => op.kind !== "upsert")),
    blobs: [{ blobId: f.blob.blobId, bytes: f.bytes }],
  });
  f.receiver.stage({
    credential: "replica-secret",
    id: "dependent",
    envelope: batch(f.a.filter((op) => op.kind === "upsert")),
  });
  expect(f.owner.getBlobBytes(f.blob.blobId)?.byteLength).toBe(f.bytes.length);
  f.target.db
    .prepare(
      "UPDATE pdpp_binary_manifests SET size_bytes=? WHERE namespace='received' AND blob_id=?",
    )
    .run(2 ** 40, f.blob.blobId);
  // The visible descriptor claims the real size; the read fails closed.
  expect(f.owner.getBlobBytes(f.blob.blobId)).toBeUndefined();
});

it("never reads a whole blob value through its store to decide preview visibility", () => {
  const d = device();
  const bytes = new Uint8Array(1024 * 1024 + 4096).map((_, i) => i % 13);
  const blob = d.store.storeBlobBytesForInstance({
    instance: "conn_a",
    method: "collector",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  const ref = {
    blob_id: blob.blobId,
    sha256: blob.sha256,
    size_bytes: blob.sizeBytes,
    mime_type: blob.mimeType,
  };
  d.store.ingestBatch(
    [
      {
        instance: "conn_a",
        stream: "messages",
        key: "b",
        emitted_at: at,
        data: { id: "b", blob_ref: ref },
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  const wholeReads: string[] = [];
  const receiver = createReplicaReceiver({
    db: d.db,
    store: {
      ...d.store,
      getBlobBytes: (id: string) => {
        wholeReads.push(id);
        return d.store.getBlobBytes(id);
      },
    },
    owner: "owner",
    enabled: true,
    authenticate: (c) => (c === "replica-secret" ? "owner" : undefined),
    declarations: () => declarations,
  });
  receiver.stage({
    credential: "replica-secret",
    id: "pending",
    envelope: batch([
      registration(),
      {
        ...upsert(50),
        data: { id: "a", blob_ref: ref },
        blobs: [
          {
            blobId: blob.blobId,
            sha256: `sha256:${blob.sha256}`,
            mimeType: blob.mimeType,
            sizeBytes: blob.sizeBytes,
          },
        ],
      } as ReplicaOperation,
    ]),
  });
  expect(
    receiver
      .readStore({ reader: "owner" })
      .getRecord("conn_a", "messages", "a"),
  ).toMatchObject({ visibility: "pending" });
  expect(wholeReads).toEqual([]);
});

it.each(["point", "page", "streams", "changes"] as const)(
  "selects conflict policy and %s values from one SQLite snapshot",
  (surface) => {
    const d = device();
    installBindingConflictFixture(d);
    put(d, "before-conflict");
    const receiver = pendingReceiver(d, false);
    const other = new Database(d.path);
    other.pragma("busy_timeout=0");
    const otherStore = createReplicaRecordStore(other);
    const prepare = d.db.prepare.bind(d.db);
    let interleaved = false;
    d.db.prepare = ((sql: string) => {
      const statement = prepare(sql);
      if (
        sql.includes(
          "SELECT 1 FROM pdpp_replica_binding_conflicts WHERE instance=?",
        )
      ) {
        const get = statement.get.bind(statement);
        statement.get = ((...args: unknown[]) => {
          const result = get(...args);
          if (!interleaved) {
            interleaved = true;
            try {
              other.transaction(() => {
                other
                  .prepare(
                    "INSERT INTO pdpp_replica_binding_conflicts VALUES ('conn_a', 'source_binding_conflict', '{}')",
                  )
                  .run();
                const clock = other
                  .prepare(
                    "UPDATE pdpp_write_clock SET value=value+1 WHERE id=1 RETURNING value",
                  )
                  .get() as { value: number };
                other
                  .prepare(
                    "UPDATE pdpp_instance_binding SET reset_clock=? WHERE instance='conn_a'",
                  )
                  .run(clock.value);
                otherStore.ingestBatch(
                  ["a", "new-after-conflict"].map((key) => ({
                    instance: "conn_a",
                    stream: "messages",
                    key,
                    emitted_at: at,
                    data: { id: key, text: "after-conflict" },
                  })),
                  () => "mutable_state",
                  () => ["id"],
                  { method: "collector", generation: 1 },
                );
              })();
            } catch (error) {
              // An immediate read transaction may serialize the competing writer.
              if ((error as { code?: string }).code !== "SQLITE_BUSY")
                throw error;
            }
          }
          return result;
        }) as typeof statement.get;
      }
      return statement;
    }) as typeof d.db.prepare;
    try {
      const read = receiver.readStore({ reader: "grant" });
      if (surface === "point")
        expect(read.getRecord("conn_a", "messages", "a")?.data.text).toBe(
          "before-conflict",
        );
      if (surface === "page")
        expect(
          read
            .listRecords("messages", {
              instanceIds: ["conn_a"],
              limit: 10,
              order: "asc",
            })
            .data.map((row) => row.data.text),
        ).toEqual(["before-conflict"]);
      if (surface === "streams")
        expect(read.listStreams(["conn_a"])).toMatchObject([
          { recordCount: 1 },
        ]);
      if (surface === "changes")
        expect(
          read
            .changesSince("messages", { instanceIds: ["conn_a"], limit: 10 })
            .data.map((row) => !row.deleted && row.data.text),
        ).toEqual(["before-conflict"]);
      expect(interleaved).toBe(true);
    } finally {
      d.db.prepare = prepare;
      other.close();
    }
  },
);

it.each([
  ["key", "receiver"],
  ["key", "fact"],
  ["connection", "receiver"],
  ["connection", "fact"],
] as const)(
  "a %s quarantine (%s) hides pending-only, overwritten and pending-removed keys on every read and restores them",
  (scope, path) => {
    const d = device();
    const time = (second: number) => `2026-10-20T00:00:0${second}.000Z`;
    d.store.ingestBatch(
      (
        [
          ["d", 0],
          ["c", 1],
          ["b", 2],
          ["a", 3],
        ] as const
      ).map(([key, second]) => ({
        instance: "conn_a",
        stream: "messages",
        key,
        data: { id: key, text: key },
        emitted_at: time(second),
      })),
      () => "mutable_state",
      () => ["id"],
      { method: "collector", generation: 1 },
    );
    const bytes = new Uint8Array([1, 2, 3]);
    const blobId = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    const blob = {
      blobId,
      sha256: blobId,
      mimeType: "application/octet-stream",
      sizeBytes: bytes.length,
    };
    const record = (
      counter: number,
      key: string,
      second: number,
    ): Extract<ReplicaOperation, { kind: "upsert" }> => ({
      ...(upsert(counter) as Extract<ReplicaOperation, { kind: "upsert" }>),
      recordKey: key,
      emittedAt: time(second),
      data: { id: key, text: `pending-${key}` },
    });
    const { data: _data, blobs: _blobs, ...removed } = record(51, "b", 4);
    // a: canonical row with a pending overwrite; b: pending removal of a
    // canonical row; p: pending-only key whose blob only the pending batch holds.
    const operations: ReplicaOperation[] = [
      registration(),
      {
        kind: "blob-claim",
        owner: "owner",
        sourceId,
        connectionId: "conn_a",
        methodId: "collector",
        generation: 1,
        revision: { counter: 49, writerId: "remote", operationId: "claim-p" },
        blob,
      } as ReplicaOperation,
      { ...removed, kind: "delete", deletedAt: time(4) } as ReplicaOperation,
      record(52, "a", 5),
      {
        ...record(53, "p", 6),
        blobs: [blob],
        data: {
          id: "p",
          text: "pending-p",
          blob_ref: {
            blob_id: blobId,
            sha256: blobId.slice(7),
            size_bytes: bytes.length,
            mime_type: blob.mimeType,
          },
        },
      },
    ];
    const receiver = pendingReceiver(d);
    receiver.stage({
      credential: "replica-secret",
      id: "pending",
      envelope: batch(operations),
      blobs: [{ blobId, bytes }],
    });
    const page = (reader: "owner" | "grant", limit: number, cursor?: string) =>
      receiver.readStore({ reader }).listRecords("messages", {
        instanceIds: ["conn_a"],
        limit,
        order: "asc",
        cursor,
      });
    const shown = (row: PdppVisibleRecordLike | undefined) =>
      row
        ? `${row.recordKey}:${row.deleted ? "removed" : row.data.text}`
        : null;
    const snapshot = (reader: "owner" | "grant") => {
      const read = receiver.readStore({ reader });
      const blobBytes = read.getBlobBytes(blobId);
      return {
        point: ["a", "b", "c", "p"].map((key) =>
          shown(read.getRecord("conn_a", "messages", key)),
        ),
        page: page(reader, 10).data.map(shown),
        // Continuation must agree with the single page.
        pages: (() => {
          const rows: (string | null)[] = [];
          let cursor: string | undefined;
          do {
            const next = page(reader, 1, cursor);
            rows.push(...next.data.map(shown));
            cursor = next.nextCursor;
          } while (cursor);
          return rows;
        })(),
        streams: read
          .listStreams(["conn_a"])
          .map(({ recordCount, lastUpdated }) => ({
            recordCount,
            lastUpdated,
          })),
        blob: {
          bytes: blobBytes && Array.from(blobBytes),
          meta: read.getBlobMeta(blobId)?.blobId,
          refs: read.findBlobReferences(blobId).map((ref) => ref.recordKey),
        },
      };
    };
    const noBlob = { bytes: undefined, meta: undefined, refs: [] };
    const before = {
      owner: {
        point: ["a:pending-a", "b:removed", "c:c", "p:pending-p"],
        page: ["d:d", "c:c", "b:removed", "a:pending-a", "p:pending-p"],
        pages: ["d:d", "c:c", "b:removed", "a:pending-a", "p:pending-p"],
        streams: [{ recordCount: 4, lastUpdated: time(6) }],
        blob: { bytes: [1, 2, 3], meta: blobId, refs: ["p"] },
      },
      grant: {
        point: ["a:a", "b:b", "c:c", null],
        page: ["d:d", "c:c", "b:b", "a:a"],
        pages: ["d:d", "c:c", "b:b", "a:a"],
        streams: [{ recordCount: 4, lastUpdated: time(3) }],
        blob: noBlob,
      },
    };
    const only = (rows: string[]) => ({
      point: [null, null, rows.length ? "c:c" : null, null],
      page: rows,
      pages: rows,
      streams: rows.length ? [{ recordCount: 2, lastUpdated: time(1) }] : [],
      blob: noBlob,
    });
    const quarantined = scope === "key" ? only(["d:d", "c:c"]) : only([]);
    expect(snapshot("owner")).toEqual(before.owner);
    expect(snapshot("grant")).toEqual(before.grant);
    const open = {
      owner: page("owner", 1).nextCursor!,
      grant: page("grant", 1).nextCursor!,
    };

    const facts = () => {
      if (scope === "key")
        for (const key of ["a", "b", "p"])
          d.db
            .prepare(
              "INSERT INTO pdpp_replica_quarantined_keys VALUES ('conn_a', 1, 'messages', ?)",
            )
            .run(key);
      else
        d.db
          .prepare(
            "INSERT INTO pdpp_replica_quarantined_connections VALUES ('conn_a')",
          )
          .run();
    };
    if (path === "fact")
      // Only the fact and its epoch move: no canonical withdrawal marks a key.
      d.db.transaction(() => {
        facts();
        d.store.fenceReplicaConnection("conn_a");
      })();
    else
      receiver.quarantineImported({
        credential: "replica-secret",
        envelope: batch(
          scope === "key"
            ? operations.filter(
                (op) => op.kind === "upsert" || op.kind === "delete",
              )
            : [registration()],
        ),
      });
    expect(snapshot("owner")).toEqual(quarantined);
    expect(snapshot("grant")).toEqual(quarantined);
    for (const reader of ["owner", "grant"] as const)
      expect(() => page(reader, 1, open[reader])).toThrow(/expired/);
    if (path === "receiver") return;

    // Restoration: no write path removes a fact today; a restoring writer
    // must move the epoch as the hiding writer does.
    const during = {
      owner: page("owner", 1).nextCursor,
      grant: page("grant", 1).nextCursor,
    };
    d.db.transaction(() => {
      d.db.exec(
        "DELETE FROM pdpp_replica_quarantined_keys; DELETE FROM pdpp_replica_quarantined_connections;",
      );
      d.store.fenceReplicaConnection("conn_a");
    })();
    expect(snapshot("owner")).toEqual(before.owner);
    expect(snapshot("grant")).toEqual(before.grant);
    for (const reader of ["owner", "grant"] as const)
      if (scope === "key")
        expect(() => page(reader, 1, during[reader]!)).toThrow(/expired/);
  },
);
type PdppVisibleRecordLike = {
  recordKey: string;
  deleted: boolean;
  data: Record<string, unknown>;
};

/**
 * The agreed generation-aware predicate (synthesis lane): a key fact for
 * generation g hides rows of generation g only. Rows that carry their own
 * generation pass it as `generationSql`; canonical rows use the binding's
 * current generation.
 */
function generationAwareUnquarantined(alias: string, generationSql?: string) {
  const generation =
    generationSql ??
    `(SELECT b.generation FROM pdpp_instance_binding b WHERE b.instance=${alias}.instance)`;
  return `NOT EXISTS (SELECT 1 FROM pdpp_replica_quarantined_connections qc WHERE qc.instance=${alias}.instance) AND NOT EXISTS (SELECT 1 FROM pdpp_replica_quarantined_keys q WHERE q.instance=${alias}.instance AND q.stream=${alias}.stream AND q.record_key=${alias}.record_key AND q.generation = ${generation})`;
}
/**
 * The binding is at generation 1 and a pending batch resets the connection to
 * generation 2 with a value for key "a". A key fact for generation 2 (Codex's
 * repro) must hide that value; a fact for generation 1 must not, because the
 * value stays visible once the reset is promoted.
 */
function pendingResetUnderQuarantine(
  predicate: "store" | "contract" | "defaulted",
  factGeneration: 1 | 2,
) {
  const d = device();
  put(d, "local");
  const reset: ReplicaOperation = {
    kind: "connection-reset",
    owner: "owner",
    sourceId,
    connectionId: "conn_a",
    methodId: "collector",
    generation: 2,
    previousGeneration: 1,
    revision: { counter: 30, writerId: "remote", operationId: "reset-pending" },
  };
  const next = { ...upsert(31), generation: 2 } as ReplicaOperation;
  const receiver = createReplicaReceiver({
    db: d.db,
    store:
      predicate === "store"
        ? d.store
        : {
            ...d.store,
            unquarantinedRecordSql:
              predicate === "contract"
                ? generationAwareUnquarantined
                : // A conforming store may default the optional argument.
                  (
                    alias: string,
                    generationSql: string | undefined = undefined,
                  ) => generationAwareUnquarantined(alias, generationSql),
          },
    owner: "owner",
    enabled: true,
    authenticate: (c) => (c === "replica-secret" ? "owner" : undefined),
    declarations: () => declarations,
  });
  const quarantine = () =>
    receiver.quarantineImported({
      credential: "replica-secret",
      envelope: batch([factGeneration === 2 ? next : upsert(20)]),
    });
  if (factGeneration === 1) quarantine();
  receiver.stage({
    credential: "replica-secret",
    id: "pending",
    envelope: batch([registration(), reset, next]),
  });
  if (factGeneration === 2) quarantine();
  expect(d.store.getInstanceBinding("conn_a").generation).toBe(1);
  const owner = receiver.readStore({ reader: "owner" });
  const shown = {
    point: owner.getRecord("conn_a", "messages", "a")?.data.text,
    page: owner
      .listRecords("messages", {
        instanceIds: ["conn_a"],
        limit: 10,
        order: "asc",
      })
      .data.map((row) => row.data.text),
    streams: owner.listStreams(["conn_a"]).map((row) => row.recordCount),
  };
  expect(shown).toEqual(
    factGeneration === 2
      ? { point: undefined, page: [], streams: [] }
      : { point: "remote-31", page: ["remote-31"], streams: [1] },
  );
}

// The store's unquarantinedRecordSql takes the row's generation (3e18fac5).
it.each([1, 2] as const)(
  "applies a generation-%i key fact to a pending reset's value by the value's generation (store predicate)",
  (generation) => pendingResetUnderQuarantine("store", generation),
);
it.each([1, 2] as const)(
  "applies a generation-%i key fact to a pending reset's value by the value's generation (agreed predicate contract)",
  (generation) => pendingResetUnderQuarantine("contract", generation),
);
it.each([1, 2] as const)(
  "applies a generation-%i key fact to a pending reset's value by the value's generation (contract with a default parameter)",
  (generation) => pendingResetUnderQuarantine("defaulted", generation),
);

/** A generation-2 key fact while the binding, canonical and local rows are at 1. */
function futureFactOverCurrentRows(predicate: "store" | "contract") {
  const d = device();
  put(d, "local");
  const receiver = createReplicaReceiver({
    db: d.db,
    store:
      predicate === "store"
        ? d.store
        : { ...d.store, unquarantinedRecordSql: generationAwareUnquarantined },
    owner: "owner",
    enabled: true,
    authenticate: (c) => (c === "replica-secret" ? "owner" : undefined),
    declarations: () => declarations,
  });
  d.db.transaction(() => {
    d.db
      .prepare(
        "INSERT INTO pdpp_replica_quarantined_keys VALUES ('conn_a', 2, 'messages', 'a')",
      )
      .run();
    d.store.fenceReplicaConnection("conn_a");
  })();
  const shown = (reader: "owner" | "grant") => {
    const read = receiver.readStore({ reader });
    return {
      point: read.getRecord("conn_a", "messages", "a")?.data.text,
      page: read
        .listRecords("messages", {
          instanceIds: ["conn_a"],
          limit: 10,
          order: "asc",
        })
        .data.map((row) => row.data.text),
      streams: read.listStreams(["conn_a"]).map((row) => row.recordCount),
    };
  };
  const local = { point: "local", page: ["local"], streams: [1] };
  // Canonical generation-1 row, for both readers.
  expect(shown("owner")).toEqual(local);
  expect(shown("grant")).toEqual(local);
  // A binding conflict switches the owner to the local journal projection.
  d.store.markReplicaBindingConflict({
    connectionId: "conn_a",
    reason: "source_binding_conflict",
    evidence: {},
  });
  expect(shown("owner")).toEqual(local);
  expect(
    receiver
      .readStore({ reader: "owner" })
      .getRecord("conn_a", "messages", "a"),
  ).toMatchObject({ visibility: "conflicted" });
}

it.each(["store", "contract"] as const)(
  "a generation-2 key fact hides no generation-1 canonical or local row (%s predicate)",
  (predicate) => futureFactOverCurrentRows(predicate),
);

it.each(["owner", "grant"] as const)(
  "A6 race: blob reader checks the grant-scoped reference before loading bytes for %s",
  async (reader) => {
    const d = device();
    installBindingConflictFixture(d);
    const bytes = new Uint8Array([10, 20, 30]);
    const blob = d.store.storeBlobBytesForInstance({
      instance: "conn_a",
      method: "collector",
      generation: 1,
      bytes,
      mimeType: "application/octet-stream",
    });
    d.store.ingestBatch(
      [
        {
          instance: "conn_a",
          stream: "messages",
          key: "a",
          emitted_at: at,
          data: { id: "a", blob_ref: { blob_id: blob.blobId } },
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "collector", generation: 1 },
    );
    const receiver = pendingReceiver(d);
    const operation = all(d).find((op) => op.kind === "upsert")!;
    const grant: Grant = {
      version: "0.2.0",
      grant_id: "review-grant",
      issued_at: at,
      subject: { id: "owner" },
      client: { client_id: "client" },
      source: { kind: "provider_native", id: sourceId },
      source_declaration: { version: "1" },
      purpose_code: "review",
      access_mode: "continuous",
      streams: [
        { name: "messages", instance_ids: ["conn_a"], fields: ["blob_ref"] },
      ],
    };
    const app = pdppBlobsRoutes({
      store: d.store,
      reads: (mode) => {
        const readStore = receiver.readStore({ reader: mode });
        let snapshots = 0;
        return {
          ...readStore,
          withReadSnapshot<T>(read: () => T) {
            snapshots++;
            if (snapshots === 2)
              receiver.quarantineImported({
                credential: "replica-secret",
                envelope: batch([operation]),
              });
            return readStore.withReadSnapshot(read);
          },
        };
      },
      auth: createFixtureAuthorizationService({
        [reader]:
          reader === "owner"
            ? {
                active: true,
                tokenKind: "owner",
                subjectId: "owner",
                instanceIds: ["conn_a"],
              }
            : {
                active: true,
                tokenKind: "client",
                subjectId: "owner",
                clientId: "client",
                grant,
              },
      }),
      declarations: createStreamDeclarationRegistry([
        {
          name: "messages",
          semantics: "mutable_state",
          primaryKey: ["id"],
          cursorField: "emitted_at",
          requiredFields: ["id"],
          declaredFields: ["id", "blob_ref"],
        },
      ]),
      instancesForSubject: () => ["conn_a"],
      readBlobBytes: async (id) => {
        receiver.quarantineImported({
          credential: "replica-secret",
          envelope: batch([operation]),
        });
        return d.store.getBlobBytes(id);
      },
    });

    const response = await app.request(`/${blob.blobId}`, {
      headers: { Authorization: `Bearer ${reader}` },
    });
    expect(response.status).not.toBe(200);
    expect(await response.text()).not.toContain("10,20,30");
  },
);

it.each(["owner", "grant"] as const)(
  "A6 race: HTTP blob stream aborts after quarantine for %s",
  async (reader) => {
    const d = device();
    installBindingConflictFixture(d);
    const bytes = new Uint8Array(8 * 1024 * 1024).fill(0x6d);
    const blob = d.store.storeBlobBytesForInstance({
      instance: "conn_a",
      method: "collector",
      generation: 1,
      bytes,
      mimeType: "application/octet-stream",
    });
    d.store.ingestBatch(
      [
        {
          instance: "conn_a",
          stream: "messages",
          key: "a",
          emitted_at: at,
          data: { id: "a", blob_ref: { blob_id: blob.blobId } },
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "collector", generation: 1 },
    );
    const receiver = pendingReceiver(d);
    const operation = all(d).find((op) => op.kind === "upsert")!;
    const grant: Grant = {
      version: "0.2.0",
      grant_id: "review-grant",
      issued_at: at,
      subject: { id: "owner" },
      client: { client_id: "client" },
      source: { kind: "provider_native", id: sourceId },
      source_declaration: { version: "1" },
      purpose_code: "review",
      access_mode: "continuous",
      streams: [
        { name: "messages", instance_ids: ["conn_a"], fields: ["blob_ref"] },
      ],
    };
    const app = pdppBlobsRoutes({
      store: d.store,
      reads: (mode) => receiver.readStore({ reader: mode }),
      auth: createFixtureAuthorizationService({
        [reader]:
          reader === "owner"
            ? {
                active: true,
                tokenKind: "owner",
                subjectId: "owner",
                instanceIds: ["conn_a"],
              }
            : {
                active: true,
                tokenKind: "client",
                subjectId: "owner",
                clientId: "client",
                grant,
              },
      }),
      declarations: createStreamDeclarationRegistry([
        {
          name: "messages",
          semantics: "mutable_state",
          primaryKey: ["id"],
          cursorField: "emitted_at",
          requiredFields: ["id"],
          declaredFields: ["id", "blob_ref"],
        },
      ]),
      instancesForSubject: () => ["conn_a"],
      readBlobBytes: async (id) => d.store.getBlobBytes(id),
    });
    const { serve } = await import("@hono/node-server");
    const server = serve({
      fetch: app.fetch,
      hostname: "127.0.0.1",
      port: 0,
    });
    await new Promise<void>((resolve) => server.once("listening", resolve));
    try {
      const address = server.address() as { port: number };
      const response = await fetch(
        `http://127.0.0.1:${address.port}/${blob.blobId}`,
        { headers: { Authorization: `Bearer ${reader}` } },
      );
      expect(response.status).toBe(200);
      const body = response.body!.getReader();
      const first = await body.read();
      expect(first.done).toBe(false);
      receiver.quarantineImported({
        credential: "replica-secret",
        envelope: batch([operation]),
      });
      let receivedAfterQuarantine = 0;
      let streamFailed = false;
      try {
        for (;;) {
          const next = await body.read();
          if (next.done) break;
          receivedAfterQuarantine += next.value.byteLength;
        }
      } catch {
        streamFailed = true;
      }
      expect(streamFailed).toBe(true);
      expect(receivedAfterQuarantine).toBeLessThan(bytes.byteLength / 2);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  },
);

it("A6 epoch: a fresh visibility store starts at zero", () => {
  const d = device();
  expect(
    d.db
      .prepare(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pdpp_replica_visibility_epoch'",
      )
      .get(),
  ).toBeUndefined();

  pendingReceiver(d);
  expect(
    d.db
      .prepare("SELECT epoch FROM pdpp_replica_visibility_epoch WHERE id=1")
      .pluck()
      .get(),
  ).toBe(0);
});

it("A6 crash: no-op reopen preserves the durable projection epoch", () => {
  const d = device();
  stagePending(d);
  const before = d.db
    .prepare("SELECT epoch FROM pdpp_replica_visibility_epoch WHERE id=1")
    .pluck()
    .get();
  d.reopen();
  pendingReceiver(d);
  const after = d.db
    .prepare("SELECT epoch FROM pdpp_replica_visibility_epoch WHERE id=1")
    .pluck()
    .get();
  expect(after).toBe(before);
});

it("A6 migration crash: signature sync can restart after schema migration", () => {
  const d = device();
  d.close();
  // Created by the actual ff971abe receiver before the signature column existed.
  const fixture = new URL(
    "./fixtures/replica-visibility-epoch-ff971abe.sqlite.gz",
    import.meta.url,
  );
  writeFileSync(d.path, gunzipSync(readFileSync(fixture)));
  d.reopen();
  const columns = d.db
    .prepare("PRAGMA table_info(pdpp_replica_visibility_epoch)")
    .all() as { name: string }[];
  expect(columns.some(({ name }) => name === "signature")).toBe(false);
  expect(value(d)?.data.text).toBe("before");
  // Exercise initialization: its transaction commits before the later sync.
  d.db.prepare("UPDATE pdpp_replica_view_schema SET version=version-1").run();
  expect(
    d.db.prepare("SELECT version FROM pdpp_replica_view_schema").pluck().get(),
  ).toBe(9);

  const beforeEpoch = d.db
    .prepare("SELECT epoch FROM pdpp_replica_visibility_epoch WHERE id=1")
    .pluck()
    .get() as number;
  const beforeView =
    "bc1cd8ceba303305c6e17ae9726c6a3cc605b42d33902dc673ab4160ff29bcc2";
  put(d, "offline changed");
  expect(value(d)?.data.text).toBe("offline changed");
  d.db.exec(`
    CREATE TRIGGER fail_legacy_epoch_signature_update
    BEFORE UPDATE OF signature ON pdpp_replica_visibility_epoch
    BEGIN SELECT RAISE(ABORT, 'simulated process stop before signature sync'); END;
  `);
  expect(() =>
    createReplicaVisibilityView({
      db: d.db,
      owner: "owner",
      declarations: () => declarations,
      blobsValid: () => true,
      unquarantinedRecordSql: d.store.unquarantinedRecordSql,
      integrityEpoch: d.store.replicaIntegrityEpoch,
    }),
  ).toThrow("simulated process stop before signature sync");

  d.close();
  d.reopen();
  d.db.exec("DROP TRIGGER fail_legacy_epoch_signature_update");
  const reopened = pendingReceiver(d);
  const afterEpoch = d.db
    .prepare("SELECT epoch FROM pdpp_replica_visibility_epoch WHERE id=1")
    .pluck()
    .get() as number;
  expect(afterEpoch).toBe(beforeEpoch + 1);
  expect(reopened.readView("grant").visibilityEpoch).not.toBe(beforeView);
  expect(
    reopened.readStore({ reader: "grant" }).getRecord("conn_a", "messages", "a")
      ?.data.text,
  ).toBe("offline changed");
});
