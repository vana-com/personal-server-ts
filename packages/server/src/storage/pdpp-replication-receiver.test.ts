import Database from "better-sqlite3";
import { afterEach, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createStreamDeclarationRegistry } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import type { Grant } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { pdppRecordsRoutes } from "../routes/pdpp-records.js";
import { pdppBlobsRoutes } from "../routes/pdpp-blobs.js";
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
const config = { owner: "owner", declarations: [{ sourceId, binding }] };
const declarations: MergeContext["declarations"] = [
  { sourceId, binding, validateData: (data) => typeof data.id === "string" },
];
const directories: string[] = [];
const devices: ReturnType<typeof device>[] = [];
function device(registered = true, entries = declarations) {
  const directory = mkdtempSync(join(tmpdir(), "pdpp-receiver-"));
  directories.push(directory);
  const path = join(directory, "db.sqlite");
  let db = new Database(path);
  let store = createSqliteRecordStore(db);
  if (registered)
    store.registerConnection({
      instance: "conn_a",
      sourceId,
      method: "collector",
      label: "A",
    });
  store.replication.beginBaseline({
    ...config,
    declarations: entries.map(({ sourceId, binding }) => ({
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
      store = createSqliteRecordStore(db);
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
  const journalA = a.db.prepare("SELECT * FROM pdpp_mutation_journal").all();
  const journalB = b.db.prepare("SELECT * FROM pdpp_mutation_journal").all();
  send(a, [...fromB].reverse());
  send(b, [...fromA].reverse());
  expect(value(a)?.data).toEqual(value(b)?.data);
  expect(a.db.prepare("SELECT * FROM pdpp_mutation_journal").all()).toEqual(
    journalA,
  );
  expect(b.db.prepare("SELECT * FROM pdpp_mutation_journal").all()).toEqual(
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
    const storeUrl = new URL("./pdpp-records-sqlite-store.ts", import.meta.url)
      .href;
    const receiverUrl = new URL(
      "./pdpp-replication-receiver.ts",
      import.meta.url,
    ).href;
    const code = `import Database from 'better-sqlite3'; import {createSqliteRecordStore} from '${storeUrl}'; import {createReplicaReceiver} from '${receiverUrl}'; const db=new Database(${JSON.stringify(d.path)}); const store=createSqliteRecordStore(db); const receiver=createReplicaReceiver({db,store,owner:'owner',authenticate:()=> 'owner',declarations:()=>[{sourceId:${JSON.stringify(sourceId)},binding:${JSON.stringify(binding)},validateData:()=>true}]}); db.function('crash',()=>process.kill(process.pid,'SIGKILL')); ${afterCommit ? "" : 'db.exec("CREATE TEMP TRIGGER crash BEFORE INSERT ON pdpp_records BEGIN SELECT crash(); END");'} receiver.import({credential:'replica-secret',envelope:${JSON.stringify(batch([upsert()]))}}); process.kill(process.pid,'SIGKILL');`;
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
  const before = d.db.prepare("SELECT * FROM pdpp_mutation_journal").all();
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
    expect(d.db.prepare("SELECT * FROM pdpp_mutation_journal").all()).toEqual(
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

it("makes competing known declaration completions unavailable instead of overwriting one by iteration order", () => {
  const operations = completedReplica();
  const d = device();
  send(d, operations);
  const competing = { ...binding, digest: `sha256:${"c".repeat(64)}` };
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
    const before = d.db.prepare("SELECT * FROM pdpp_mutation_journal").all();
    try {
      put(d, "local");
    } catch {
      /* Quarantine may explicitly refuse the write. */
    }
    expect(value(d)).toBeUndefined();
    expect(d.db.prepare("SELECT * FROM pdpp_mutation_journal").all()).toEqual(
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
