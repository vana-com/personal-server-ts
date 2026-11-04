import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import {
  canonicalJson,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import { initializeDatabase } from "./index-schema.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { trackLegacyScopeMutations } from "./legacy-scope-revalidation-state.js";
import {
  binaryWriter,
  copyBinary,
  copyBinaryToCanonical,
  deleteBinary,
  clearMalformedManifest,
  writeCanonicalBinary,
  materializeCanonicalBinaries,
  createBinaryCompactor,
  CANONICAL_INLINE_BYTES,
} from "./pdpp-binary-chunks.js";
import {
  establishReplicaWriterIdentity,
  rotateReplicaWriterIdentity,
  rotateReplicaWriterIdentityAtBoot,
} from "./pdpp-replica-writer-identity.js";
import { nodeReplicaSql } from "./pdpp-replica-sql.js";
import { createReplicaStagingStore } from "./pdpp-replica-staging.js";
import {
  admit,
  ReplicaByteBudget,
} from "@opendatalabs/personal-server-ts-core/replication/limits";
import { replicaChainCommitment } from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import { captureWrites, retireReplication } from "./pdpp-replication-door.js";

const I = "writer",
  PEER = "shared-blob-peer",
  S = "writer.audit";
const SOURCE = "https://example.test/writer",
  METHOD = "collector";
const at = "2026-10-01T00:00:00.000Z",
  credential = "synthetic",
  owner = "owner";
const binding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const closers: (() => void)[] = [];
afterEach(() => {
  while (closers.length) closers.pop()!();
});
function fixture(
  replica = true,
  method = METHOD,
  sourceId = SOURCE,
  takeover = true,
) {
  const raw = initializeDatabase(":memory:");
  const state = trackLegacyScopeMutations(raw, { ceilingMs: 1_800_000 });
  const db = state.db;
  const store = replica
    ? createReplicaRecordStore(db)
    : createSqliteRecordStore(db);
  closers.push(() => store.close());
  for (const instance of [I, PEER]) {
    store.registerConnection({
      instance,
      sourceId: instance === PEER && method !== METHOD ? SOURCE : sourceId,
      method: instance === PEER && method !== METHOD ? METHOD : method,
      label: "Synthetic",
    });
    if (takeover)
      raw
        .prepare(
          `INSERT INTO legacy_scope_takeovers(scope,instance,generation,method,superseded_path,
      superseded_version,superseded_cas_revision,superseded_collected_at) VALUES (?, ?, 1, ?, 'audit.json',1,1,?)`,
        )
        .run(S, instance, method, at);
  }
  raw
    .prepare(
      "INSERT INTO data_files(path,scope,collected_at,size_bytes) VALUES ('audit.json',?,?,1)",
    )
    .run(S, at);
  const authority = createLegacyScopeAuthority(db, state);
  let declarations = [
    {
      sourceId,
      binding,
      validateData: (data: Record<string, unknown>) =>
        typeof data.id === "string",
    },
  ];
  const replicated = replica
    ? (store as ReturnType<typeof createReplicaRecordStore>)
    : undefined;
  const receiver = replicated
    ? createReplicaReceiver({
        db,
        store: replicated,
        owner,
        authenticate: (c) => (c === credential ? owner : undefined),
        declarations: () => declarations,
        enabled: true,
      })
    : undefined;
  function activate() {
    replicated!.replication.beginBaseline({ owner, declarations });
  }
  const bytes = new TextEncoder().encode("synthetic writer bytes");
  const digest = createHash("sha256").update(bytes).digest("hex");
  const meta = {
    blobId: `sha256:${digest}`,
    sha256: digest,
    sizeBytes: bytes.length,
    mimeType: "text/plain",
  };
  function put(key = "a") {
    return store.ingestBatch(
      [
        {
          instance: I,
          stream: "messages",
          key,
          data: { id: key, content: key },
          emitted_at: at,
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method, generation: 1 },
    );
  }
  function operation(
    counter = 2,
    data: Record<string, unknown> = { id: "a", content: "remote" },
  ): ReplicaOperation {
    return {
      kind: "upsert",
      owner,
      sourceId,
      connectionId: I,
      methodId: method,
      generation: 1,
      revision: { counter, writerId: "remote", operationId: `op-${counter}` },
      declaration: binding,
      recordKey: "a",
      emittedAt: at,
      data,
      blobs: [],
    };
  }
  const envelope = (ops: ReplicaOperation[], id = "batch") => ({
    format: "vana-pdpp-replica" as const,
    version: 1 as const,
    owner,
    batchId: id,
    operations: ops,
  });
  function stage(id = "batch") {
    receiver!.stage({ credential, id, envelope: envelope([operation()], id) });
  }
  function blob(instance = I) {
    return store.storeBlobBytesForInstance({
      instance,
      method,
      generation: 1,
      bytes,
      mimeType: meta.mimeType,
    });
  }
  const copyEnvelope = envelope([operation()], "copy-batch");
  const hex = (n: number) =>
    `0x${n.toString(16).padStart(64, "0")}` as `0x${string}`;
  const fragment = { dataHash: hex(1), metadataHash: hex(2) };
  const copy = {
    id: canonicalJson(["remote", "copy-batch"]),
    writer: "remote",
    batch: "copy-batch",
    sequence: 1,
    previous: null,
    envelopeDigest: `sha256:${createHash("sha256").update(canonicalJson(copyEnvelope)).digest("hex")}`,
    envelope: copyEnvelope,
    fragments: [fragment],
  };
  const descriptor = {
    blobId: meta.blobId,
    sha256: meta.blobId,
    mimeType: meta.mimeType,
    sizeBytes: bytes.length,
  };
  const claim = (connectionId = I): ReplicaOperation => ({
    kind: "blob-claim",
    owner,
    sourceId,
    connectionId,
    methodId: method,
    generation: 1,
    revision: {
      counter: 1,
      writerId: "remote",
      operationId: `claim-${connectionId}`,
    },
    blob: descriptor,
  });
  const blobOperation = (): ReplicaOperation =>
    ({
      ...operation(),
      blobs: [descriptor],
      data: {
        id: "a",
        blob_ref: {
          blob_id: meta.blobId,
          mime_type: meta.mimeType,
          size_bytes: bytes.length,
        },
      },
    }) as ReplicaOperation;
  let copyKey: `0x${string}` | undefined;
  function stageCopy() {
    copyKey = receiver!.copies.stage({ credential, copy }).copyKey;
  }
  function stageBlobCopy() {
    const envelopeWithBlob = envelope([claim(), blobOperation()], "copy-batch");
    copyKey = receiver!.copies.stage({
      credential,
      copy: {
        ...copy,
        envelope: envelopeWithBlob,
        envelopeDigest: `sha256:${createHash("sha256").update(canonicalJson(envelopeWithBlob)).digest("hex")}`,
      },
      blobs: [{ blobId: meta.blobId, bytes }],
    }).copyKey;
  }
  function fact() {
    return {
      chainId: 1,
      registry: hex(123),
      owner,
      version: "1",
      currentVersion: "1",
      status: "Active",
      commitment: replicaChainCommitment(
        fragment.dataHash,
        fragment.metadataHash,
      ) as `0x${string}`,
      blockNumber: 1n,
      blockHash: hex(456),
      eligible: true,
    };
  }
  function proveCopy() {
    receiver!.copies.recordFact({
      credential,
      id: copy.id,
      scope: `${copy.id}#0`,
      fragmentIndex: 0,
      fact: fact(),
    });
  }
  let clock = 1000;
  const staging = createReplicaStagingStore({
    db,
    owner,
    repositoryId: "writer-audit",
    now: () => clock,
  });
  const admission = admit(
    { totalBytes: bytes.length, fragments: [{ bytes: bytes.length }] },
    new ReplicaByteBudget(1024),
    { repositoryId: "writer-audit", owner, manifestDigest: "sha256:synthetic" },
  );
  if ("kind" in admission) throw Error("synthetic admission");
  let stagedWriter: ReturnType<typeof staging.begin> | undefined;
  let handle: ReturnType<typeof staging.begin>["handle"] | undefined;
  const expectedBlob = {
    blobId: meta.blobId,
    sha256: meta.blobId,
    sizeBytes: bytes.length,
  };
  function beginStage() {
    stagedWriter = staging.begin(admission);
  }
  function appendStage() {
    beginStage();
    stagedWriter!.write(bytes);
  }
  function finishStage() {
    stagedWriter = staging.begin(admission);
    stagedWriter.write(bytes);
    handle = stagedWriter.complete();
  }
  function verifiedStage() {
    finishStage();
    staging.verify(handle!, expectedBlob);
  }
  function transition(kind: "claude" | "strava") {
    const scope = kind === "claude" ? "claude.projects" : "strava.activities";
    const input = {
      instance: I,
      expectedGeneration: 1,
      expectedWriteClock: store.transitionWriteClock(),
      snapshots: {
        [scope]: { version: "1.0" as const, scope, collectedAt: at, data: {} },
      },
    };
    if (kind === "claude") store.transitionClaudeToLive(input);
    else store.transitionStravaToBrowser(input);
  }
  function prepareTransition(kind: "claude" | "strava") {
    blob();
    transition(kind);
    raw
      .prepare(
        "UPDATE legacy_scope_takeovers SET generation=2 WHERE instance=?",
      )
      .run(I);
  }
  function key(instance: string) {
    const row = state.status(instance, S);
    // The fallback permits this same regression to run on the old parent.
    // On the fixed commit this is the production body's actual witness token.
    return JSON.stringify(
      authority.witnessState?.(S, instance) ?? {
        dependencyRevision: state.revision(instance),
        dirtySince: row?.dirty_since ?? null,
        deadline:
          row?.dirty_since == null ? null : row.dirty_since + row.ceiling_ms,
      },
    );
  }
  return {
    copy,
    stageCopy,
    stageBlobCopy,
    claim,
    blobOperation,
    copyKey: () => copyKey!,
    proveCopy,
    fact,
    staging,
    admission,
    beginStage,
    appendStage,
    finishStage,
    verifiedStage,
    stagedWriter: () => stagedWriter!,
    handle: () => handle!,
    expectedBlob,
    expire: () => {
      clock += staging.leaseMs + 1;
    },
    transition,
    prepareTransition,
    raw,
    state,
    db,
    store,
    replicated,
    receiver,
    activate,
    bytes,
    meta,
    put,
    operation,
    envelope,
    stage,
    blob,
    key,
    method,
    sourceId,
    declare: (next: typeof declarations) => {
      declarations = next;
    },
  };
}
type Fixture = ReturnType<typeof fixture>;
type Writer = {
  name: string;
  replica?: boolean;
  takeover?: boolean;
  ownBoundary?: boolean;
  method?: string;
  source?: string;
  prepare?(h: Fixture): void;
  write(h: Fixture): void;
};
const writers: Writer[] = [
  {
    name: "record store: first-takeover blob writer",
    replica: false,
    takeover: false,
    write: (h) => {
      h.blob();
    },
  },

  {
    name: "record store: blob metadata upsert",
    replica: false,
    write: (h) => {
      h.store.putBlobMeta(h.meta);
    },
  },
  {
    name: "record store: raw blob bytes",
    replica: false,
    write: (h) => {
      h.store.storeBlobBytes(h.bytes, h.meta.mimeType);
    },
  },
  {
    name: "record store: scoped blob and claim",
    replica: false,
    write: (h) => {
      h.blob();
    },
  },
  {
    name: "record store: claim existing shared bytes",
    prepare: (h) => {
      h.blob();
    },
    write: (h) => {
      h.blob(PEER);
    },
  },
  {
    name: "record store: fill a metadata-only blob",
    replica: false,
    prepare: (h) => {
      h.store.putBlobMeta(h.meta);
    },
    write: (h) => {
      h.store.storeBlobBytes(h.bytes, h.meta.mimeType);
    },
  },
  {
    name: "record store: reset removes blob claims",
    replica: false,
    prepare: (h) => {
      h.blob();
    },
    write: (h) => {
      h.store.resetInstanceBinding({
        instance: I,
        expectedMethod: METHOD,
        expectedGeneration: 1,
        nextMethod: METHOD,
      });
    },
  },
  {
    name: "record store: delete removes blobs and claims",
    replica: false,
    prepare: (h) => {
      h.blob();
    },
    write: (h) => {
      h.store.deleteConnection(I);
    },
  },
  {
    name: "record store: startup unclaimed blob collection",
    replica: false,
    prepare: (h) => {
      h.store.storeBlobBytes(h.bytes, h.meta.mimeType);
    },
    write: (h) => {
      createSqliteRecordStore(h.db);
    },
  },
  {
    name: "record store: startup stale-claim sweep",
    replica: false,
    prepare: (h) => {
      h.blob();
      h.raw.prepare("UPDATE pdpp_blob_claims SET generation=99").run();
    },
    write: (h) => {
      createSqliteRecordStore(h.db);
    },
  },
  {
    name: "binary writer: append chunk",
    write: (h) => {
      const writer = binaryWriter(h.db, "staging", "new");
      writer.write(h.bytes);
    },
  },
  {
    name: "binary writer: publish manifest",
    write: (h) => {
      binaryWriter(h.db, "staging", "new").finish();
    },
  },
  {
    name: "binary deletion",
    prepare: (h) => {
      const w = binaryWriter(h.db, "received", "old");
      w.write(h.bytes);
      w.finish();
    },
    write: (h) => {
      deleteBinary(h.db, "received", "old");
    },
  },
  {
    name: "binary malformed-manifest repair",
    prepare: (h) => {
      h.db
        .prepare(
          "INSERT INTO pdpp_binary_manifests VALUES ('received','bad',-1)",
        )
        .run();
    },
    write: (h) => {
      clearMalformedManifest(h.db, "received", "bad");
    },
  },
  {
    name: "binary copy",
    prepare: (h) => {
      const w = binaryWriter(h.db, "staging", "old");
      w.write(h.bytes);
      w.finish();
    },
    write: (h) => {
      copyBinary(h.db, "staging", "old", "received", "new");
    },
  },
  {
    name: "canonical inline byte write",
    prepare: (h) => {
      h.store.putBlobMeta(h.meta);
    },
    write: (h) => {
      writeCanonicalBinary(h.db, h.meta.blobId, h.bytes);
    },
  },
  {
    name: "canonical chunked byte write",
    prepare: (h) => {
      h.store.putBlobMeta(h.meta);
    },
    write: (h) => {
      writeCanonicalBinary(
        h.db,
        h.meta.blobId,
        new Uint8Array(CANONICAL_INLINE_BYTES + 1),
      );
    },
  },
  {
    name: "canonical byte promotion",
    prepare: (h) => {
      h.store.putBlobMeta(h.meta);
      const w = binaryWriter(h.db, "staging", "old");
      w.write(h.bytes);
      w.finish();
    },
    write: (h) => {
      copyBinaryToCanonical(h.db, "staging", "old", h.meta.blobId);
    },
  },
  {
    name: "canonical byte materialization",
    prepare: (h) => {
      h.store.putBlobMeta(h.meta);
      const w = binaryWriter(h.db, "canonical", h.meta.blobId);
      w.write(h.bytes);
      w.finish();
    },
    write: (h) => {
      materializeCanonicalBinaries(h.db);
    },
  },
  {
    name: "binary compaction",
    prepare: (h) => {
      h.blob();
      const w = binaryWriter(h.db, "pinned", h.meta.blobId);
      w.write(h.bytes);
      w.finish();
    },
    write: (h) => {
      h.db.transaction(() => createBinaryCompactor(h.db).step(1024 * 1024))();
    },
  },
  {
    name: "replica: baseline and declaration history",
    write: (h) => {
      h.activate();
    },
  },
  {
    name: "replica: record capture and journal",
    prepare: (h) => {
      h.activate();
    },
    write: (h) => {
      h.put();
    },
  },
  {
    name: "replica: blob capture and pin",
    prepare: (h) => {
      h.activate();
    },
    write: (h) => {
      h.blob();
    },
  },
  {
    name: "replica: pending batch/preview",
    write: (h) => {
      h.stage();
    },
  },
  {
    name: "replica: pending byte custody",
    write: (h) => {
      h.receiver!.stage({
        credential,
        id: "bytes",
        envelope: h.envelope([h.operation()], "bytes"),
        blobs: [{ blobId: h.meta.blobId, bytes: h.bytes }],
      });
    },
  },
  {
    name: "replica: staged chunk custody",
    prepare: (h) => {
      const w = binaryWriter(h.db, "staging", "old");
      w.write(h.bytes);
      w.finish();
    },
    write: (h) => {
      h.receiver!.stage({
        credential,
        id: "chunks",
        envelope: h.envelope([h.operation()], "chunks"),
        stagedBlobs: [
          { blobId: h.meta.blobId, key: "old", sizeBytes: h.bytes.length },
        ],
      });
    },
  },
  {
    name: "replica: pending batch quarantine",
    prepare: (h) => {
      h.stage();
    },
    write: (h) => {
      h.receiver!.quarantine({ credential, id: "batch", reason: "synthetic" });
    },
  },
  {
    name: "replica: pending equivocation quarantine",
    prepare: (h) => {
      h.stage();
    },
    write: (h) => {
      h.receiver!.stage({
        credential,
        id: "batch",
        envelope: h.envelope([h.operation(3)]),
      });
    },
  },
  {
    name: "replica: batch promotion and canonical merge",
    prepare: (h) => {
      h.stage();
    },
    write: (h) => {
      h.receiver!.promote({ credential, id: "batch" });
    },
  },
  {
    name: "replica: direct import and reconciliation",
    write: (h) => {
      h.receiver!.import({ credential, envelope: h.envelope([h.operation()]) });
    },
  },
  {
    name: "replica: record quarantine and integrity fence",
    prepare: (h) => {
      h.receiver!.import({ credential, envelope: h.envelope([h.operation()]) });
    },
    write: (h) => {
      h.receiver!.quarantineImported({
        credential,
        envelope: h.envelope([h.operation()]),
      });
    },
  },
  {
    name: "replica: connection quarantine",
    write: (h) => {
      h.receiver!.quarantineImported({
        credential,
        envelope: h.envelope([
          {
            kind: "connection-register",
            owner,
            sourceId: SOURCE,
            connectionId: I,
            methodId: METHOD,
            generation: 1,
            revision: {
              counter: 1,
              writerId: "remote",
              operationId: "registration",
            },
          },
        ]),
      });
    },
  },
  {
    name: "replica: declaration reconciliation",
    prepare: (h) => {
      h.receiver!.import({ credential, envelope: h.envelope([h.operation()]) });
      h.declare([]);
    },
    write: (h) => {
      h.receiver!.reconcileDeclarations({ credential });
    },
  },
  {
    name: "replica: re-enable retry",
    prepare: (h) => {
      h.declare([]);
      h.receiver!.import({ credential, envelope: h.envelope([h.operation()]) });
      h.declare([{ sourceId: SOURCE, binding, validateData: () => true }]);
    },
    write: (h) => {
      h.receiver!.retry({ credential });
    },
  },
  {
    name: "replica: bounded declaration reconciliation",
    prepare: (h) => {
      h.receiver!.import({ credential, envelope: h.envelope([h.operation()]) });
      h.declare([]);
    },
    write: (h) => {
      h.receiver!.reconcileStep({
        credential,
        restart: true,
        page: { operations: 1000, bytes: 1024 * 1024 },
      });
    },
  },
  {
    name: "replica: retirement materializes and closes the door",
    prepare: (h) => {
      h.activate();
    },
    write: (h) => {
      retireReplication(h.db);
    },
  },
  {
    name: "effect SQL writer: run",
    write: (h) => {
      nodeReplicaSql(h.db).run(
        "INSERT INTO pdpp_replica_pending_bytes VALUES (?,?,?)",
        ["run", "b", h.bytes],
      );
    },
  },
  {
    name: "effect SQL writer: get returning",
    write: (h) => {
      nodeReplicaSql(h.db).get(
        "INSERT INTO pdpp_replica_pending_bytes VALUES (?,?,?) RETURNING blob_id",
        ["get", "b", h.bytes],
      );
    },
  },
  {
    name: "effect SQL writer: all returning",
    prepare: (h) => {
      nodeReplicaSql(h.db).run(
        "INSERT INTO pdpp_replica_pending_bytes VALUES (?,?,?)",
        ["all", "b", h.bytes],
      );
    },
    write: (h) => {
      nodeReplicaSql(h.db).all(
        "DELETE FROM pdpp_replica_pending_bytes RETURNING blob_id",
        [],
      );
    },
  },
  {
    name: "effect SQL writer: exec",
    write: (h) => {
      nodeReplicaSql(h.db).exec(
        "INSERT INTO pdpp_replica_pending_bytes VALUES ('exec','b',X'01')",
      );
    },
  },
  {
    name: "replica: copy retention and preview",
    write: (h) => {
      h.stageCopy();
    },
  },
  {
    name: "replica: copy validity rejection",
    write: (h) => {
      h.receiver!.copies.stage({
        credential,
        copy: {
          ...h.copy,
          fragments: [{ dataHash: "0xZZ", metadataHash: "0x00" }],
        },
      });
    },
  },
  {
    name: "replica: finalized fact append",
    prepare: (h) => {
      h.stageCopy();
    },
    write: (h) => {
      h.proveCopy();
    },
  },
  {
    name: "replica: copy quarantine disposition",
    prepare: (h) => {
      h.stageCopy();
    },
    write: (h) => {
      h.receiver!.copies.apply({
        credential,
        id: h.copy.id,
        decision: {
          kind: "terminal",
          reason: "finalized_conflict",
          quarantine: [h.copyKey()],
        },
      });
    },
  },
  {
    name: "replica: copy terminal retention",
    prepare: (h) => {
      h.stageCopy();
    },
    write: (h) => {
      h.receiver!.copies.terminate({
        credential,
        id: h.copy.id,
        reason: "synthetic",
      });
    },
  },
  {
    name: "replica: copy promotion and receipt",
    prepare: (h) => {
      h.stageCopy();
      h.proveCopy();
    },
    write: (h) => {
      h.receiver!.copies.promote({ credential, id: h.copy.id });
    },
  },
  {
    name: "staging: begin custody",
    write: (h) => {
      h.staging.begin(h.admission);
    },
  },
  {
    name: "staging: byte append",
    prepare: (h) => {
      h.beginStage();
    },
    write: (h) => {
      h.stagedWriter().write(h.bytes);
    },
  },
  {
    name: "staging: complete manifest",
    prepare: (h) => {
      h.appendStage();
    },
    write: (h) => {
      h.stagedWriter().complete();
    },
  },
  {
    name: "staging: verify custody",
    prepare: (h) => {
      h.finishStage();
    },
    write: (h) => {
      h.staging.verify(h.handle(), h.expectedBlob);
    },
  },
  {
    name: "staging: attach custody",
    prepare: (h) => {
      h.verifiedStage();
    },
    write: (h) => {
      h.staging.attach(h.handle(), h.expectedBlob);
    },
  },
  {
    name: "staging: abort custody",
    prepare: (h) => {
      h.finishStage();
    },
    write: (h) => {
      h.staging.abort(h.admission);
    },
  },
  {
    name: "staging: reclaim admission",
    prepare: (h) => {
      h.finishStage();
    },
    write: (h) => {
      h.staging.reclaimAdmission(h.admission);
    },
  },
  {
    name: "staging: expired custody cleanup",
    prepare: (h) => {
      h.finishStage();
      h.expire();
    },
    write: (h) => {
      h.staging.cleanup();
    },
  },
  {
    name: "staging: attached temporary byte cleanup",
    prepare: (h) => {
      h.verifiedStage();
      h.db.transaction(() => h.staging.attach(h.handle(), h.expectedBlob))();
    },
    write: (h) => {
      h.staging.cleanupAttachedTemporaryBytes();
    },
  },
  {
    name: "archive: Claude moves blob claims",
    replica: false,
    method: "anthropic",
    source: "https://registry.pdpp.dev/sources/claude",
    prepare: (h) => {
      h.blob();
    },
    write: (h) => {
      h.transition("claude");
    },
  },
  {
    name: "archive: Claude clears blob claims",
    replica: false,
    method: "anthropic",
    source: "https://registry.pdpp.dev/sources/claude",
    prepare: (h) => {
      h.prepareTransition("claude");
    },
    write: (h) => {
      h.store.clearClaudeTransitionScope("claude.projects");
    },
  },
  {
    name: "archive: Claude confirmation",
    replica: false,
    method: "anthropic",
    source: "https://registry.pdpp.dev/sources/claude",
    prepare: (h) => {
      h.prepareTransition("claude");
    },
    write: (h) => {
      h.store.confirmClaudeTransition(I, 2);
    },
  },
  {
    name: "archive: Strava moves blob claims",
    replica: false,
    method: "strava",
    source: "https://registry.pdpp.dev/sources/strava",
    prepare: (h) => {
      h.blob();
    },
    write: (h) => {
      h.transition("strava");
    },
  },
  {
    name: "archive: Strava clears blob claims",
    replica: false,
    method: "strava",
    source: "https://registry.pdpp.dev/sources/strava",
    prepare: (h) => {
      h.prepareTransition("strava");
    },
    write: (h) => {
      h.store.clearStravaTransitionScope("strava.activities");
    },
  },
  {
    name: "archive: Strava confirmation",
    replica: false,
    method: "strava",
    source: "https://registry.pdpp.dev/sources/strava",
    prepare: (h) => {
      h.prepareTransition("strava");
    },
    write: (h) => {
      h.store.confirmStravaTransition(I, 2);
    },
  },
  {
    name: "replica: binding conflict",
    write: (h) => {
      h.replicated!.markReplicaBindingConflict({
        connectionId: I,
        reason: "source_binding_conflict",
        evidence: { synthetic: true },
      });
    },
  },
  {
    name: "replica: integrity fence",
    write: (h) => {
      h.replicated!.fenceReplicaConnection(I);
    },
  },
  {
    name: "replica: baseline checkpoint",
    write: (h) => {
      h.replicated!.replication.acknowledgeBaselinePage(0, 1);
    },
  },
  {
    name: "replica: declaration rebaseline",
    write: (h) => {
      h.replicated!.replication.beginBaseline({
        owner,
        declarations: [
          {
            sourceId: SOURCE,
            binding: {
              ...binding,
              version: "2",
              digest: `sha256:${"c".repeat(64)}`,
            },
          },
        ],
      });
    },
  },
  {
    name: "replica: stream completion capture",
    write: (h) => {
      h.store.replaceStream({
        instance: I,
        stream: "messages",
        method: METHOD,
        generation: 1,
        primaryKey: ["id"],
        emittedAt: at,
        sourceCollectedAt: at,
        envelopes: [],
      });
    },
  },
  {
    name: "replica: record deletion and invalidation capture",
    prepare: (h) => {
      h.put();
    },
    write: (h) => {
      h.store.deleteRecord(I, "messages", "a", at, "mutable_state");
    },
  },
  {
    name: "record store: multiple replacement and receipt writes",
    replica: false,
    write: (h) => {
      h.store.replaceStreams(
        ["messages", "other"].map((stream) => ({
          instance: I,
          stream,
          method: METHOD,
          generation: 1,
          primaryKey: ["id"],
          emittedAt: at,
          sourceCollectedAt: at,
          envelopes: [],
        })),
      );
    },
  },
  {
    name: "replica: startup orphan cleanup",
    ownBoundary: true,
    prepare: (h) => {
      h.db
        .prepare(
          "INSERT INTO pdpp_binary_manifests VALUES ('canonical','orphan',0)",
        )
        .run();
    },
    write: (h) => {
      createReplicaRecordStore(h.db);
    },
  },
  {
    name: "writer identity: establishment",
    ownBoundary: true,
    write: (h) => {
      establishReplicaWriterIdentity(h.db, {
        owner: "0x" + "1".repeat(40),
        server: "0x" + "2".repeat(40),
        record: {
          owner: "0x" + "1".repeat(40),
          id: "0x" + "3".repeat(64),
          revokedAt: null,
        },
      });
    },
  },
  {
    name: "writer identity: rotation",
    ownBoundary: true,
    prepare: (h) => {
      establishReplicaWriterIdentity(h.db, {
        owner: "0x" + "1".repeat(40),
        server: "0x" + "2".repeat(40),
        record: {
          owner: "0x" + "1".repeat(40),
          id: "0x" + "3".repeat(64),
          revokedAt: null,
        },
      });
    },
    write: (h) => {
      rotateReplicaWriterIdentity(h.db);
    },
  },
  {
    name: "writer identity: boot rotation",
    ownBoundary: true,
    prepare: (h) => {
      establishReplicaWriterIdentity(h.db, {
        owner: "0x" + "1".repeat(40),
        server: "0x" + "2".repeat(40),
        record: {
          owner: "0x" + "1".repeat(40),
          id: "0x" + "3".repeat(64),
          revokedAt: null,
        },
      });
    },
    write: (h) => {
      rotateReplicaWriterIdentityAtBoot(h.db, {
        requested: true,
        replicationEnabled: true,
      });
    },
  },
  {
    name: "replica: imported blob metadata bytes and claims",
    write: (h) => {
      h.receiver!.import({
        credential,
        envelope: h.envelope([h.claim(), h.blobOperation()]),
        blobs: [{ blobId: h.meta.blobId, bytes: h.bytes }],
      });
    },
  },
  {
    name: "replica: imported shared-blob claim only",
    prepare: (h) => {
      h.blob();
    },
    write: (h) => {
      h.receiver!.import({ credential, envelope: h.envelope([h.claim(PEER)]) });
    },
  },
  {
    name: "replica: promotion releases whole pending bytes",
    prepare: (h) => {
      h.receiver!.stage({
        credential,
        id: "batch",
        envelope: h.envelope([h.operation()]),
        blobs: [{ blobId: h.meta.blobId, bytes: h.bytes }],
      });
    },
    write: (h) => {
      h.receiver!.promote({ credential, id: "batch" });
    },
  },
  {
    name: "replica: copy retains chunked blob custody",
    write: (h) => {
      h.stageBlobCopy();
    },
  },
  {
    name: "replica: terminal copy releases pending blob bytes",
    prepare: (h) => {
      h.stageBlobCopy();
    },
    write: (h) => {
      h.receiver!.copies.terminate({
        credential,
        id: h.copy.id,
        reason: "synthetic",
      });
    },
  },
  {
    name: "replica: completion invalidation capture",
    prepare: (h) => {
      h.store.replaceStream({
        instance: I,
        stream: "messages",
        method: METHOD,
        generation: 1,
        primaryKey: ["id"],
        emittedAt: at,
        sourceCollectedAt: at,
        envelopes: [
          {
            instance: I,
            stream: "messages",
            key: "a",
            data: { id: "a", content: "old" },
            emitted_at: at,
          },
        ],
      });
    },
    write: (h) => {
      h.store.deleteRecord(I, "messages", "a", at, "mutable_state");
    },
  },
];

describe("every canonical blob/replica writer changes the body witness key", () => {
  it.each(writers)(
    "$name",
    ({
      name,
      replica,
      takeover,
      ownBoundary,
      method,
      source,
      prepare,
      write,
    }) => {
      const h = fixture(replica, method, source, takeover);
      if (
        name.startsWith("replica:") &&
        !name.includes("baseline and declaration")
      )
        h.activate();
      prepare?.(h);
      if (takeover !== false)
        for (const instance of [I, PEER])
          h.state.complete(instance, S, h.state.revision(instance));
      const before = [h.key(I), h.key(PEER)];
      const revisions = [h.state.revision(I), h.state.revision(PEER)];
      if (h.replicated && !ownBoundary)
        h.db.transaction(() => captureWrites(h.db, () => write(h)))();
      else write(h);
      expect(h.state.revision(I)).toBeGreaterThan(revisions[0]!);
      expect(h.state.revision(PEER)).toBeGreaterThan(revisions[1]!);
      expect(h.key(I)).not.toBe(before[0]);
      expect(h.key(PEER)).not.toBe(before[1]);
    },
  );
});
