import type { Database } from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { keccak256, type Hex } from "viem";
import { createHash } from "node:crypto";
import {
  binaryWriter,
  readBinaryChunks,
  deleteBinary,
  verifyBinary,
} from "./pdpp-binary-chunks.js";
import {
  encodeReplicaPayload,
  fragmentReplicaStream,
  assembleReplicaStream,
  inspectReplicaPayload,
} from "@opendatalabs/personal-server-ts-core/replication/stream";
import {
  canonicalJson,
  decodeReplicaEnvelope,
  type EnvelopeExpectation,
  type ReplicaEnvelope,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  decodeReplicaFragment,
  decodeReplicaManifest,
  fragmentMatchesManifest,
  prepareReplicaManifest,
  replicaDigest,
  replicaMetadataHash,
  replicaScope,
  replicaWriterOf,
  REPLICA_MAX_BLOB_BYTES,
  type ManifestEntry,
  type PreparedManifest,
  type ReplicaFragment,
  type ReplicaManifest,
  type Predecessor,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import {
  replicaRegistrationState,
  replicaAwaitingFinality,
  replicaRegistrationInactive,
  replicaChainCommitment,
  type ReplicaSlot,
  type ReplicaTransportPort,
  type ReplicaRegistrationEvidence,
} from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import {
  abortable,
  createReplicaCoordinator,
  type ReplicaAttempt,
  type ReplicaSettle,
  type ProgressReport,
  type ReplicaBudget,
  type ReplicaPhaseHandler,
  type ReplicaWorkItem,
} from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import {
  dependencyKey,
  outcomeReason,
  retryFromError,
  ReplicaFramingUnsupported,
  ReplicaProblemError,
  type ReplicaDependency,
  type ReplicaOutcome,
  type ReplicaPhase,
  type ReplicaPhaseOutcome,
  type ReplicaQuarantineProof,
} from "@opendatalabs/personal-server-ts-core/replication/outcome";
import { replicaCopyKey } from "@opendatalabs/personal-server-ts-core/replication/copy-promotion";
import { REPLICA_REFETCH_BUDGET } from "./pdpp-replica-copies.js";
import { captureWrites, replicationAdmitted } from "./pdpp-replication-door.js";
import {
  defaultReplicaBackoff,
  REPLICA_TERMINAL,
  replicaEligibleAt,
  replicaEligibleAtSql,
  type ReplicaEligibility,
  type ReplicaWorkState,
} from "@opendatalabs/personal-server-ts-core/replication/schedule";
import {
  createCachedReplicaRoster,
  type ReplicaRosterPort,
} from "@opendatalabs/personal-server-ts-core/replication/roster";
import {
  type ReplicaAuthorityRefusal,
  type ReplicaBatchSigner,
  type ReplicaEnvironment,
} from "@opendatalabs/personal-server-ts-core/replication/writer-identity";
import { REPLICA_WAIT_FALLBACK_MS } from "@opendatalabs/personal-server-ts-core/replication/schedule";
import type { ReplicationExport } from "./pdpp-replication-sqlite.js";
import {
  currentReplicaWriterIdentity,
  enableReplicaWriterIdentity,
  type ReplicaWriterIdentity,
} from "./pdpp-replica-writer-identity.js";
import type { createReplicaReceiver } from "./pdpp-replication-receiver.js";

// One process owns a transport writer per database; other local instances serialize cycles.
const activeDatabases = new Set<Database | string>();
const ownedTokens = new Set<string>();

/** Default bound on the operations one batch (one registration) covers. */
export const REPLICA_BATCH_OPERATIONS = 10_000;
/**
 * Default bound on the estimated payload bytes of one batch. One operation
 * always fits, so a single larger blob makes a larger batch.
 */
export const REPLICA_BATCH_BYTES = 32 * 1024 * 1024;
/** The export's page limit. A batch reads several pages. */
const EXPORT_PAGE = 1000;
/** New slots one discover pass admits per writer scope. */
const DISCOVER_SLOTS = 256;

/** Durable outcome columns shared by every per-item work table. */
const WORK = `outcome TEXT, reason TEXT, cause_json TEXT, dependency TEXT, error TEXT,
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0,
 wait_since INTEGER, checked_block TEXT`;
/*
 * Sender: a retained batch is prepared into content-addressed fragments and
 * one manifest. Fragments are stored unregistered; the manifest is the one
 * registration, at the next version of the writer's single scope.
 * Receiver: each discovered version of a writer scope is a slot. A slot's
 * manifest is fetched only under finalized evidence, and each fragment is
 * checked against the manifest's digest before it is decrypted.
 */
const migration = `
CREATE TABLE IF NOT EXISTS pdpp_transport_lock (id INTEGER PRIMARY KEY CHECK(id=1), pid INTEGER NOT NULL, token TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pdpp_transport_state (
 id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT NOT NULL, writer TEXT NOT NULL,
 baseline_cursor INTEGER NOT NULL DEFAULT 0, baseline_done INTEGER NOT NULL DEFAULT 0,
 tail_cursor INTEGER, sequence INTEGER NOT NULL DEFAULT 0, previous_json TEXT, scan_cursor TEXT);
CREATE TABLE IF NOT EXISTS pdpp_transport_batches (
 batch TEXT PRIMARY KEY, sequence INTEGER UNIQUE NOT NULL, previous_json TEXT,
 collected_at TEXT NOT NULL, digest TEXT NOT NULL, total_bytes INTEGER NOT NULL,
 prepared INTEGER NOT NULL DEFAULT 0, admission_json TEXT, ${WORK});
CREATE TABLE IF NOT EXISTS pdpp_transport_staged_fragments (
 token TEXT NOT NULL, position INTEGER NOT NULL, digest TEXT NOT NULL, encrypted BLOB NOT NULL,
 PRIMARY KEY(token,position));
CREATE TABLE IF NOT EXISTS pdpp_transport_fragments_out (
 batch TEXT NOT NULL, position INTEGER NOT NULL, digest TEXT NOT NULL, encrypted BLOB NOT NULL,
 state TEXT NOT NULL DEFAULT 'ready', ${WORK}, PRIMARY KEY(batch,position));
CREATE TABLE IF NOT EXISTS pdpp_transport_manifests_out (
 batch TEXT PRIMARY KEY, scope TEXT NOT NULL, version INTEGER NOT NULL,
 plaintext BLOB NOT NULL, encrypted BLOB NOT NULL, data_hash TEXT NOT NULL, metadata_hash TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'ready', ${WORK}, UNIQUE(scope,version));
CREATE TABLE IF NOT EXISTS pdpp_transport_manifests_in (
 slot TEXT PRIMARY KEY, scope TEXT NOT NULL, version INTEGER NOT NULL, writer TEXT NOT NULL,
 manifest_json TEXT, data_hash TEXT, metadata_hash TEXT, batch TEXT, sequence INTEGER,
 state TEXT NOT NULL DEFAULT 'ready', evidence_checked INTEGER NOT NULL DEFAULT 0, ${WORK},
 UNIQUE(scope,version));
CREATE TABLE IF NOT EXISTS pdpp_transport_fragments_in (
 slot TEXT NOT NULL, position INTEGER NOT NULL, digest TEXT NOT NULL, bytes INTEGER NOT NULL,
 fragment_json TEXT, state TEXT NOT NULL DEFAULT 'ready', ${WORK}, PRIMARY KEY(slot,position));
CREATE INDEX IF NOT EXISTS pdpp_manifests_in_batch ON pdpp_transport_manifests_in(writer,batch);
CREATE INDEX IF NOT EXISTS pdpp_manifests_in_checked ON pdpp_transport_manifests_in(evidence_checked) WHERE state='imported';
CREATE TABLE IF NOT EXISTS pdpp_transport_imported (
 writer TEXT NOT NULL, batch TEXT NOT NULL, sequence INTEGER NOT NULL, digest TEXT NOT NULL,
 PRIMARY KEY(writer,batch), UNIQUE(writer,sequence));
CREATE TABLE IF NOT EXISTS pdpp_transport_import_work (
 writer TEXT NOT NULL, batch TEXT NOT NULL, sequence INTEGER NOT NULL,
 ${WORK}, refetch_attempts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(writer,batch));
CREATE INDEX IF NOT EXISTS pdpp_import_work_dependency ON pdpp_transport_import_work(dependency) WHERE outcome='wait';
CREATE TABLE IF NOT EXISTS pdpp_transport_phase_state (
 phase TEXT PRIMARY KEY, ${WORK}, fingerprint TEXT);
`;
type State = {
  owner: string;
  writer: string;
  baseline_cursor: number;
  baseline_done: number;
  tail_cursor: number | null;
  sequence: number;
  previous_json: string | null;
  scan_cursor: string | null;
};
type Work = {
  attempts: number;
  next_attempt: number;
  wait_since: number | null;
  checked_block: string | null;
};
type Batch = Work & {
  batch: string;
  sequence: number;
  previous_json: string | null;
  collected_at: string;
  digest: string;
  total_bytes: number;
};
/** One outbound unit: a fragment PUT, or a manifest PUT and registration. */
type Outbound = Work & {
  kind: "fragment" | "manifest";
  id: string;
  batch: string;
  position: number;
};
type ManifestOut = {
  batch: string;
  scope: string;
  version: number;
  plaintext: Buffer;
  encrypted: Buffer;
  data_hash: Hex;
  metadata_hash: Hex;
};
type Slot = Work & {
  slot: string;
  scope: string;
  version: number;
  writer: string;
  data_hash: Hex | null;
  metadata_hash: Hex | null;
};
type FragmentIn = Work & {
  slot: string;
  position: number;
  digest: string;
  bytes: number;
  writer: string;
};
type Item<R> = ReplicaWorkItem & { row: R };

const workState = (row: Work): ReplicaWorkState => ({
  attempts: row.attempts,
  nextEligible: row.next_attempt,
  waitSince: row.wait_since ?? null,
  checkedBlock: row.checked_block ?? null,
});
/** Values for WORK_SET, in order. `error` keeps a closed code, never exception text. */
function workValues(outcome: ReplicaOutcome, state: ReplicaWorkState) {
  const reason = outcome.tag === "progress" ? null : outcomeReason(outcome);
  return [
    outcome.tag,
    reason,
    outcome.tag === "retry" && outcome.cause
      ? canonicalJson(outcome.cause)
      : null,
    outcome.tag === "wait" ? dependencyKey(outcome.dependency) : null,
    outcome.tag === "progress" || outcome.tag === "wait" ? null : reason,
    state.attempts,
    state.nextEligible,
    state.waitSince,
    state.checkedBlock,
  ];
}
const WORK_SET =
  "outcome=?,reason=?,cause_json=?,dependency=?,error=?,attempts=?,next_attempt=?,wait_since=?,checked_block=?";
/** A durable quarantine with its closed reason, for a slot or fragment row. */
const QUARANTINE_SET = (reason: ReplicaQuarantineProof["reason"]) =>
  `state='quarantined',outcome='quarantine',reason='${reason}',error='${reason}'`;
/** Column reset that makes a receiver row fresh work again. */
const RESET_WORK =
  "outcome=NULL,reason=NULL,cause_json=NULL,dependency=NULL,error=NULL,attempts=0,wait_since=NULL,checked_block=NULL";
/** A slot's storage and evidence identity: the DPv2 `<scope>/<version>` key. */
const slotKey = (scope: string, version: number) => `${scope}/${version}`;
const encoder = new TextEncoder();
const blobsOf = (op: ReplicaOperation) =>
  op.kind === "blob-claim" ? [op.blob] : op.kind === "upsert" ? op.blobs : [];

/** The owner binding every phase runs under, validated before any phase. */
export class ReplicaAuthorityError extends Error {
  readonly code = "replica_authority_mismatch";
  constructor() {
    super("replica transport owner binding mismatch");
    this.name = "ReplicaAuthorityError";
  }
}

/**
 * The database holds state of the earlier carrier (one registration per
 * fragment). This worker cannot read it, and mixing the two layouts would
 * corrupt both. Testers start such a database fresh.
 */
export class ReplicaCarrierMismatchError extends Error {
  readonly code = "replica_carrier_mismatch";
  constructor() {
    super("replica transport state is from the per-fragment carrier");
    this.name = "ReplicaCarrierMismatchError";
  }
}
/** Tables only the per-fragment carrier created. */
const PER_FRAGMENT_TABLES = [
  "pdpp_transport_outbox",
  "pdpp_transport_inbox",
  "pdpp_transport_preparing",
];

/** Internal experiment only. No bootstrap wiring; false by default. */
export function createReplicaTransportWorker(deps: {
  db: Database;
  enabled?: boolean;
  expected: () => EnvelopeExpectation;
  exporter: ReplicationExport;
  receiver: ReturnType<typeof createReplicaReceiver>;
  credential: unknown;
  transport: ReplicaTransportPort;
  /** Who may write (host contract §3). */
  authority: {
    /**
     * The registered PS server key: Node `key.json`, or the Lite server
     * identity. Never the owner wallet or the Lite owner sync signer.
     */
    signer: ReplicaBatchSigner;
    /**
     * The gateway roster, uncached. The worker caches each answer for at most
     * REPLICA_ROSTER_MAX_AGE_MS on its own clock.
     */
    roster: ReplicaRosterPort;
    /** EIP-712 domain chain and environment of this owner's partition. */
    chainId: number;
    environment: ReplicaEnvironment;
  };
  now?: () => number;
  maxBlobBytes?: number;
  targetChunkBytes?: number;
  /**
   * Bounds on one batch, so on what one registration covers. A batch closes
   * at whichever bound it reaches first; it always takes one operation.
   */
  maxBatchOperations?: number;
  maxBatchBytes?: number;
  /** Units per phase per step. Defaults keep today's per-cycle limits. */
  quantum?: Partial<Record<ReplicaPhase, number>>;
  /** Items per writer per phase per step. */
  perWriter?: number;
  /** Per-run deadline; a late result is discarded. */
  deadlineMs?: number;
  /**
   * Delay after a successful revalidation of one imported slot. The default 0
   * rechecks every imported slot round-robin on every step, so a finalized
   * conflict retracts data on the next step.
   */
  revalidateIntervalMs?: number;
  /** Completed non-matching re-downloads of a batch before the owner decides. */
  refetchBudget?: number;
}) {
  const { db, transport } = deps;
  const now = deps.now ?? Date.now;
  const roster = createCachedReplicaRoster(deps.authority.roster, { now });
  const server = deps.authority.signer.address.toLowerCase();
  const cap = deps.maxBlobBytes ?? REPLICA_MAX_BLOB_BYTES;
  if (!Number.isSafeInteger(cap) || cap < 1 || cap > REPLICA_MAX_BLOB_BYTES)
    throw new RangeError("invalid storage cap");
  const maxOperations = deps.maxBatchOperations ?? REPLICA_BATCH_OPERATIONS;
  const maxBytes = deps.maxBatchBytes ?? REPLICA_BATCH_BYTES;
  if (
    !Number.isSafeInteger(maxOperations) ||
    maxOperations < 1 ||
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 1
  )
    throw new RangeError("invalid replica batch bounds");
  if (
    db
      .prepare(
        `SELECT 1 FROM sqlite_master WHERE type='table' AND name IN (${PER_FRAGMENT_TABLES.map(() => "?").join(",")})`,
      )
      .get(...PER_FRAGMENT_TABLES)
  )
    throw new ReplicaCarrierMismatchError();
  db.exec(migration);
  deps.receiver.setPendingEnabled(deps.enabled === true);
  const enabled = () => deps.enabled === true;
  const state = () =>
    db.prepare("SELECT * FROM pdpp_transport_state WHERE id=1").get() as State;

  /**
   * One validated authority context for every phase: the expected owner, the
   * persisted binding, the transport port's owner and the writer identity's
   * owner must agree. Checked before any phase runs, so a wrong-owner reopen
   * cannot encrypt, publish or import. False, with nothing written, when the
   * replication door closed since the step began.
   */
  function authority(identity: ReplicaWriterIdentity): boolean {
    const owner = deps.expected().owner;
    return db
      .transaction(() => {
        if (!replicationAdmitted(db)) return false;
        db.prepare(
          "INSERT OR IGNORE INTO pdpp_transport_state (id,owner,writer) VALUES (1,?,?)",
        ).run(owner, identity.transportWriter);
        const bound = state();
        if (
          bound.owner !== owner ||
          identity.seed.owner !== owner.toLowerCase() ||
          (transport.owner !== undefined &&
            transport.owner.toLowerCase() !== owner.toLowerCase())
        )
          throw new ReplicaAuthorityError();
        if (bound.writer !== identity.transportWriter) startWriter(identity);
        return true;
      })
      .immediate();
  }
  /**
   * A new writer identity (re-registration, reset or restore) starts its own
   * chain at sequence 1, and its first publication is a full current-state
   * baseline under the new writer, in the new writer's own scope from
   * version 1. The old writer's batches, fragments and manifests that are
   * not yet published are abandoned, so its scope gets no new version: their
   * operations name the old operation writer, which no receiver accepts from
   * the new one. The baseline carries their effect instead, so a peer that
   * missed any old batch still converges. The same transaction switches the
   * writer and pins the baseline; a crash resumes it from its durable
   * cursor. The rebaseline is a capture, so the door's fence does not count
   * it as a bypass.
   */
  function startWriter(identity: ReplicaWriterIdentity) {
    const baseline = captureWrites(db, () => deps.exporter.rebaseline());
    db.prepare(
      "UPDATE pdpp_transport_state SET writer=?,sequence=0,previous_json=NULL,baseline_cursor=?,baseline_done=0,tail_cursor=NULL WHERE id=1",
    ).run(identity.transportWriter, baseline?.after ?? 0);
    for (const table of [
      "pdpp_transport_batches",
      "pdpp_transport_staged_fragments",
      "pdpp_transport_fragments_out",
      "pdpp_transport_manifests_out",
    ])
      db.prepare(`DELETE FROM ${table}`).run();
  }
  /** An attempt with no durable effect besides its outcome. */
  const verdict = (outcome: ReplicaPhaseOutcome): ReplicaAttempt => ({
    outcome,
  });
  /** An attempt whose effect commits only together with its own outcome. */
  const withPlan = (
    outcome: ReplicaPhaseOutcome,
    effect: () => void,
  ): ReplicaAttempt => ({
    outcome,
    plan: () => {
      effect();
    },
  });
  const quarantine = (
    reason: ReplicaQuarantineProof["reason"],
    key: string,
  ): ReplicaPhaseOutcome => ({ tag: "quarantine", proof: { reason, key } });
  /**
   * Every adapter's commit: in one transaction run this attempt's plan,
   * settle the (possibly refined) verdict and write the item's state.
   */
  const commitIn =
    <I extends ReplicaWorkItem>(
      write: (outcome: ReplicaOutcome, work: ReplicaWorkState, item: I) => void,
    ) =>
    (item: I, attempt: ReplicaAttempt, settle: ReplicaSettle): ReplicaOutcome =>
      // The receiver's own boundary: its plans read and write derived state,
      // which a transaction opened on the raw connection would not refresh.
      deps.receiver.atomically(() => {
        const settled = settle(attempt.plan?.() ?? attempt.outcome);
        write(settled.outcome, settled.state, item);
        return settled.outcome;
      });
  /** Network calls stop at the attempt's deadline or the host's abort. */
  const call = <T>(signal: AbortSignal, start: () => Promise<T>) =>
    abortable(signal, start);
  /** The coordinator's eligibility policy over a work table's columns. */
  const due = (e: ReplicaEligibility) =>
    `${replicaEligibleAtSql(e)} <= ${e.now}`;
  /** Earliest eligibility among rows of `from` (a table plus WHERE clause). */
  const earliestIn = (e: ReplicaEligibility, from: string) => {
    const row = db
      .prepare(`SELECT min(${replicaEligibleAtSql(e)}) AS next FROM ${from}`)
      .get() as { next: number | null } | undefined;
    return row?.next ?? undefined;
  };
  /**
   * Writer-fair due selection (see ReplicaPhaseHandler.due). Parameters:
   * perWriter, the writer served last ('' for none), total.
   */
  const dueWindow = (
    from: string,
    writer: string,
    order: string,
    where: string,
  ) =>
    `SELECT * FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY ${writer} ORDER BY ${order}) AS writer_rank FROM ${from} WHERE ${where}) WHERE writer_rank<=? ORDER BY writer_rank, ${writer}<=?, ${writer}, ${order} LIMIT ?`;

  const finalityWait = (
    evidence: ReplicaRegistrationEvidence,
    key: string,
  ): ReplicaPhaseOutcome => ({
    tag: "wait",
    dependency: {
      kind: "finality",
      key,
      checkedBlock: String(evidence.chain!.blockNumber),
    },
  });
  /** The verdict for a slot whose registration is not confirmed yet. */
  const unconfirmed = (
    evidence: ReplicaRegistrationEvidence,
    slot: ReplicaSlot,
  ): ReplicaPhaseOutcome =>
    replicaAwaitingFinality(evidence, slot) ||
    replicaRegistrationInactive(evidence, slot)
      ? finalityWait(evidence, slotKey(slot.scope, slot.version))
      : { tag: "retry", problem: "registration_unconfirmed" };

  // --------------------------------------------------------------- retain
  const singleton = (phase: ReplicaPhase) =>
    (db
      .prepare("SELECT * FROM pdpp_transport_phase_state WHERE phase=?")
      .get(phase) as
      | (Work & { fingerprint: string | null; outcome: string | null })
      | undefined) ?? {
      outcome: null,
      attempts: 0,
      next_attempt: 0,
      wait_since: null,
      checked_block: null,
      fingerprint: null,
    };
  function settleSingleton(
    phase: ReplicaPhase,
    outcome: ReplicaOutcome,
    work: ReplicaWorkState,
    fingerprint?: string,
  ) {
    db.prepare(
      `INSERT INTO pdpp_transport_phase_state (phase) VALUES (?) ON CONFLICT(phase) DO NOTHING`,
    ).run(phase);
    db.prepare(
      `UPDATE pdpp_transport_phase_state SET ${WORK_SET}${fingerprint === undefined ? "" : ",fingerprint=?"} WHERE phase=?`,
    ).run(
      ...workValues(outcome, work),
      ...(fingerprint === undefined ? [] : [fingerprint]),
      phase,
    );
  }
  /** A singleton phase's durable deadline, by the shared eligibility policy. */
  function singletonEligibleAt(
    row: Work & { outcome?: string | null },
    e: ReplicaEligibility,
  ) {
    return replicaEligibleAt(
      {
        finalityWait: false,
        nextEligible: row.next_attempt,
        waitSince: row.wait_since,
        checkedBlock: row.checked_block,
      },
      e,
    );
  }
  /** Only an outstanding Retry or Wait of a singleton is a deadline. */
  function singletonDeadline(phase: ReplicaPhase, e: ReplicaEligibility) {
    const row = singleton(phase);
    return row.outcome === "retry" || row.outcome === "wait"
      ? singletonEligibleAt(row, e)
      : undefined;
  }
  /** The local export has operations not yet retained. One indexed probe. */
  function tailPending() {
    const s = state();
    return (
      !s.baseline_done ||
      deps.exporter.readTailPage({
        limit: 1,
        ...(s.tail_cursor === null ? {} : { afterSequence: s.tail_cursor }),
      }).operations.length > 0
    );
  }
  /**
   * A retained batch that is still on its way to a finalized registration and
   * is not failing. While one exists, new operations accumulate for the next
   * batch instead of each step cutting its own: a sync costs one
   * registration. A batch in Retry or Unsupported does not hold the window,
   * so one failing batch never blocks its successors.
   */
  function batchInFlight() {
    return !!db
      .prepare(
        `SELECT 1 FROM pdpp_transport_batches b WHERE
          (b.prepared=0 AND coalesce(b.outcome,'')<>'retry')
          OR (b.prepared=1 AND EXISTS (SELECT 1 FROM pdpp_transport_manifests_out m
            WHERE m.batch=b.batch AND m.state='ready' AND coalesce(m.outcome,'')<>'retry'
            AND NOT EXISTS (SELECT 1 FROM pdpp_transport_fragments_out f
              WHERE f.batch=b.batch AND f.outcome='retry')))
          LIMIT 1`,
      )
      .get();
  }
  /**
   * Wire bytes an operation adds to a payload: its JSON and each new blob.
   * `shares` is true when it references a blob the payload already carries.
   */
  function operationBytes(op: ReplicaOperation, seen: Set<string>) {
    const json = encoder.encode(canonicalJson(op)).length + 1;
    let blobs = 0;
    let shares = false;
    for (const blob of blobsOf(op))
      if (seen.has(blob.blobId)) shares = true;
      else {
        seen.add(blob.blobId);
        blobs += 4 * Math.ceil(blob.sizeBytes / 3) + blob.blobId.length + 16;
      }
    return { json, blobs, shares };
  }
  /**
   * Read export pages from the cursor until a batch bound is reached or the
   * export has no more. A page that overflows the byte bound is read again
   * with a smaller limit, so the cursor ends exactly after the last operation
   * taken. Baseline and tail operations never share a batch.
   * Every batch carries the blobs its operations reference. An operation that
   * only shares blobs already in the batch is bounded by JSON bytes alone:
   * cutting it into the next batch would send those blobs again.
   */
  function readBatch(s: State) {
    const read = (afterSequence: number | undefined, limit: number) =>
      s.baseline_done
        ? deps.exporter.readTailPage({
            limit,
            ...(afterSequence === undefined ? {} : { afterSequence }),
          })
        : deps.exporter.readBaselinePage({
            limit,
            afterSequence: afterSequence ?? s.baseline_cursor,
          });
    const operations: ReplicaOperation[] = [];
    const seen = new Set<string>();
    let bytes = 0;
    let jsonBytes = 0;
    let cursor = s.baseline_done
      ? (s.tail_cursor ?? undefined)
      : s.baseline_cursor;
    let hasMore = true;
    let next = cursor ?? 0;
    while (hasMore && operations.length < maxOperations) {
      let page = read(
        cursor,
        Math.min(EXPORT_PAGE, maxOperations - operations.length),
      );
      const trial = new Set(seen);
      let fit = 0;
      let added = 0;
      let addedJson = 0;
      for (const op of page.operations) {
        const size = operationBytes(op, trial);
        const fits =
          operations.length + fit === 0 ||
          bytes + added + size.json + size.blobs <= maxBytes ||
          (size.shares &&
            size.blobs === 0 &&
            jsonBytes + addedJson + size.json <= maxBytes);
        if (!fits) break;
        fit++;
        added += size.json + size.blobs;
        addedJson += size.json;
      }
      const full = fit < page.operations.length;
      if (full && fit === 0) break;
      if (full) page = read(cursor, fit);
      for (const op of page.operations) {
        operations.push(op);
        operationBytes(op, seen);
      }
      bytes += added;
      jsonBytes += addedJson;
      cursor = next = page.nextAfterSequence;
      hasMore = full || page.hasMore;
      if (full) break;
    }
    return { operations, next, hasMore };
  }
  const retain: ReplicaPhaseHandler<Item<Work>> = {
    phase: "retain",
    due(e) {
      const row = singleton("retain");
      const at = singletonEligibleAt(row, e);
      if (at === undefined || at > e.now) return [];
      // An idle tail costs one indexed probe and no budget unit.
      if (batchInFlight() || !tailPending()) return [];
      return [
        {
          id: "retain",
          phase: "retain",
          writer: "",
          state: workState(row),
          row,
        },
      ];
    },
    async run() {
      const s = state();
      const page = readBatch(s);
      const batch = randomUUID().replaceAll("-", "");
      let digest = "",
        totalBytes = 0;
      try {
        if (page.operations.length) {
          const envelope: ReplicaEnvelope = {
            format: "vana-pdpp-replica",
            version: 1,
            owner: s.owner,
            batchId: batch,
            operations: page.operations,
          };
          decodeReplicaEnvelope(canonicalJson(envelope), deps.expected());
          const writer = binaryWriter(db, "payload", batch);
          const hash = createHash("sha256");
          for await (const bytes of encodeReplicaPayload(
            envelope,
            async function* (id) {
              yield* deps.exporter.readPinnedBlobChunks(id);
            },
          )) {
            db.transaction(() => writer.write(bytes))();
            hash.update(bytes);
            totalBytes += bytes.length;
          }
          writer.finish();
          digest = `sha256:${hash.digest("hex")}`;
        }
      } catch (error) {
        deleteBinary(db, "payload", batch);
        throw new ReplicaProblemError("retain_failed", { cause: error });
      }
      // Queue + export cursor commit together with the phase outcome. They
      // acknowledge durable local responsibility, not publication.
      return withPlan(
        { tag: "progress", receipt: { phase: "retain", key: batch } },
        () => {
          const current = state();
          if (
            current.sequence !== s.sequence ||
            current.baseline_cursor !== s.baseline_cursor ||
            current.baseline_done !== s.baseline_done ||
            current.tail_cursor !== s.tail_cursor
          )
            throw new ReplicaProblemError("retain_failed");
          if (page.operations.length) {
            if (!verifyBinary(db, "payload", batch, digest, totalBytes))
              throw new ReplicaProblemError("retain_failed");
            db.prepare(
              "INSERT INTO pdpp_transport_batches (batch,sequence,previous_json,collected_at,digest,total_bytes) VALUES (?,?,?,?,?,?)",
            ).run(
              batch,
              s.sequence + 1,
              s.previous_json,
              new Date(now()).toISOString(),
              digest,
              totalBytes,
            );
            db.prepare(
              "UPDATE pdpp_transport_state SET sequence=?, previous_json=? WHERE id=1",
            ).run(s.sequence + 1, canonicalJson({ batch, digest }));
          }
          if (!s.baseline_done) {
            deps.exporter.acknowledgeBaselinePage(
              deps.exporter.getBaselineCheckpoint(),
              page.next,
            );
            db.prepare(
              "UPDATE pdpp_transport_state SET baseline_cursor=?, baseline_done=? WHERE id=1",
            ).run(page.next, page.hasMore ? 0 : 1);
          } else
            db.prepare(
              "UPDATE pdpp_transport_state SET tail_cursor=? WHERE id=1",
            ).run(page.next);
        },
      );
    },
    commit: commitIn((outcome, work) => {
      settleSingleton("retain", outcome, work);
    }),
    commitProblem: "retain_failed",
    earliest(e) {
      return (
        singletonDeadline("retain", e) ??
        (!batchInFlight() && tailPending() ? e.now : undefined)
      );
    },
  };

  // -------------------------------------------------------------- prepare
  const unsupported = (error: ReplicaFramingUnsupported) => {
    const admission = {
      actual: error.actual,
      limit: error.limit,
      capability:
        error.dimension === "fragment_count"
          ? `fragments:${error.limit}`
          : `cap:${cap}`,
    };
    return { reason: "replica_framing_unsupported" as const, ...admission };
  };
  const prepare: ReplicaPhaseHandler<Item<Batch>> = {
    phase: "prepare",
    due(e, limit) {
      return (
        db
          .prepare(
            `SELECT batch,sequence,previous_json,collected_at,digest,total_bytes,attempts,next_attempt,wait_since,checked_block FROM pdpp_transport_batches WHERE prepared=0 AND ${due(e)} ORDER BY next_attempt,sequence LIMIT ?`,
          )
          .all(limit.total) as Batch[]
      ).map((row) => ({
        id: row.batch,
        phase: "prepare",
        writer: "",
        state: workState(row),
        bytes: row.total_bytes,
        row,
      }));
    },
    async run(item, signal) {
      const batch = item.row;
      const token = randomUUID();
      const s = state();
      const identity = currentReplicaWriterIdentity(db);
      const statement = {
        owner: s.owner,
        writer: s.writer,
        batch: batch.batch,
        sequence: batch.sequence,
        previous: batch.previous_json
          ? (JSON.parse(batch.previous_json) as Predecessor)
          : null,
        collectedAt: batch.collected_at,
        digest: batch.digest,
        totalBytes: batch.total_bytes,
      };
      const encrypt = (scope: string, bytes: Uint8Array) =>
        call(signal, () => transport.encrypt(scope, bytes));
      let chunkBytes = deps.targetChunkBytes ?? 4 * 1024 * 1024;
      let entries: ManifestEntry[] = [];
      let manifest: Omit<PreparedManifest, "version">;
      const unsupportedPlan = (error: ReplicaFramingUnsupported) => {
        const admission = unsupported(error);
        return withPlan({ tag: "unsupported", admission }, () =>
          db
            .prepare(
              "UPDATE pdpp_transport_batches SET prepared=-1,admission_json=? WHERE batch=?",
            )
            .run(
              canonicalJson({
                actual: admission.actual,
                limit: admission.limit,
                capability: admission.capability,
              }),
              batch.batch,
            ),
        );
      };
      try {
        // Batches belong to the current writer; startWriter drops older ones.
        if (identity?.transportWriter !== s.writer)
          throw new ReplicaProblemError("prepare_failed");
        while (true) {
          try {
            entries = [];
            for await (const part of fragmentReplicaStream({
              ...statement,
              bytes: async function* () {
                yield* readBinaryChunks(db, "payload", batch.batch);
              },
              encrypt,
              maxBlobBytes: cap,
              targetChunkBytes: chunkBytes,
            })) {
              db.prepare(
                "INSERT INTO pdpp_transport_staged_fragments VALUES (?,?,?,?)",
              ).run(token, part.index, part.digest, part.encrypted);
              entries.push({
                digest: part.digest,
                bytes: part.encrypted.length,
              });
            }
            break;
          } catch (error) {
            db.prepare(
              "DELETE FROM pdpp_transport_staged_fragments WHERE token=?",
            ).run(token);
            // Only the typed, measured framing failure narrows the chunk size or
            // becomes Unsupported. Every other error is a transient Retry.
            // Unsupported is terminal for this batch only and claims no
            // version: later batches of this writer still prepare and
            // publish, and a remote importer holds them as Wait(predecessor)
            // until an explicit readmitUnsupported() under a new capability.
            if (!(error instanceof ReplicaFramingUnsupported)) throw error;
            if (error.dimension === "fragment_bytes" && chunkBytes > 1) {
              chunkBytes = Math.max(1, Math.floor(chunkBytes / 2));
              continue;
            }
            return unsupportedPlan(error);
          }
        }
        manifest = await prepareReplicaManifest({
          ...statement,
          fragments: entries,
          encrypt,
        });
        if (manifest.encrypted.length > cap)
          return unsupportedPlan(
            new ReplicaFramingUnsupported(
              manifest.encrypted.length,
              cap,
              "manifest_bytes",
            ),
          );
      } catch (error) {
        db.prepare(
          "DELETE FROM pdpp_transport_staged_fragments WHERE token=?",
        ).run(token);
        return verdict(retryFromError(error, "prepare_failed"));
      }
      return withPlan(
        { tag: "progress", receipt: { phase: "prepare", key: batch.batch } },
        () => {
          const current = db
            .prepare(
              "SELECT prepared FROM pdpp_transport_batches WHERE batch=?",
            )
            .get(batch.batch) as { prepared: number };
          // Concurrent preparation may choose different randomized ciphertext.
          // Only the first committed bytes can go on wire.
          if (!current.prepared) {
            const staged = db
              .prepare(
                "SELECT count(*) AS count FROM pdpp_transport_staged_fragments WHERE token=?",
              )
              .get(token) as { count: number };
            if (
              staged.count !== entries.length ||
              entries.length !== Math.ceil(batch.total_bytes / chunkBytes)
            )
              throw new ReplicaProblemError("prepare_failed");
            // The batch claims the writer's next version now, in the same
            // transaction as its manifest, so a retry or a lost
            // acknowledgement can never register it at a second version.
            const { version } = db
              .prepare(
                "SELECT coalesce(max(version),0)+1 AS version FROM pdpp_transport_manifests_out WHERE scope=?",
              )
              .get(manifest.scope) as { version: number };
            db.prepare(
              "INSERT INTO pdpp_transport_manifests_out (batch,scope,version,plaintext,encrypted,data_hash,metadata_hash) VALUES (?,?,?,?,?,?,?)",
            ).run(
              batch.batch,
              manifest.scope,
              version,
              manifest.plaintext,
              manifest.encrypted,
              manifest.dataHash,
              manifest.metadataHash,
            );
            db.prepare(
              "INSERT INTO pdpp_transport_fragments_out (batch,position,digest,encrypted) SELECT ?,position,digest,encrypted FROM pdpp_transport_staged_fragments WHERE token=?",
            ).run(batch.batch, token);
            db.prepare(
              "UPDATE pdpp_transport_batches SET prepared=1 WHERE batch=?",
            ).run(batch.batch);
          }
          db.prepare(
            "DELETE FROM pdpp_transport_staged_fragments WHERE token=?",
          ).run(token);
        },
      );
    },
    commit: commitIn((outcome, work, item) => {
      db.prepare(
        `UPDATE pdpp_transport_batches SET ${WORK_SET} WHERE batch=?`,
      ).run(...workValues(outcome, work), item.id);
    }),
    commitProblem: "prepare_failed",
    earliest(e) {
      return earliestIn(e, "pdpp_transport_batches WHERE prepared=0");
    },
  };

  // -------------------------------------------------------------- publish
  /**
   * Fragment PUTs, and manifests ready to register: every fragment of the
   * batch is stored and the previous version is published. DPv2 accepts only
   * the next version, so a writer has at most one registration in flight.
   */
  const OUTBOUND = `(SELECT 'fragment' AS kind, batch||':'||position AS id, batch, position,
      attempts,next_attempt,wait_since,checked_block,outcome,dependency
      FROM pdpp_transport_fragments_out WHERE state='ready'
    UNION ALL
    SELECT 'manifest' AS kind, m.scope||'/'||m.version AS id, m.batch, -1 AS position,
      m.attempts,m.next_attempt,m.wait_since,m.checked_block,m.outcome,m.dependency
      FROM pdpp_transport_manifests_out m WHERE m.state='ready'
      AND NOT EXISTS (SELECT 1 FROM pdpp_transport_fragments_out f WHERE f.batch=m.batch AND f.state<>'stored')
      AND (m.version=1 OR EXISTS (SELECT 1 FROM pdpp_transport_manifests_out p WHERE p.scope=m.scope AND p.version=m.version-1 AND p.state='published')))`;
  async function publishManifest(
    batch: string,
    signal: AbortSignal,
  ): Promise<ReplicaAttempt> {
    const row = db
      .prepare("SELECT * FROM pdpp_transport_manifests_out WHERE batch=?")
      .get(batch) as ManifestOut;
    const key = slotKey(row.scope, row.version);
    const expected: ReplicaSlot = {
      owner: state().owner,
      scope: row.scope,
      version: row.version,
      dataHash: row.data_hash,
      metadataHash: row.metadata_hash,
    };
    try {
      let evidence = await call(signal, () =>
        transport.evidence(row.scope, row.version),
      );
      let status = replicaRegistrationState(evidence, expected);
      if (status === "absent") {
        const manifest: PreparedManifest = {
          scope: row.scope,
          version: row.version,
          plaintext: row.plaintext,
          encrypted: row.encrypted,
          dataHash: row.data_hash,
          metadataHash: row.metadata_hash,
        };
        await call(signal, () => transport.put(manifest));
        await call(signal, () => transport.register(manifest));
        evidence = await call(signal, () =>
          transport.evidence(row.scope, row.version),
        );
        status = replicaRegistrationState(evidence, expected);
      }
      if (status === "conflict")
        return verdict(quarantine("immutable_registration_conflict", key));
      if (status === "confirmed")
        return verdict({
          tag: "progress",
          receipt: { phase: "publish", key },
        });
      return verdict(unconfirmed(evidence, expected));
    } catch (error) {
      return verdict(retryFromError(error, "publish_failed"));
    }
  }
  const publish: ReplicaPhaseHandler<Item<Outbound>> = {
    phase: "publish",
    due(e, limit) {
      // Parked waits are filtered before LIMIT so they cannot hide fresh or error work.
      return (
        db
          .prepare(
            dueWindow(OUTBOUND, "batch", "next_attempt,kind,position", due(e)),
          )
          .all(limit.perWriter, limit.after ?? "", limit.total) as Outbound[]
      ).map((row) => ({
        id: row.id,
        phase: "publish",
        // Local batches take turns like remote writers do.
        writer: row.batch,
        state: workState(row),
        row,
      }));
    },
    async run(item, signal) {
      const row = item.row;
      if (row.kind === "manifest") return publishManifest(row.batch, signal);
      try {
        const fragment = db
          .prepare(
            "SELECT digest,encrypted FROM pdpp_transport_fragments_out WHERE batch=? AND position=?",
          )
          .get(row.batch, row.position) as {
          digest: string;
          encrypted: Buffer;
        };
        // Unregistered and content-addressed: a PUT is safe to repeat, and
        // nothing references it until the manifest is finalized.
        await call(signal, () =>
          transport.putFragment({
            scope: replicaScope(state().writer),
            digest: fragment.digest,
            encrypted: fragment.encrypted,
          }),
        );
        return verdict({
          tag: "progress",
          receipt: { phase: "publish", key: row.id },
        });
      } catch (error) {
        return verdict(retryFromError(error, "publish_failed"));
      }
    },
    commit: (item, attempt, settle) =>
      commitIn<Item<Outbound>>((outcome, work) => {
        const next =
          outcome.tag === "progress"
            ? item.row.kind === "manifest"
              ? "published"
              : "stored"
            : outcome.tag === "quarantine"
              ? "quarantined"
              : "ready";
        if (item.row.kind === "manifest")
          db.prepare(
            `UPDATE pdpp_transport_manifests_out SET ${WORK_SET},state=? WHERE batch=?`,
          ).run(...workValues(outcome, work), next, item.row.batch);
        else
          db.prepare(
            `UPDATE pdpp_transport_fragments_out SET ${WORK_SET},state=? WHERE batch=? AND position=?`,
          ).run(
            ...workValues(outcome, work),
            next,
            item.row.batch,
            item.row.position,
          );
      })(item, attempt, settle),
    commitProblem: "publish_failed",
    earliest(e) {
      return earliestIn(e, `${OUTBOUND} outbound`);
    },
  };

  // ------------------------------------------------------------- discover
  const discover: ReplicaPhaseHandler<Item<Work>> = {
    phase: "discover",
    due(e) {
      const row = singleton("discover");
      return (singletonEligibleAt(row, e) ?? Infinity) <= e.now
        ? [
            {
              id: "discover",
              phase: "discover",
              writer: "",
              state: workState(row),
              row,
            },
          ]
        : [];
    },
    async run(_item, signal) {
      let page: Awaited<ReturnType<ReplicaTransportPort["list"]>>;
      try {
        page = await call(signal, () => transport.list(state().scan_cursor));
      } catch (error) {
        return verdict(retryFromError(error, "discovery_failed"));
      }
      // Page admissions and its cursor commit together. A null cursor restarts
      // from page one next step: no timestamp high-water mark can hide a late
      // registration. The Gateway version only says how many slots to admit;
      // each slot is verified against finalized evidence before any fetch.
      return withPlan(
        {
          tag: "progress",
          receipt: { phase: "discover", key: page.cursor ?? "" },
        },
        () => {
          for (const point of page.points) {
            const writer = replicaWriterOf(point.scope);
            if (!writer || !/^[1-9][0-9]{0,14}$/.test(point.version)) continue;
            const known = (
              db
                .prepare(
                  "SELECT coalesce(max(version),0) AS version FROM pdpp_transport_manifests_in WHERE scope=?",
                )
                .get(point.scope) as { version: number }
            ).version;
            const last = Math.min(
              Number(point.version),
              known + DISCOVER_SLOTS,
            );
            for (let version = known + 1; version <= last; version++)
              db.prepare(
                "INSERT OR IGNORE INTO pdpp_transport_manifests_in (slot,scope,version,writer) VALUES (?,?,?,?)",
              ).run(
                slotKey(point.scope, version),
                point.scope,
                version,
                writer,
              );
          }
          db.prepare(
            "UPDATE pdpp_transport_state SET scan_cursor=? WHERE id=1",
          ).run(page.cursor);
        },
      );
    },
    commit: commitIn((outcome, work) => {
      settleSingleton("discover", outcome, work);
    }),
    commitProblem: "discovery_failed",
    earliest(e) {
      // A polling source: only an outstanding Retry is a deadline.
      return singletonDeadline("discover", e);
    },
  };

  // ------------------------------------------------------------- download
  const slotItem =
    (phase: ReplicaPhase) =>
    (row: Slot): Item<Slot> => ({
      id: row.slot,
      phase,
      writer: row.writer,
      state: workState(row),
      row,
    });
  /** Make matching waits due now. Durable: survives a lost notification. */
  function wake(key: string, at: number) {
    return db
      .prepare(
        "UPDATE pdpp_transport_import_work SET next_attempt=? WHERE outcome='wait' AND dependency=? AND next_attempt>?",
      )
      .run(at, key, at).changes;
  }
  const download: ReplicaPhaseHandler<Item<Slot>> = {
    phase: "download",
    due(e, limit) {
      return (
        db
          .prepare(
            dueWindow(
              `(SELECT rowid AS position,slot,scope,version,writer,attempts,next_attempt,wait_since,checked_block,outcome,dependency FROM pdpp_transport_manifests_in WHERE state='ready' AND manifest_json IS NULL)`,
              "writer",
              "next_attempt,version",
              due(e),
            ),
          )
          .all(limit.perWriter, limit.after ?? "", limit.total) as Slot[]
      ).map(slotItem("download"));
    },
    async run(item, signal) {
      const row = item.row;
      const slot: ReplicaSlot = {
        owner: state().owner,
        scope: row.scope,
        version: row.version,
      };
      try {
        // A manifest is trusted only through its finalized slot commitment,
        // so nothing is fetched before that commitment exists.
        const evidence = await call(signal, () =>
          transport.evidence(row.scope, row.version),
        );
        if (replicaRegistrationState(evidence, slot) !== "confirmed")
          return verdict(unconfirmed(evidence, slot));
        const encrypted = await call(signal, () =>
          transport.get(row.scope, row.version),
        );
        if (encrypted.length > cap)
          throw new ReplicaProblemError("download_failed");
        const plaintext = await call(signal, () =>
          transport.decrypt(row.scope, encrypted),
        );
        const manifest = decodeReplicaManifest(
          plaintext,
          row.scope,
          state().owner,
        );
        const dataHash = keccak256(plaintext);
        const metadataHash = replicaMetadataHash(
          row.scope,
          manifest.collectedAt,
          encrypted.length,
        );
        // Storage is not trusted: bytes that are not the finalized
        // commitment are a refetch, never data.
        if (
          replicaRegistrationState(evidence, {
            ...slot,
            dataHash,
            metadataHash,
          }) !== "confirmed"
        )
          throw new ReplicaProblemError("commitment_mismatch");
        const record = factOf(row, evidence, manifest);
        return {
          outcome: {
            tag: "progress",
            receipt: { phase: "download", key: row.slot },
          },
          plan: () => {
            // A correct writer gives each batch one version. Another slot
            // naming the same batch is equivocation: only the first is used.
            const holder = db
              .prepare(
                "SELECT slot FROM pdpp_transport_manifests_in WHERE writer=? AND batch=? AND slot<>? AND state<>'quarantined'",
              )
              .get(row.writer, manifest.batch, row.slot);
            if (holder) {
              db.prepare(
                `UPDATE pdpp_transport_manifests_in SET ${QUARANTINE_SET("batch_equivocation")} WHERE slot=?`,
              ).run(row.slot);
              return quarantine("batch_equivocation", row.slot);
            }
            db.prepare(
              "UPDATE pdpp_transport_manifests_in SET manifest_json=?,data_hash=?,metadata_hash=?,batch=?,sequence=? WHERE slot=?",
            ).run(
              canonicalJson(manifest),
              dataHash,
              metadataHash,
              manifest.batch,
              manifest.sequence,
              row.slot,
            );
            manifest.fragments.forEach((entry, position) =>
              db
                .prepare(
                  "INSERT OR IGNORE INTO pdpp_transport_fragments_in (slot,position,digest,bytes) VALUES (?,?,?,?)",
                )
                .run(row.slot, position, entry.digest, entry.bytes),
            );
            record?.();
            return undefined;
          },
        };
      } catch (error) {
        // Network and unavailable bytes are retryable; authenticated malformed bytes back off.
        return verdict(retryFromError(error, "download_failed"));
      }
    },
    commit: commitIn((outcome, work, item) => {
      db.prepare(
        `UPDATE pdpp_transport_manifests_in SET ${WORK_SET} WHERE slot=? AND state='ready'`,
      ).run(...workValues(outcome, work), item.id);
    }),
    commitProblem: "download_failed",
    earliest(e) {
      return earliestIn(
        e,
        "pdpp_transport_manifests_in WHERE state='ready' AND manifest_json IS NULL",
      );
    },
  };

  // ---------------------------------------------------------------- fetch
  const manifestOf = (slot: string) =>
    JSON.parse(
      (
        db
          .prepare(
            "SELECT manifest_json FROM pdpp_transport_manifests_in WHERE slot=?",
          )
          .get(slot) as { manifest_json: string }
      ).manifest_json,
    ) as ReplicaManifest;
  /** A fragment that disproves its slot quarantines the slot with it. */
  const quarantineFragment = (
    row: FragmentIn,
    reason: "fragment_missing" | "fragment_mismatch",
  ) =>
    withPlan(quarantine(reason, `${row.slot}#${row.position}`), () =>
      db
        .prepare(
          `UPDATE pdpp_transport_manifests_in SET ${QUARANTINE_SET(reason)} WHERE slot=? AND state='ready'`,
        )
        .run(row.slot),
    );
  const FETCHABLE = `(SELECT f.rowid AS rowid_,f.slot,f.position,f.digest,f.bytes,m.writer,f.attempts,f.next_attempt,f.wait_since,f.checked_block,f.outcome,f.dependency
    FROM pdpp_transport_fragments_in f JOIN pdpp_transport_manifests_in m ON m.slot=f.slot
    WHERE f.state='ready' AND f.fragment_json IS NULL AND m.state='ready')`;
  const fetchFragment: ReplicaPhaseHandler<Item<FragmentIn>> = {
    phase: "fetch",
    due(e, limit) {
      return (
        db
          .prepare(
            dueWindow(FETCHABLE, "writer", "next_attempt,rowid_", due(e)),
          )
          .all(limit.perWriter, limit.after ?? "", limit.total) as FragmentIn[]
      ).map((row) => ({
        id: `${row.slot}#${row.position}`,
        phase: "fetch",
        writer: row.writer,
        state: workState(row),
        row,
      }));
    },
    async run(item, signal) {
      const row = item.row;
      const scope = replicaScope(row.writer);
      let encrypted: Uint8Array;
      try {
        encrypted = await call(signal, () =>
          transport.getFragment(scope, row.digest),
        );
      } catch (error) {
        // Only a definitive not-found is proof; anything else is transient.
        try {
          if (
            !(await call(signal, () =>
              transport.hasFragment(scope, row.digest),
            ))
          )
            return quarantineFragment(row, "fragment_missing");
        } catch {
          // The original failure decides the retry.
        }
        return verdict(retryFromError(error, "download_failed"));
      }
      // The finalized manifest names these exact bytes. Storage overwrites
      // without checks and reads without auth, so anything else is rejected
      // before it is decrypted.
      if (
        encrypted.length !== row.bytes ||
        replicaDigest(encrypted) !== row.digest
      )
        return quarantineFragment(row, "fragment_mismatch");
      let fragment: ReplicaFragment;
      try {
        // The bytes are committed: a fragment that does not decrypt, decode
        // or match its manifest is the writer's fault, not storage damage.
        const plaintext = await transport.decrypt(scope, encrypted);
        fragment = decodeReplicaFragment(plaintext, scope, state().owner);
        if (
          !fragmentMatchesManifest(fragment, manifestOf(row.slot), row.position)
        )
          return quarantineFragment(row, "fragment_mismatch");
      } catch (error) {
        if (signal.aborted)
          return verdict(retryFromError(error, "download_failed"));
        return quarantineFragment(row, "fragment_mismatch");
      }
      return withPlan(
        { tag: "progress", receipt: { phase: "fetch", key: item.id } },
        () => {
          db.prepare(
            "UPDATE pdpp_transport_fragments_in SET fragment_json=? WHERE slot=? AND position=?",
          ).run(canonicalJson(fragment), row.slot, row.position);
          wake(`fragments:${fragment.writer}:${fragment.batch}`, now());
        },
      );
    },
    commit: commitIn((outcome, work, item) => {
      db.prepare(
        `UPDATE pdpp_transport_fragments_in SET ${WORK_SET},state=? WHERE slot=? AND position=?`,
      ).run(
        ...workValues(outcome, work),
        outcome.tag === "quarantine" ? "quarantined" : "ready",
        item.row.slot,
        item.row.position,
      );
    }),
    commitProblem: "download_failed",
    earliest(e) {
      return earliestIn(e, `${FETCHABLE} fetchable`);
    },
  };

  // ----------------------------------------- revalidate (imported slots)
  /**
   * A finalized fact disagrees with an imported slot. The batch records the
   * fact and takes the copy decision, which is terminal for a disproved
   * promoted copy (contract A, H).
   */
  function importedConflict(
    row: Slot,
    evidence: ReplicaRegistrationEvidence,
  ): ReplicaAttempt {
    const manifest = manifestOf(row.slot);
    const id = canonicalJson([manifest.writer, manifest.batch]);
    const record = factOf(row, evidence, manifest);
    return {
      outcome: quarantine("immutable_registration_conflict", row.slot),
      plan: () => {
        record?.();
        const decision = deps.receiver.copies.decide(id, {
          attempts: 0,
          budget: deps.refetchBudget ?? REPLICA_REFETCH_BUDGET,
        });
        if (decision.kind !== "terminal")
          return { tag: "retry", problem: "commitment_mismatch" };
        deps.receiver.copies.apply({
          credential: deps.credential,
          id,
          decision,
        });
        quarantineWriterFrom(manifest.writer, manifest.sequence);
        return quarantine("finalized_conflict", id);
      },
    };
  }
  const revalidate: ReplicaPhaseHandler<Item<Slot>> = {
    phase: "revalidate",
    due(e, limit) {
      // Round-robin by last check, so a fixed prefix cannot starve later slots.
      return (
        db
          .prepare(
            `SELECT slot,scope,version,writer,data_hash,metadata_hash,attempts,next_attempt,wait_since,checked_block FROM pdpp_transport_manifests_in WHERE state='imported' AND ${due(e)} ORDER BY evidence_checked,rowid LIMIT ?`,
          )
          .all(limit.total) as Slot[]
      ).map(slotItem("revalidate"));
    },
    async run(item, signal) {
      const row = item.row;
      const slot: ReplicaSlot = {
        owner: state().owner,
        scope: row.scope,
        version: row.version,
        dataHash: row.data_hash ?? undefined,
        metadataHash: row.metadata_hash ?? undefined,
      };
      try {
        const evidence = await call(signal, () =>
          transport.evidence(row.scope, row.version),
        );
        const status = replicaRegistrationState(evidence, slot);
        if (status === "conflict") return importedConflict(row, evidence);
        // Only a confirmed check is Progress. Unavailable or inactive evidence
        // is not a successful check (an imported slot stays visible meanwhile).
        if (status === "confirmed")
          return verdict({
            tag: "progress",
            receipt: { phase: "revalidate", key: row.slot },
          });
        return verdict(
          replicaRegistrationInactive(evidence, slot)
            ? finalityWait(evidence, row.slot)
            : { tag: "retry", problem: "evidence_unavailable" },
        );
      } catch (error) {
        return verdict(retryFromError(error, "evidence_unavailable"));
      }
    },
    commit: commitIn((outcome, work, item) => {
      const checked = (
        db
          .prepare(
            "SELECT COALESCE(MAX(evidence_checked),0) AS value FROM pdpp_transport_manifests_in WHERE state='imported'",
          )
          .get() as { value: number }
      ).value;
      const interval = deps.revalidateIntervalMs ?? 0;
      // A revalidated slot is never terminal: it is checked again on the sweep interval.
      const next =
        outcome.tag === "progress"
          ? { ...work, nextEligible: now() + interval }
          : work;
      if (outcome.tag === "quarantine")
        db.prepare(
          `UPDATE pdpp_transport_manifests_in SET ${QUARANTINE_SET("immutable_registration_conflict")} WHERE slot=? AND state='imported'`,
        ).run(item.id);
      else
        db.prepare(
          `UPDATE pdpp_transport_manifests_in SET ${WORK_SET},evidence_checked=? WHERE slot=?`,
        ).run(...workValues(outcome, next), checked + 1, item.id);
    }),
    commitProblem: "evidence_unavailable",
    earliest(e) {
      // A sweep on the host's cadence: only Retry and Wait are deadlines.
      return earliestIn(
        e,
        "pdpp_transport_manifests_in WHERE state='imported' AND outcome IN ('retry','wait')",
      );
    },
  };

  // --------------------------------------------------------------- import
  type Refetch = { attempts: number; budget: number };
  type Group = Work & {
    slot: string;
    writer: string;
    batch: string;
    sequence: number;
  };
  /** Ordered verified fragments of one complete slot, read one row at a time. */
  function retainedBytes(slot: string) {
    const positions = (
      db
        .prepare(
          "SELECT position FROM pdpp_transport_fragments_in WHERE slot=? ORDER BY position",
        )
        .all(slot) as { position: number }[]
    ).map((r) => r.position);
    return () =>
      assembleReplicaStream(async function* () {
        for (const position of positions)
          yield JSON.parse(
            (
              db
                .prepare(
                  "SELECT fragment_json FROM pdpp_transport_fragments_in WHERE slot=? AND position=?",
                )
                .get(slot, position) as { fragment_json: string }
            ).fragment_json,
          ) as ReplicaFragment;
      });
  }
  /**
   * Fail closed at writer scope (contract H): every retained slot of the
   * writer from `sequence` on leaves import and revalidation.
   */
  function quarantineWriterFrom(writer: string, sequence: number) {
    db.prepare(
      `UPDATE pdpp_transport_manifests_in SET ${QUARANTINE_SET("finalized_conflict")} WHERE writer=? AND sequence>=?`,
    ).run(writer, sequence);
  }
  /** Durable acknowledgement of an imported batch, and its successor's wake. */
  function acknowledge(group: Group, manifest: ReplicaManifest) {
    if (
      !db
        .prepare(
          "SELECT 1 FROM pdpp_transport_imported WHERE writer=? AND batch=?",
        )
        .get(group.writer, group.batch)
    )
      db.prepare("INSERT INTO pdpp_transport_imported VALUES (?,?,?,?)").run(
        group.writer,
        group.batch,
        manifest.sequence,
        manifest.digest,
      );
    db.prepare(
      "UPDATE pdpp_transport_manifests_in SET state='imported',error=NULL WHERE slot=?",
    ).run(group.slot);
    // The receiver retains its own copy: the fragment bodies are scratch now.
    db.prepare("DELETE FROM pdpp_transport_fragments_in WHERE slot=?").run(
      group.slot,
    );
    wake(`predecessor:${group.writer}:${manifest.sequence}`, now());
  }
  /**
   * The copy decision for one complete download of a batch (contract v3.1
   * §3 "Coordinator step"). Runs inside the import outcome transaction, over
   * the durable copies, facts and disposition it commits with.
   */
  function decideImport(
    group: Group,
    manifest: ReplicaManifest,
    stage: ((refetch: Refetch) => void) | undefined,
  ): ReplicaPhaseOutcome {
    const { writer, batch } = group;
    const id = canonicalJson([writer, batch]);
    const key = `${writer}:${batch}`;
    const credential = deps.credential;
    db.prepare(
      "INSERT INTO pdpp_transport_import_work (writer,batch,sequence) VALUES (?,?,?) ON CONFLICT(writer,batch) DO NOTHING",
    ).run(writer, batch, group.sequence);
    const refetch: Refetch = {
      attempts: (
        db
          .prepare(
            "SELECT refetch_attempts FROM pdpp_transport_import_work WHERE writer=? AND batch=?",
          )
          .get(writer, batch) as { refetch_attempts: number }
      ).refetch_attempts,
      budget: deps.refetchBudget ?? REPLICA_REFETCH_BUDGET,
    };
    stage?.(refetch);
    const decision = deps.receiver.copies.decide(id, refetch);
    const terminal = (): ReplicaPhaseOutcome => {
      quarantineWriterFrom(writer, manifest.sequence);
      return quarantine("finalized_conflict", id);
    };
    const progress: ReplicaPhaseOutcome = {
      tag: "progress",
      receipt: { phase: "import", key },
    };
    switch (decision.kind) {
      case "terminal":
        deps.receiver.copies.apply({ credential, id, decision });
        return terminal();
      case "wait":
        deps.receiver.copies.apply({ credential, id, decision });
        return { tag: "wait", dependency: { kind: "fragments", key } };
      case "owner":
        deps.receiver.copies.apply({ credential, id, decision });
        return { tag: "wait", dependency: { kind: "owner", key } };
      case "refetch": {
        // One completed non-matching observation spends one unit of budget,
        // in the transaction that commits it; a discarded attempt spends none.
        deps.receiver.copies.apply({ credential, id, decision });
        db.prepare(
          "UPDATE pdpp_transport_import_work SET refetch_attempts=refetch_attempts+1 WHERE writer=? AND batch=?",
        ).run(writer, batch);
        const at = now() + defaultReplicaBackoff(refetch.attempts + 1);
        db.prepare("DELETE FROM pdpp_transport_fragments_in WHERE slot=?").run(
          group.slot,
        );
        db.prepare(
          `UPDATE pdpp_transport_manifests_in SET manifest_json=NULL,data_hash=NULL,metadata_hash=NULL,batch=NULL,sequence=NULL,state='ready',${RESET_WORK},next_attempt=? WHERE slot=?`,
        ).run(at, group.slot);
        return { tag: "wait", dependency: { kind: "fragments", key } };
      }
      case "reconcile_promoted":
        deps.receiver.copies.apply({ credential, id, decision });
        acknowledge(group, manifest);
        return progress;
      case "promote": {
        const result = deps.receiver.copies.promote({
          credential,
          id,
          copyKey: decision.copyKey,
        });
        if (result.kind === "terminal") return terminal();
        if (result.kind === "wait_predecessor")
          return {
            tag: "wait",
            dependency: {
              kind: "predecessor",
              key: `${writer}:${manifest.sequence - 1}`,
            },
          };
        acknowledge(group, manifest);
        return progress;
      }
    }
  }
  /**
   * The verified finalized fact a slot's evidence carries (contract F2), as
   * an effect for the caller's outcome transaction. Unavailable evidence
   * (thrown) and a chain object for another owner or slot are not facts.
   * The effect returns true when the fact is new, and then wakes the batch.
   */
  function factOf(
    row: Slot,
    evidence: ReplicaRegistrationEvidence,
    manifest: ReplicaManifest,
  ): (() => boolean) | undefined {
    const chain = evidence.chain;
    if (
      !chain ||
      chain.owner.toLowerCase() !== state().owner.toLowerCase() ||
      chain.scope !== row.scope ||
      chain.version !== String(row.version) ||
      !/^(0|[1-9][0-9]*)$/.test(chain.currentVersion)
    )
      return undefined;
    const { writer, batch } = manifest;
    return () => {
      const added = deps.receiver.copies.recordFact({
        credential: deps.credential,
        id: canonicalJson([writer, batch]),
        scope: row.scope,
        // A manifest batch has exactly one registered slot.
        fragmentIndex: 0,
        fact: {
          chainId: chain.chainId,
          registry: chain.registry,
          owner: chain.owner,
          version: chain.version,
          currentVersion: chain.currentVersion,
          status: chain.status,
          commitment: chain.commitment,
          blockNumber: chain.blockNumber,
          blockHash: chain.blockHash,
          // Eligibility is the fact's own: Active, with a live head that
          // agrees with the slot (contract D, I).
          eligible:
            replicaRegistrationState(evidence, {
              owner: state().owner,
              scope: row.scope,
              version: row.version,
            }) === "confirmed",
        },
      });
      if (added) {
        wake(`fragments:${writer}:${batch}`, now());
        wake(`owner:${writer}:${batch}`, now());
      }
      return added;
    };
  }
  const importRun: ReplicaPhaseHandler<Item<Group>> = {
    phase: "import",
    due(e, limit) {
      // Slot metadata only: no fragment bodies from incomplete or other slots.
      return (
        db
          .prepare(
            `WITH complete AS (SELECT m.slot,m.writer,m.batch,m.sequence FROM pdpp_transport_manifests_in m WHERE m.state='ready' AND m.manifest_json IS NOT NULL
              AND NOT EXISTS (SELECT 1 FROM pdpp_transport_fragments_in f WHERE f.slot=m.slot AND (f.fragment_json IS NULL OR f.state<>'ready'))),
            candidates AS (SELECT c.slot,c.writer,c.batch,c.sequence,coalesce(w.attempts,0) AS attempts,coalesce(w.next_attempt,0) AS next_attempt,w.wait_since,w.checked_block FROM complete c LEFT JOIN pdpp_transport_import_work w ON w.writer=c.writer AND w.batch=c.batch WHERE w.writer IS NULL OR (${replicaEligibleAtSql(e, { outcome: "w.outcome", dependency: "w.dependency", next: "w.next_attempt", since: "w.wait_since", checked: "w.checked_block" })} <= ${e.now} AND coalesce(w.outcome,'') NOT IN ('quarantine','unsupported')))
            SELECT * FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY writer ORDER BY next_attempt,sequence,batch) AS writer_rank FROM candidates) WHERE writer_rank<=? ORDER BY writer_rank, writer<=?, writer, next_attempt, sequence, batch LIMIT ?`,
          )
          .all(limit.perWriter, limit.after ?? "", limit.total) as Group[]
      ).map((row) => ({
        id: `${row.writer}:${row.batch}`,
        phase: "import",
        writer: row.writer,
        state: workState(row),
        row,
      }));
    },
    async run(item, signal) {
      const { writer, batch, slot } = item.row;
      const id = item.id;
      const manifest = manifestOf(slot);
      const hashes = db
        .prepare(
          "SELECT data_hash,metadata_hash FROM pdpp_transport_manifests_in WHERE slot=?",
        )
        .get(slot) as { data_hash: Hex; metadata_hash: Hex };
      const pendingId = canonicalJson([writer, batch]);
      /** Terminal for this batch; the receiver drops any staged copy of it. */
      const refuse = (
        reason: ReplicaAuthorityRefusal | "batch_equivocation",
        receiverReason: string = reason,
      ) =>
        withPlan(quarantine(reason, id), () => {
          deps.receiver.quarantine({
            credential: deps.credential,
            id: pendingId,
            reason: receiverReason,
          });
          db.prepare(
            `UPDATE pdpp_transport_manifests_in SET ${QUARANTINE_SET(reason)} WHERE slot=?`,
          ).run(slot);
        });
      const imported = db
        .prepare(
          "SELECT digest,sequence FROM pdpp_transport_imported WHERE writer=? AND batch=?",
        )
        .get(writer, batch) as { digest: string; sequence: number } | undefined;
      const sequenceHolder = db
        .prepare(
          "SELECT batch FROM pdpp_transport_imported WHERE writer=? AND sequence=?",
        )
        .get(writer, manifest.sequence) as { batch: string } | undefined;
      // A different batch reusing an imported writer sequence (or a changed
      // digest) is proven equivocation: terminal, never a hot retry.
      if (
        (imported &&
          (imported.digest !== manifest.digest ||
            imported.sequence !== manifest.sequence)) ||
        (sequenceHolder && sequenceHolder.batch !== batch)
      )
        return refuse("batch_equivocation", "batch equivocation");
      const staging: string[] = [];
      /**
       * Copy custody of this download, if its copy is not retained yet. It
       * commits only inside this attempt's outcome transaction, so a crash
       * or a discarded attempt never leaves custody without its outcome.
       */
      let stage: ((refetch: Refetch) => void) | undefined;
      // A batch's one registered slot is its copy's one commitment.
      const fragments = [
        {
          dataHash: hashes.data_hash.toLowerCase(),
          metadataHash: hashes.metadata_hash.toLowerCase(),
        },
      ];
      try {
        const copyKey = replicaCopyKey([
          replicaChainCommitment(hashes.data_hash, hashes.metadata_hash),
        ]);
        const retained = deps.receiver.copies
          .list(pendingId)
          .some((copy) => copy.copyKey === copyKey);
        if (!retained) {
          const writers = new Map<
            number,
            { key: string; writer: ReturnType<typeof binaryWriter> }
          >();
          const payload = await inspectReplicaPayload(
            retainedBytes(slot),
            undefined,
            (_blobId, chunk, blobIndex) => {
              let target = writers.get(blobIndex);
              if (!target) {
                const key = randomUUID();
                staging.push(key);
                target = { key, writer: binaryWriter(db, "staging", key) };
                writers.set(blobIndex, target);
              }
              db.transaction(() => target.writer.write(chunk))();
            },
          );
          // A discarded attempt stops before it prepares any custody.
          signal.throwIfAborted();
          if (payload.envelope.batchId !== manifest.batch)
            throw new ReplicaProblemError("payload_invalid");
          // Trusted retained declarations, never claims copied from the envelope.
          // An unknown declaration is a dependency the host can supply later.
          const expected = deps.expected();
          const missing = payload.envelope.operations.find(
            (op) =>
              "declaration" in op &&
              !expected.declarations.some(
                (entry) =>
                  entry.sourceId === op.sourceId &&
                  canonicalJson(entry.binding) ===
                    canonicalJson(op.declaration),
              ),
          );
          if (missing && "declaration" in missing)
            return verdict({
              tag: "wait",
              dependency: {
                kind: "declaration",
                key: `${missing.sourceId}:${missing.declaration.stream}`,
              },
            });
          decodeReplicaEnvelope(canonicalJson(payload.envelope), expected);
          const stagedBlobs = payload.blobs.map((blob, index) => {
            let target = writers.get(index);
            if (!target) {
              const key = randomUUID();
              staging.push(key);
              target = { key, writer: binaryWriter(db, "staging", key) };
            }
            if (target.writer.finish() !== blob.sizeBytes)
              throw new ReplicaProblemError("payload_invalid");
            return {
              blobId: blob.blobId,
              key: target.key,
              sizeBytes: blob.sizeBytes,
            };
          });
          stage = (refetch) => {
            deps.receiver.copies.stage({
              credential: deps.credential,
              copy: {
                id: pendingId,
                writer,
                batch,
                sequence: manifest.sequence,
                previous: manifest.previous,
                envelopeDigest: manifest.digest,
                envelope: payload.envelope,
                fragments,
              },
              stagedBlobs,
              refetch,
            });
            for (const key of staging) deleteBinary(db, "staging", key);
          };
        }
        const plan = stage;
        // The copy decision runs inside the outcome transaction, over the
        // durable copies, facts and disposition it commits with.
        return {
          outcome: {
            tag: "progress",
            receipt: { phase: "import", key: id },
          },
          plan: () => decideImport(item.row, manifest, plan),
        };
      } catch (error) {
        stage = undefined;
        return verdict(retryFromError(error, "import_failed"));
      } finally {
        // Without a plan to consume it, staging is scratch. A discarded
        // attempt's staging is reclaimed at the next step start.
        if (!stage) for (const key of staging) deleteBinary(db, "staging", key);
      }
    },
    commit: commitIn((outcome, work, item) => {
      db.prepare(
        "INSERT INTO pdpp_transport_import_work (writer,batch,sequence) VALUES (?,?,?) ON CONFLICT(writer,batch) DO NOTHING",
      ).run(item.row.writer, item.row.batch, item.row.sequence);
      db.prepare(
        `UPDATE pdpp_transport_import_work SET ${WORK_SET} WHERE writer=? AND batch=?`,
      ).run(...workValues(outcome, work), item.row.writer, item.row.batch);
    }),
    commitProblem: "import_failed",
    earliest(e) {
      return earliestIn(
        e,
        "pdpp_transport_import_work WHERE coalesce(outcome,'') NOT IN ('progress','quarantine','unsupported')",
      );
    },
  };

  // ----------------------------------------- reconcile (retained dependencies)
  /**
   * Durable fingerprint of what retained operations outside an import can wait
   * on: local connection mappings and trusted declarations. Two small reads,
   * never retained history. An import reconciles inside its own transaction,
   * so received operations are not part of it. A validator change that keeps
   * the declaration digest arrives as onDependencyChanged("declaration:...").
   */
  function dependencyFingerprint() {
    const bindings = db
      .prepare(
        "SELECT instance,source_id,method,generation,deleted_at FROM pdpp_instance_binding ORDER BY instance",
      )
      .all();
    const declarations = deps
      .expected()
      .declarations.map((d) => [d.sourceId, d.binding.digest, d.binding.stream])
      .sort();
    return createHash("sha256")
      .update(canonicalJson({ bindings, declarations }))
      .digest("hex");
  }
  let fingerprint = "";
  /** The first unmet dependency a reconcile reported, in a stable order. */
  function pendingDependency(
    plan: ReturnType<typeof deps.receiver.retry>,
  ): ReplicaDependency | undefined {
    const found: ReplicaDependency[] = [];
    for (const issue of plan.pending)
      for (const op of issue.operations)
        if (issue.reason === "missing_local_connection")
          found.push({ kind: "mapping", key: op.connectionId });
        else if (issue.reason === "missing_declaration" && "declaration" in op)
          found.push({
            kind: "declaration",
            key: `${op.sourceId}:${op.declaration.stream}`,
          });
        else
          found.push({
            kind: "reset",
            key: `${op.connectionId}:${op.generation}`,
          });
    return found.sort((x, y) =>
      dependencyKey(x).localeCompare(dependencyKey(y)),
    )[0];
  }
  /**
   * Canonical reconcile of retained history. It reads every retained
   * operation, so it runs only when a dependency changed: the fingerprint
   * moved, a host notification woke it, or an outstanding Wait reached its
   * bounded fallback. With nothing outstanding it is never due on a timer.
   */
  const reconcile: ReplicaPhaseHandler<Item<Work>> = {
    phase: "reconcile",
    due(e) {
      const row = singleton("reconcile");
      return row.fingerprint !== fingerprint ||
        (singletonEligibleAt(row, e) ?? Infinity) <= e.now
        ? [
            {
              id: "reconcile",
              phase: "reconcile",
              writer: "",
              state: workState(row),
              row,
            },
          ]
        : [];
    },
    async run() {
      // The canonical commit runs inside this attempt's outcome transaction:
      // the plan reconciles and returns the verdict its result implies.
      const seen = fingerprint;
      return {
        outcome: {
          tag: "progress",
          receipt: { phase: "reconcile", key: seen },
        },
        plan: () => {
          const plan = deps.receiver.retry({ credential: deps.credential });
          const dependency = pendingDependency(plan);
          return dependency ? { tag: "wait", dependency } : undefined;
        },
      };
    },
    commit: commitIn((outcome, work) =>
      settleSingleton(
        "reconcile",
        outcome,
        // With nothing outstanding it waits for a dependency change only.
        outcome.tag === "progress"
          ? { ...work, nextEligible: REPLICA_TERMINAL }
          : work,
        fingerprint,
      ),
    ),
    commitProblem: "reconcile_failed",
    earliest(e) {
      const row = singleton("reconcile");
      if (row.fingerprint !== fingerprint) return e.now;
      return singletonEligibleAt(row, e);
    },
    wake(key, at) {
      const row = singleton("reconcile");
      const outstanding = (
        db
          .prepare(
            "SELECT dependency FROM pdpp_transport_phase_state WHERE phase='reconcile'",
          )
          .get() as { dependency: string | null } | undefined
      )?.dependency;
      // A declaration notification can change validation of any retained
      // operation; other keys matter only when they are what it waits on.
      if (
        row.next_attempt <= at ||
        (!key.startsWith("declaration:") && key !== outstanding)
      )
        return 0;
      db.prepare(
        "UPDATE pdpp_transport_phase_state SET next_attempt=? WHERE phase='reconcile'",
      ).run(at);
      return 1;
    },
  };

  const coordinator = createReplicaCoordinator({
    phases: [
      retain,
      prepare,
      publish,
      discover,
      download,
      fetchFragment,
      revalidate,
      importRun,
      reconcile,
    ] as ReplicaPhaseHandler[],
    quantum: {
      retain: 1,
      prepare: 4,
      publish: 50,
      discover: 1,
      download: 50,
      fetch: 50,
      revalidate: 50,
      import: 50,
      reconcile: 1,
      ...deps.quantum,
    },
    perWriter: deps.perWriter,
    deadlineMs: deps.deadlineMs,
    background: ["revalidate"],
    clock: now,
    ...(transport.finality && {
      hint: {
        head: (signal: AbortSignal) =>
          abortable(signal, () => transport.finality!.head()),
      },
    }),
  });

  function acquireWriter(token: string) {
    db.transaction(() => {
      const holder = db
        .prepare("SELECT pid,token FROM pdpp_transport_lock WHERE id=1")
        .get() as { pid: number; token: string } | undefined;
      if (holder?.pid === process.pid && !ownedTokens.has(holder.token)) {
        db.prepare("DELETE FROM pdpp_transport_lock WHERE id=1").run();
      } else if (holder) {
        try {
          process.kill(holder.pid, 0);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ESRCH") {
            db.prepare("DELETE FROM pdpp_transport_lock WHERE id=1").run();
          } else throw error;
        }
        if (db.prepare("SELECT 1 FROM pdpp_transport_lock WHERE id=1").get())
          throw Object.assign(
            new Error("replica database worker already active"),
            { code: "replica_worker_active" },
          );
      }
      db.prepare("INSERT INTO pdpp_transport_lock VALUES (1,?,?)").run(
        process.pid,
        token,
      );
    }).immediate();
    ownedTokens.add(token);
  }
  let running = false;
  const databaseKey = db.name && db.name !== ":memory:" ? db.name : db;
  const idle = (): ProgressReport => ({
    receipts: [],
    waits: [],
    problems: [],
    quarantines: [],
    unsupported: [],
    nextWake: undefined,
  });

  /**
   * One bounded coordinator step. The authority context is validated before any
   * phase; a mismatch rejects the step without encrypt, network or receiver calls.
   */
  async function step(
    input: { budget?: ReplicaBudget; signal?: AbortSignal } = {},
  ): Promise<ProgressReport> {
    // A closed door stops replication for good: no identity, capture or
    // publish work.
    if (
      !enabled() ||
      running ||
      activeDatabases.has(databaseKey) ||
      !replicationAdmitted(db)
    )
      return idle();
    // Writer ids come from this server's own registration. Until it is
    // registered under the owner, nothing runs.
    running = true;
    let own;
    try {
      own = await enableReplicaWriterIdentity({
        db,
        owner: deps.expected().owner,
        server,
        roster,
        signal: input.signal,
      });
    } finally {
      running = false;
    }
    if (own.tag === "refused") return idle();
    if (own.tag === "waiting")
      return {
        ...idle(),
        waits: [
          {
            id: "writer-identity",
            phase: "retain",
            dependency: { kind: "roster", key: server },
          },
        ],
        nextWake: now() + REPLICA_WAIT_FALLBACK_MS,
      };
    const writerToken = randomUUID();
    acquireWriter(writerToken);
    running = true;
    activeDatabases.add(databaseKey);
    try {
      // Under the writer lock: a new identity resets the writer's chain.
      if (!authority(own.identity)) return idle();
      // Only this process owns the worker. None of these hidden stages can be published.
      db.transaction(() => {
        db.prepare("DELETE FROM pdpp_transport_staged_fragments").run();
        for (const table of ["pdpp_binary_chunks", "pdpp_binary_manifests"]) {
          db.prepare(
            `DELETE FROM ${table} WHERE namespace='staging' OR (namespace='payload' AND NOT EXISTS (SELECT 1 FROM pdpp_transport_batches b WHERE b.batch=${table}.blob_id))`,
          ).run();
        }
      }).immediate();
      const current = dependencyFingerprint();
      if (current !== fingerprint) {
        fingerprint = current;
        db.prepare(
          "UPDATE pdpp_transport_import_work SET next_attempt=? WHERE outcome='wait' AND (dependency LIKE 'mapping:%' OR dependency LIKE 'declaration:%') AND next_attempt>?",
        ).run(now(), now());
      }
      return await coordinator.step(
        now(),
        input.signal,
        input.budget ?? { units: Number.POSITIVE_INFINITY },
      );
    } finally {
      running = false;
      activeDatabases.delete(databaseKey);
      try {
        db.prepare(
          "DELETE FROM pdpp_transport_lock WHERE id=1 AND token=?",
        ).run(writerToken);
      } finally {
        ownedTokens.delete(writerToken);
      }
    }
  }
  return {
    step,
    /** Legacy entry point: one unbounded step. Rejects when a whole phase failed. */
    async cycle(): Promise<void> {
      const report = await step();
      const failed = report.problems.filter((p) =>
        ["retain", "discover", "reconcile"].includes(p.phase),
      );
      if (failed.length)
        throw new AggregateError(
          failed.map(
            (p) =>
              new ReplicaProblemError(p.problem, {
                ...(p.cause && { cause: p.cause }),
              }),
          ),
          "Replica transport cycle incomplete",
        );
    },
    /**
     * Explicit capability change: re-admit Unsupported batches that were
     * measured against a different capability than the current cap. Same
     * batch, digest and operations; the old admission stays as history. A
     * plain restart never re-admits. Returns the number re-admitted.
     */
    readmitUnsupported(): number {
      return db
        .prepare(
          `UPDATE pdpp_transport_batches SET prepared=0,outcome=NULL,reason=NULL,error=NULL,attempts=0,next_attempt=0
          WHERE prepared=-1 AND coalesce(json_extract(admission_json,'$.capability'),'') <> ?`,
        )
        .run(`cap:${cap}`).changes;
    },
    /**
     * Owner decision after storage was repaired: fetch again every slot that
     * was quarantined for a missing or mismatched fragment. The finalized
     * manifest still decides which bytes are accepted. Returns the number of
     * slots re-admitted.
     */
    readmitFragments(): number {
      return db.transaction(() => {
        const reasons = "('fragment_missing','fragment_mismatch')";
        const slots = (
          db
            .prepare(
              `SELECT slot FROM pdpp_transport_manifests_in WHERE state='quarantined' AND reason IN ${reasons}`,
            )
            .all() as { slot: string }[]
        ).map((r) => r.slot);
        for (const slot of slots) {
          db.prepare(
            `UPDATE pdpp_transport_fragments_in SET state='ready',fragment_json=NULL,${RESET_WORK},next_attempt=0 WHERE slot=? AND state='quarantined'`,
          ).run(slot);
          db.prepare(
            `UPDATE pdpp_transport_manifests_in SET state='ready',${RESET_WORK},next_attempt=0 WHERE slot=?`,
          ).run(slot);
        }
        return slots.length;
      })();
    },
    /** A host-observed dependency change (e.g. `mapping:<connection>`). Idempotent. */
    onDependencyChanged(key: string) {
      return wake(key, now()) + coordinator.onDependencyChanged(key, now());
    },
  };
}
