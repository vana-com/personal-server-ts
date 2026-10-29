/**
 * The replication phase engine: retain, prepare, publish, discover,
 * download, fetch, revalidate, import and reconcile under one coordinator.
 *
 * The phase logic is written once, as storage effects (./effects.ts), and
 * two hosts run it: Node over better-sqlite3, synchronously
 * (packages/server `pdpp-replication-transport.ts`), and PS-Lite over its
 * native SQLite transaction, asynchronously (packages/lite
 * `replication-engine.ts`). A host supplies storage and its transactions,
 * the replication door, the writer lock and identity, blob staging, payload
 * bytes, its exporter and its receiver (`ReplicaEngineHost`). The phase
 * order, SQL, outcomes and network protocol live here only.
 *
 * On a synchronous host every storage call answers with a plain value, so a
 * phase's storage work between two network awaits runs to completion as one
 * synchronous block, as it did before the engine was shared.
 */
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import {
  encodeReplicaPayload,
  fragmentReplicaStream,
  assembleReplicaStream,
  inspectReplicaPayload,
  replicaPayloadOperationCrossings,
  replicaStreamCiphertextByteLength,
  hashReplicaBytes,
  DEFAULT_REPLICA_STREAMED_LIMITS,
} from "./stream.js";
import {
  admit,
  ReplicaByteBudget,
  ReplicaResourceBusyError,
  ReplicaResourceLimitError,
  REPLICA_DEFAULT_BYTE_BUDGET_BYTES,
  REPLICA_DEFAULT_FRAGMENT_BYTES,
  REPLICA_MAX_FRAGMENTS,
  REPLICA_BATCH_OPERATION_LIMIT,
  REPLICA_BATCH_TARGET_BYTES,
  REPLICA_LIVE_COPY_FACTOR,
  REPLICA_ENVELOPE_LIVE_COPY_FACTOR,
  replicaResourceLimits,
  REPLICA_LIMITS_VERSION,
  type Admission,
  type ReplicaResourceLimits,
} from "./limits.js";
import {
  canonicalJson,
  decodeReplicaEnvelope,
  REPLICA_TEXT_PART_BYTES,
  replicaTextParts,
  type EnvelopeExpectation,
  type ReplicaEnvelope,
  type ReplicaOperation,
} from "./envelope.js";
import {
  prepareReplicaFragment,
  prepareReplicaManifest,
  decodeReplicaManifest,
  replicaDigest,
  replicaManifestFacts,
  replicaScope,
  replicaWriterOf,
  REPLICA_MAX_BLOB_BYTES,
  type ManifestEntry,
  type PreparedManifest,
  type ReplicaFragment,
  type ReplicaManifest,
  type Predecessor,
} from "./transport.js";
import {
  replicaRegistrationState,
  replicaAwaitingFinality,
  replicaRegistrationInactive,
  replicaChainCommitment,
  ReplicaObjectRefused,
  type ReplicaSlot,
  type ReplicaTransportPort,
  type ReplicaRegistrationEvidence,
} from "./dpv2.js";
import {
  receiveReplicaManifest,
  receiveReplicaFragment,
  REPLICA_RECEIVE_TIMEOUT_MS,
} from "./receive.js";
import {
  abortable,
  createAsyncReplicaCoordinator,
  REPLICA_REPORT_LIMIT,
  REPLICA_STEP_BYTES,
  validateReplicaStep,
  type AsyncReplicaCoordinatorStatePort,
  type AsyncReplicaPhaseHandler,
  type ReplicaAttempt,
  type ReplicaCoordinatorStatePort,
  type ReplicaSettle,
  type ProgressReport,
  type ReplicaBudget,
  type ReplicaWorkItem,
} from "./coordinator.js";
import { REPLICA_COORDINATOR_SCHEMA } from "./coordinator-state.js";
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
} from "./outcome.js";
import {
  replicaCopyKey,
  REPLICA_REFETCH_BUDGET,
  type CopyDecision,
  type FinalizedFact,
} from "./copy-promotion.js";
import { replicaCopyEnvelope } from "./copies.js";
import {
  defaultReplicaBackoff,
  REPLICA_TERMINAL,
  REPLICA_WAIT_FALLBACK_MS,
  replicaEligibleAt,
  replicaEligibleAtSql,
  type ReplicaEligibility,
  type ReplicaWorkState,
} from "./schedule.js";
import { createCachedReplicaRoster, type ReplicaRosterPort } from "./roster.js";
import {
  authorizeReplicaBatch,
  replicaOperationWriterRefusal,
  signReplicaBatch,
  type ReplicaAuthorityRefusal,
  type ReplicaBatchSigner,
  type ReplicaEnvironment,
  type ReplicaPartition,
  type ReplicaWriterSeed,
} from "./writer-identity.js";
import type { ReplicationRefusal } from "./door.js";
import { resolveDeclaration, type ReplicaMergePlan } from "./merge-plan.js";
import {
  sql,
  type ReplicaEffect,
  type ReplicaEffectContext,
} from "./effects.js";
import {
  deleteReplicaPayload,
  readReplicaPayload,
  readReplicaPayloadWindow,
  replicaPayloadWriter,
  verifyReplicaPayload,
} from "./payload.js";
import {
  REPLICA_PREPARATION_MIGRATION,
  classifyReplicaPreparationError,
  preparationOperationFailures,
  snapshotReplicaOperation,
  type ReplicaPreparation,
  type RetainedPreparationOperation,
} from "./preparation.js";

type MaybePromise<T> = T | Promise<T>;
const isPromiseLike = (value: unknown): value is PromiseLike<unknown> =>
  typeof value === "object" &&
  value !== null &&
  typeof (value as { then?: unknown }).then === "function";
/** Sequence without awaiting, so a synchronous host stays synchronous. */
function then<T, R>(
  value: MaybePromise<T>,
  next: (value: T) => MaybePromise<R>,
): MaybePromise<R> {
  return isPromiseLike(value)
    ? (value as Promise<T>).then(next)
    : next(value as T);
}

// Each process shares one default ledger, whichever host it runs.
const processReplicaByteBudget = new ReplicaByteBudget(
  REPLICA_DEFAULT_BYTE_BUDGET_BYTES,
);

/**
 * One reconcile attempt's work: retained operations it may load, and their
 * JSON bytes. The attempt reserves the bytes, times the live-copy factor,
 * from the process byte budget. A single key larger than a page still runs
 * alone.
 */
export const REPLICA_RECONCILE_PAGE = {
  operations: 2_000,
  bytes: 8 * 1024 * 1024,
} as const;

/** Default bound on the operations one batch (one registration) covers. */
export const REPLICA_BATCH_OPERATIONS = REPLICA_BATCH_OPERATION_LIMIT;
/**
 * Default bound on the estimated payload bytes of one batch. One operation
 * always fits, so a single larger blob makes a larger batch.
 */
export const REPLICA_BATCH_BYTES = REPLICA_BATCH_TARGET_BYTES;
/** The export's page limit. A batch reads several pages. */
const EXPORT_PAGE = 1000;
/** New slots one discover pass admits per writer scope. */
const DISCOVER_SLOTS = 256;
/** An unresolved AddData intent is retried only after this bounded window. */
export const REPLICA_REGISTRATION_INTENT_TIMEOUT_MS = 5 * 60 * 1000;
/** Per-writer recovery budget; only explicit owner acknowledgement resumes an exhausted writer. */
export const REPLICA_VERSION_SQUAT_ATTEMPTS = 8;
export const REPLICA_VERSION_SQUAT_WINDOW_MS = 60 * 60 * 1000;

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
export const REPLICA_ENGINE_MIGRATION = `
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
CREATE TABLE IF NOT EXISTS pdpp_transport_preparation_progress (
 batch TEXT PRIMARY KEY, statement TEXT NOT NULL, chunk_bytes INTEGER NOT NULL,
 next_index INTEGER NOT NULL, source_position INTEGER NOT NULL, source_offset INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS pdpp_transport_manifests_out (
 batch TEXT PRIMARY KEY, scope TEXT NOT NULL, version INTEGER NOT NULL,
 plaintext BLOB NOT NULL, encrypted BLOB NOT NULL, data_hash TEXT NOT NULL, metadata_hash TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'ready', ${WORK}, UNIQUE(scope,version));
CREATE TABLE IF NOT EXISTS pdpp_transport_registration_intents (
 scope TEXT NOT NULL, version INTEGER NOT NULL, owner TEXT NOT NULL,
 manifest_hash TEXT NOT NULL, request_id TEXT NOT NULL UNIQUE,
 created_at INTEGER NOT NULL, attempted_at INTEGER NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'unresolved',
 PRIMARY KEY(scope,version));
CREATE TABLE IF NOT EXISTS pdpp_transport_manifests_in (
 slot TEXT PRIMARY KEY, scope TEXT NOT NULL, version INTEGER NOT NULL, writer TEXT NOT NULL,
 manifest_json TEXT, data_hash TEXT, metadata_hash TEXT, batch TEXT, sequence INTEGER,
 state TEXT NOT NULL DEFAULT 'ready', evidence_checked INTEGER NOT NULL DEFAULT 0, ${WORK},
 UNIQUE(scope,version));
CREATE TABLE IF NOT EXISTS pdpp_transport_fragments_in (
 slot TEXT NOT NULL, position INTEGER NOT NULL, digest TEXT NOT NULL, bytes INTEGER NOT NULL,
 fragment_json TEXT, state TEXT NOT NULL DEFAULT 'ready', ${WORK}, PRIMARY KEY(slot,position));
CREATE TABLE IF NOT EXISTS pdpp_transport_fragment_parts (
 slot TEXT NOT NULL, position INTEGER NOT NULL, part INTEGER NOT NULL, json TEXT NOT NULL,
 PRIMARY KEY(slot,position,part));
CREATE TABLE IF NOT EXISTS pdpp_transport_discover_floor (scope TEXT PRIMARY KEY, version INTEGER NOT NULL);
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
CREATE TABLE IF NOT EXISTS pdpp_transport_reconcile_pass (
 id INTEGER PRIMARY KEY CHECK(id=1), dependency_json TEXT);
`;
const admissionMigration = `
CREATE TABLE IF NOT EXISTS pdpp_transport_version_squats (
 scope TEXT NOT NULL, version INTEGER NOT NULL, digest TEXT NOT NULL,
 detected_at INTEGER NOT NULL, batch TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('squatted','resigning','registering','committed')),
 PRIMARY KEY(scope,version));
CREATE TABLE IF NOT EXISTS pdpp_transport_registration_recovery (
 batch TEXT PRIMARY KEY, version INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('resigning','registering','committed','own_key_conflict','version_squat')));
CREATE TABLE IF NOT EXISTS pdpp_transport_repository (
 id INTEGER PRIMARY KEY CHECK(id=1), repository_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pdpp_transport_staged_objects (
 object_id TEXT PRIMARY KEY, admission_id TEXT NOT NULL, repository_id TEXT NOT NULL,
 owner TEXT NOT NULL, namespace_key TEXT NOT NULL, created_at INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('receiving','complete','verified','attached','aborted')),
 size_bytes INTEGER, sha256 TEXT, attached_at INTEGER);
CREATE INDEX IF NOT EXISTS pdpp_staged_objects_cleanup
 ON pdpp_transport_staged_objects(state,created_at,object_id);
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
  prepared: number;
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
  scope: string | null;
  version: number | null;
  outcome: string | null;
};
type ManifestOut = {
  batch: string;
  scope: string;
  version: number;
  plaintext: Uint8Array;
  encrypted: Uint8Array;
  data_hash: `0x${string}`;
  metadata_hash: `0x${string}`;
  state: string;
};
type RegistrationRecoveryState =
  | "resigning"
  | "registering"
  | "committed"
  | "own_key_conflict"
  | "version_squat";
type Slot = Work & {
  slot: string;
  scope: string;
  version: number;
  writer: string;
  data_hash: `0x${string}` | null;
  metadata_hash: `0x${string}` | null;
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
export const REPLICA_RESET_WORK =
  "outcome=NULL,reason=NULL,cause_json=NULL,dependency=NULL,error=NULL,attempts=0,wait_since=NULL,checked_block=NULL";
const RESET_WORK = REPLICA_RESET_WORK;
/** A slot's storage and evidence identity: the DPv2 `<scope>/<version>` key. */
const slotKey = (scope: string, version: number) => `${scope}/${version}`;
const encoder = new TextEncoder();
const blobsOf = (op: ReplicaOperation) =>
  op.kind === "blob-claim" ? [op.blob] : op.kind === "upsert" ? op.blobs : [];
const sameBytes = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((byte, index) => byte === b[index]);
/** `sha256:<hex>` of bytes. */
const sha256Digest = (bytes: Uint8Array) =>
  `sha256:${bytesToHex(sha256(bytes))}`;

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

// ------------------------------------------------------------------ host

/** The engine's writer identity (host contract §3.2). */
export interface ReplicaEngineIdentity {
  incarnation: number;
  seed: ReplicaWriterSeed;
  transportWriter: string;
  operationWriter: string;
}
export type ReplicaEngineIdentityState =
  | { tag: "ready"; identity: ReplicaEngineIdentity }
  | {
      tag: "waiting";
      reason: "server_not_registered" | "roster_unavailable";
    }
  | { tag: "refused"; reason: ReplicationRefusal };

/** A page of local operations, from the baseline or the tail. */
export interface ReplicaExportPage {
  operations: ReplicaOperation[];
  nextAfterSequence: number;
  hasMore: boolean;
}
export interface ReplicaExportPageOptions {
  afterSequence?: number;
  limit: number;
}

/**
 * The local operations a writer publishes. Storage reads and writes are
 * effects in the engine's transaction; blob bytes stream outside it.
 */
export interface ReplicaEngineExporter<C> {
  readBaselinePage(
    options: ReplicaExportPageOptions,
  ): ReplicaEffect<ReplicaExportPage, C>;
  readTailPage(
    options: ReplicaExportPageOptions,
  ): ReplicaEffect<ReplicaExportPage, C>;
  getBaselineCheckpoint(): ReplicaEffect<number, C>;
  acknowledgeBaselinePage(
    expected: number,
    next: number,
  ): ReplicaEffect<void, C>;
  /** A new writer re-captures current state as its baseline. */
  rebaseline(): ReplicaEffect<{ after: number } | undefined, C>;
  /**
   * Every binding this host retained for its own operations, beyond the
   * current expected set (Node: `pdpp_replica_declaration_history`). An
   * operation captured before a rebinding keeps its binding and still
   * publishes. A host without binding history returns none.
   */
  declarationHistory(): ReplicaEffect<
    readonly EnvelopeExpectation["declarations"][number][],
    C
  >;
  /**
   * The gateway confirmed the registration of a tail batch: every local
   * operation up to `next` (a tail cursor) is published. A host with an
   * outbox moves past them; called in order, possibly more than once.
   */
  acknowledgePublished(next: number): ReplicaEffect<void, C>;
  readPinnedBlobChunks(
    blobId: string,
  ): Iterable<Uint8Array> | AsyncIterable<Uint8Array>;
}

/** Outcome of promoting a retained copy (contract v3.1). */
export type ReplicaEngineCopyPromotion =
  | { kind: "promoted" }
  | { kind: "wait_predecessor" }
  | { kind: "terminal"; reason: string };

/** A copy of a batch as the import phase stages it. */
export interface ReplicaEngineStagedCopy {
  id: string;
  writer: string;
  batch: string;
  sequence: number;
  previous: Predecessor | null;
  envelopeDigest: string;
  envelope: ReplicaEnvelope;
  fragments: readonly { dataHash: string; metadataHash: string }[];
}

/**
 * Retained copies, finalized facts and canonical import (contract v3.1).
 * Every method is an effect in the engine's outcome transaction, except
 * `setPendingEnabled`.
 */
export interface ReplicaEngineReceiver<C> {
  setPendingEnabled(enabled: boolean): void;
  quarantine(input: {
    credential: unknown;
    id: string;
    reason: string;
  }): ReplicaEffect<void, C>;
  /**
   * Reconcile one page of retained history; `restart` begins a new pass.
   * `complete` is true when the pass has no queued work left.
   */
  reconcileStep(input: {
    credential: unknown;
    page: { operations: number; bytes: number };
    restart: boolean;
  }): ReplicaEffect<
    { plan: Pick<ReplicaMergePlan, "pending">; complete: boolean },
    C
  >;
  /** Whether an open pass still has queued pages. */
  reconcileQueued(): ReplicaEffect<boolean, C>;
  copies: {
    list(id: string): ReplicaEffect<readonly { copyKey: string }[], C>;
    decide(
      id: string,
      refetch: { attempts: number; budget: number },
    ): ReplicaEffect<CopyDecision, C>;
    apply(input: {
      credential: unknown;
      id: string;
      decision: CopyDecision;
    }): ReplicaEffect<void, C>;
    stage(input: {
      credential: unknown;
      copy: ReplicaEngineStagedCopy;
      /** Attached staging, by the key `ReplicaEngineStaging.attach` returned. */
      stagedBlobs: { blobId: string; key: string; sizeBytes: number }[];
      refetch: { attempts: number; budget: number };
    }): ReplicaEffect<unknown, C>;
    recordFact(input: {
      credential: unknown;
      id: string;
      scope: string;
      fragmentIndex: number;
      fact: FinalizedFact;
    }): ReplicaEffect<boolean, C>;
    promote(input: {
      credential: unknown;
      id: string;
      copyKey?: string;
    }): ReplicaEffect<ReplicaEngineCopyPromotion, C>;
  };
}

/** One staged object being written. */
export interface ReplicaEngineStagedWriter<H> {
  write(bytes: Uint8Array): MaybePromise<void>;
  complete(): MaybePromise<H>;
}
type ExpectedObject = { blobId: string; sha256: string; sizeBytes: number };
/**
 * Received blob bytes, staged outside any transaction and attached to the
 * import's outcome transaction (Node: `pdpp-replica-staging.ts`; PS-Lite:
 * native blob staging).
 */
export interface ReplicaEngineStaging<C, H = unknown> {
  begin(admission: Admission): ReplicaEngineStagedWriter<H>;
  verify(handle: H, expected: ExpectedObject): MaybePromise<void>;
  /** In the outcome transaction; returns the key the receiver copies from. */
  attach(handle: H, expected: ExpectedObject): ReplicaEffect<string, C>;
  abort(admission: Admission): MaybePromise<void>;
  reclaimAdmission(admission: Admission): MaybePromise<number>;
  cleanup(): MaybePromise<number>;
  cleanupAttachedTemporaryBytes(): MaybePromise<number>;
}

/** The replication door (core `door.ts`) as the host enforces it. */
export interface ReplicaEngineDoor {
  admitted(): boolean;
  beginStep(signal: AbortSignal | undefined): {
    signal: AbortSignal;
    close(): void;
  };
  assertStepOpen(signal: AbortSignal): void;
  assertTransactionOpen(signal: AbortSignal): void;
}

/** What a host gives the engine. `C` is its storage transaction context. */
export interface ReplicaEngineHost<C extends ReplicaEffectContext> {
  /**
   * Run one effect now. Node answers synchronously, outside a transaction
   * unless the effect opens one; PS-Lite runs it as one native transaction.
   */
  run<T>(effect: ReplicaEffect<T, C>): MaybePromise<T>;
  /** One immediate write transaction around `effect` (Node `BEGIN IMMEDIATE`). */
  immediate<T>(effect: ReplicaEffect<T, C>): ReplicaEffect<T, C>;
  /** One deferred transaction around `effect` (Node `BEGIN`). */
  transaction<T>(effect: ReplicaEffect<T, C>): ReplicaEffect<T, C>;
  /**
   * Run an attempt's commit inside the coordinator's checkpoint, whose
   * transaction is `context`, at the receiver's atomic boundary.
   */
  commit<T>(
    effect: ReplicaEffect<T, C>,
    context: unknown,
    signal: AbortSignal,
  ): MaybePromise<T>;
  /** Best-effort cleanup after an attempt; never awaited by the coordinator. */
  cleanup(effect: ReplicaEffect<unknown, C>): void;
  /** Writes the door's capture fence counts as captures, not bypasses. */
  captureWrites<T>(effect: ReplicaEffect<T, C>): ReplicaEffect<T, C>;
  door: ReplicaEngineDoor;
  /** A fresh UUID (Node: `node:crypto`, which seeded tests replace). */
  randomId(): string;
  /** One writer per database. */
  lock: {
    busy(): boolean;
    acquire(token: string): MaybePromise<void>;
    release(token: string): MaybePromise<void>;
  };
  identity: {
    current(): ReplicaEffect<ReplicaEngineIdentity | undefined, C>;
    enable(input: {
      owner: string;
      server: string;
      roster: ReplicaRosterPort;
      signal: AbortSignal;
    }): Promise<ReplicaEngineIdentityState>;
  };
  /** The coordinator's durable rotation, fenced by the writer lock. */
  coordinatorState(input: {
    owner: () => string | undefined;
    signal: () => AbortSignal | undefined;
    enabled: () => boolean;
  }): ReplicaCoordinatorStatePort | AsyncReplicaCoordinatorStatePort<C>;
  staging(input: {
    /** False for the host's own cleanup, never a test's injected store. */
    injected: boolean;
    repositoryId: string;
    owner: string;
    now: () => number;
    assertOpen: () => void;
  }): ReplicaEngineStaging<C>;
  /**
   * At step start, inside the transaction that drops staged fragments:
   * delete staged bytes that no staged-object row tracks.
   */
  sweepStages(): ReplicaEffect<void, C>;
  /** Reclaim redundant host-specific canonical copies within the byte budget. */
  compactCanonical?(bytes: number): ReplicaEffect<void, C>;
  exporter: ReplicaEngineExporter<C>;
  receiver: ReplicaEngineReceiver<C>;
  /**
   * Local connection bindings for the reconcile fingerprint: any JSON value
   * that changes when a mapping does.
   */
  bindings(): ReplicaEffect<unknown, C>;
}

/** Engine configuration that does not depend on the host. */
export interface ReplicaEngineConfig {
  enabled?: boolean;
  expected: () => EnvelopeExpectation;
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
  /** Items per writer per step. */
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
  /** Maximum age before a slot with authoritative absence may be resubmitted. */
  registrationIntentTimeoutMs?: number;
  /** Tests can share a smaller ledger to prove concurrent admission behavior. */
  resourceBudget?: ReplicaByteBudget;
  /** Test-scaled bounds; production uses the shared source-derived defaults. */
  resourceLimits?: Partial<ReplicaResourceLimits>;
  /** Test-scaled reconcile page; production uses `REPLICA_RECONCILE_PAGE`. */
  reconcilePage?: { operations: number; bytes: number };
}

/** What the engine gives a host: the worker's public operations. */
export interface ReplicaEngine {
  step(input?: {
    now?: number;
    budget?: ReplicaBudget;
    signal?: AbortSignal;
  }): Promise<ProgressReport>;
  retryVersionSquats(): MaybePromise<number>;
  cycle(): Promise<void>;
  readmitUnsupported(): MaybePromise<number>;
  readmitFragments(): MaybePromise<number>;
  onDependencyChanged(key: string): MaybePromise<number>;
  /** Settles when construction-time storage work is done (PS-Lite). */
  ready: MaybePromise<void>;
}

/** Internal experiment only. No bootstrap wiring; false by default. */
export function createReplicaEngine<C extends ReplicaEffectContext>(
  host: ReplicaEngineHost<C>,
  deps: ReplicaEngineConfig,
): ReplicaEngine {
  type Fx<T> = ReplicaEffect<T, C>;
  type Attempt = ReplicaAttempt<() => Fx<ReplicaPhaseOutcome | void>>;
  type Handler<I extends ReplicaWorkItem> = AsyncReplicaPhaseHandler<
    I,
    unknown,
    () => Fx<ReplicaPhaseOutcome | void>
  >;
  const { transport } = deps;
  const now = deps.now ?? Date.now;
  const resourceBudget = deps.resourceBudget ?? processReplicaByteBudget;
  const reconcilePage = deps.reconcilePage ?? REPLICA_RECONCILE_PAGE;
  const resourceLimits = replicaResourceLimits(deps.resourceLimits);
  const streamedLimits = {
    ...DEFAULT_REPLICA_STREAMED_LIMITS,
    maxOperations: resourceLimits.maxOperations,
    maxOperationBytes: resourceLimits.maxOperationBytes,
    maxSingleBlobBytes: resourceLimits.maxSingleBlobBytes,
    maxBlobTotalBytes: resourceLimits.maxBlobTotalBytes,
    maxPayloadBytes: resourceLimits.maxTotalBytes,
  };
  const roster = createCachedReplicaRoster(deps.authority.roster, { now });
  const server = deps.authority.signer.address.toLowerCase();
  const registrationIntentTimeout =
    deps.registrationIntentTimeoutMs ?? REPLICA_REGISTRATION_INTENT_TIMEOUT_MS;
  if (
    !Number.isSafeInteger(registrationIntentTimeout) ||
    registrationIntentTimeout < 1 ||
    registrationIntentTimeout > REPLICA_REGISTRATION_INTENT_TIMEOUT_MS
  )
    throw new RangeError("invalid registration intent timeout");
  const cap = deps.maxBlobBytes ?? REPLICA_MAX_BLOB_BYTES;
  if (!Number.isSafeInteger(cap) || cap < 1 || cap > REPLICA_MAX_BLOB_BYTES)
    throw new RangeError("invalid storage cap");
  const maxOperations = deps.maxBatchOperations ?? REPLICA_BATCH_OPERATIONS;
  const maxBytes = deps.maxBatchBytes ?? REPLICA_BATCH_BYTES;
  if (
    !Number.isSafeInteger(maxOperations) ||
    maxOperations < 1 ||
    maxOperations > resourceLimits.maxOperations ||
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 1
  )
    throw new RangeError("invalid replica batch bounds");
  const { door, exporter, receiver } = host;
  const enabled = () => deps.enabled === true;
  let activeStepSignal: AbortSignal | undefined;
  let coordinatorOwner: string | undefined;
  /** One effect now; Node runs it outside a transaction, as plain statements. */
  const query = <T>(effect: Fx<T>) => host.run(effect);
  /** One effect in its own immediate write transaction. */
  const atomic = <T>(effect: Fx<T>) => host.run(host.immediate(effect));
  /** One effect in its own deferred transaction. */
  const deferred = <T>(effect: Fx<T>) => host.run(host.transaction(effect));
  const payloadChunks = (key: string) => readReplicaPayload(query, key);
  function* state(): Fx<State> {
    return (yield* sql.get<State>(
      "SELECT * FROM pdpp_transport_state WHERE id=1",
    )) as State;
  }

  function* ensureAdmissionSchema(): Fx<void> {
    if (!enabled()) return;
    yield* sql.exec(admissionMigration);
    yield* sql.exec(REPLICA_COORDINATOR_SCHEMA);
    yield* sql.exec(REPLICA_PREPARATION_MIGRATION);
    // #504 refusals have not advanced the source cursor. Let the new per-op
    // classifier retain that exact pending page, instead of keeping its wedge.
    yield* sql.run(
      `UPDATE pdpp_transport_phase_state SET ${RESET_WORK},next_attempt=0
      WHERE phase='retain' AND outcome='unsupported' AND reason='resource_unsupported'`,
    );
    yield* sql.run(
      `UPDATE pdpp_transport_batches SET prepared=0,${RESET_WORK},next_attempt=0
      WHERE prepared=-2 AND NOT EXISTS (SELECT 1 FROM pdpp_transport_preparation p WHERE p.batch=pdpp_transport_batches.batch)`,
    );
    const columns = yield* sql.all<{ name: string }>(
      "PRAGMA table_info(pdpp_transport_manifests_in)",
    );
    if (!columns.some((column) => column.name === "resource_limits_version"))
      yield* sql.exec(
        "ALTER TABLE pdpp_transport_manifests_in ADD COLUMN resource_limits_version INTEGER",
      );
    // The tail cursor after a tail batch's operations; NULL for a baseline
    // batch and for batches retained before this column.
    if (
      !(yield* sql.all<{ name: string }>(
        "PRAGMA table_info(pdpp_transport_batches)",
      )).some((column) => column.name === "export_next")
    )
      yield* sql.exec(
        "ALTER TABLE pdpp_transport_batches ADD COLUMN export_next INTEGER",
      );
    yield* sql.run(
      "INSERT OR IGNORE INTO pdpp_transport_repository (id,repository_id) VALUES (1,?)",
      host.randomId(),
    );
    yield* sql.run(
      `UPDATE pdpp_transport_manifests_in
       SET ${RESET_WORK},resource_limits_version=NULL
       WHERE outcome='unsupported' AND reason='resource_unsupported'
         AND coalesce(resource_limits_version,0) < ?`,
      REPLICA_LIMITS_VERSION,
    );
    yield* sql.run(
      `UPDATE pdpp_transport_import_work SET ${RESET_WORK}
       WHERE outcome='unsupported' AND reason='resource_unsupported'
         AND EXISTS (
           SELECT 1 FROM pdpp_transport_manifests_in m
           WHERE m.writer=pdpp_transport_import_work.writer
             AND m.batch=pdpp_transport_import_work.batch
             AND m.outcome IS NULL
         )`,
    );
  }

  function* repositoryId(): Fx<string> {
    const row = yield* sql.get<{ repository_id: string }>(
      "SELECT repository_id FROM pdpp_transport_repository WHERE id=1",
    );
    if (!row) throw new Error("replication repository identity is missing");
    return row.repository_id;
  }

  function stagingStore(
    injected = true,
  ): MaybePromise<ReplicaEngineStaging<C>> {
    if (!enabled()) throw new Error("replication admission is disabled");
    return then(
      query(
        (function* () {
          yield* ensureAdmissionSchema();
          return yield* repositoryId();
        })(),
      ),
      (id) =>
        host.staging({
          injected,
          repositoryId: id,
          owner: deps.expected().owner,
          now,
          assertOpen: () => {
            const signal = activeStepSignal;
            if (signal) door.assertStepOpen(signal);
            else if (!door.admitted())
              throw new Error("replication door is closed");
          },
        }),
    );
  }

  /** Construction-time storage work: synchronous on Node, as before. */
  const ready = then(
    query(
      (function* () {
        if (
          yield* sql.get(
            `SELECT 1 FROM sqlite_master WHERE type='table' AND name IN (${PER_FRAGMENT_TABLES.map(() => "?").join(",")})`,
            ...PER_FRAGMENT_TABLES,
          )
        )
          throw new ReplicaCarrierMismatchError();
        yield* sql.exec(REPLICA_ENGINE_MIGRATION);
      })(),
    ),
    () => {
      receiver.setPendingEnabled(deps.enabled === true);
      if (!enabled()) return;
      return then(query(ensureAdmissionSchema()), () => {
        if (!door.admitted()) return;
        return then(stagingStore(false), (stages) =>
          then(stages.cleanup(), () =>
            then(stages.cleanupAttachedTemporaryBytes(), () => undefined),
          ),
        );
      });
    },
  );

  // Owner and writer of the running step, read under the writer lock. The
  // owner binding never changes, and only authority() changes the writer.
  let bound: { owner: string; writer: string } | undefined;
  const stepState = () => {
    if (!bound) throw new Error("replication state read outside a worker step");
    return bound;
  };
  const owner = () => stepState().owner;
  const writer = () => stepState().writer;

  /**
   * One validated authority context for every phase: the expected owner, the
   * persisted binding, the transport port's owner and the writer identity's
   * owner must agree. Checked before any phase runs, so a wrong-owner reopen
   * cannot encrypt, publish or import. False, with nothing written, when the
   * replication door closed since the step began.
   */
  function authority(identity: ReplicaEngineIdentity) {
    const expectedOwner = deps.expected().owner;
    return atomic(
      (function* (): Fx<false | { owner: string; writer: string }> {
        if (!door.admitted()) return false;
        yield* sql.run(
          "INSERT OR IGNORE INTO pdpp_transport_state (id,owner,writer) VALUES (1,?,?)",
          expectedOwner,
          identity.transportWriter,
        );
        const current = yield* state();
        if (
          current.owner !== expectedOwner ||
          identity.seed.owner !== expectedOwner.toLowerCase() ||
          (transport.owner !== undefined &&
            transport.owner.toLowerCase() !== expectedOwner.toLowerCase())
        )
          throw new ReplicaAuthorityError();
        if (current.writer !== identity.transportWriter)
          yield* startWriter(identity);
        return { owner: current.owner, writer: identity.transportWriter };
      })(),
    );
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
  function* startWriter(identity: ReplicaEngineIdentity): Fx<void> {
    const baseline = yield* host.captureWrites(exporter.rebaseline());
    yield* sql.run(
      "UPDATE pdpp_transport_state SET writer=?,sequence=0,previous_json=NULL,baseline_cursor=?,baseline_done=0,tail_cursor=NULL WHERE id=1",
      identity.transportWriter,
      baseline?.after ?? 0,
    );
    yield* sql.run(`UPDATE pdpp_transport_discover_floor SET version=min(version,(
      SELECT min(o.version)-1 FROM pdpp_transport_manifests_out o
      WHERE o.scope=pdpp_transport_discover_floor.scope))
      WHERE scope IN (SELECT scope FROM pdpp_transport_manifests_out)`);
    for (const table of [
      "pdpp_transport_batches",
      "pdpp_transport_staged_fragments",
      "pdpp_transport_fragments_out",
      "pdpp_transport_manifests_out",
      "pdpp_transport_preparation",
      "pdpp_transport_preparation_progress",
      "pdpp_transport_operation_outcomes",
      "pdpp_transport_upload_attempts",
      "pdpp_transport_registration_recovery",
    ])
      yield* sql.run(`DELETE FROM ${table}`);
  }
  /** This receiver's partition: its owner, chain and environment. */
  const partition = (): ReplicaPartition => ({
    owner: owner(),
    chainId: deps.authority.chainId,
    environment: deps.authority.environment,
  });
  /**
   * Receiver checks 2-5 (host contract §3.4) for the manifest registered at
   * `slot`: its statement must sign this manifest at this version, and the
   * writer it derives must be the one the slot's scope names.
   */
  const authorizeManifest = (
    manifest: ReplicaManifest,
    slot: { writer: string; version: number },
    signal: AbortSignal,
  ) =>
    authorizeReplicaBatch({
      authority: manifest.authority,
      facts: replicaManifestFacts(manifest, slot.version),
      transportWriter: slot.writer,
      receiver: partition(),
      roster: (address) => roster.server(address, { signal }),
    });
  const rosterWait = (address: string): ReplicaPhaseOutcome => ({
    tag: "wait",
    dependency: { kind: "roster", key: address },
  });
  /** An attempt with no durable effect besides its outcome. */
  const verdict = (outcome: ReplicaPhaseOutcome): Attempt => ({
    outcome,
  });
  /** An attempt whose effect commits only together with its own outcome. */
  const withPlan = (
    outcome: ReplicaPhaseOutcome,
    effect: () => Fx<unknown>,
  ): Attempt => ({
    outcome,
    plan: function* () {
      yield* effect();
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
      write: (
        outcome: ReplicaOutcome,
        work: ReplicaWorkState,
        item: I,
      ) => Fx<unknown>,
      isCurrent?: (item: I) => Fx<boolean>,
    ) =>
    (
      item: I,
      attempt: Attempt,
      settle: ReplicaSettle,
      context: unknown,
    ): MaybePromise<ReplicaOutcome> => {
      const signal = activeStepSignal;
      if (!signal) throw new Error("replication commit outside a worker step");
      // The coordinator's outer transaction has already raised the capture
      // guard. The host keeps the pre-transaction check for direct callers.
      if (!enabled()) throw new ReplicaProblemError("prepare_failed");
      return host.commit(
        (function* (): Fx<ReplicaOutcome> {
          door.assertTransactionOpen(signal);
          // A receipt belongs to the exact row state selected by `due`. If a
          // newer worker changed it while this attempt was in flight, discard
          // the older receipt and its plan before any projection can advance.
          if (isCurrent && !(yield* isCurrent(item)))
            return {
              tag: "retry",
              problem: "storage_failed",
              nextEligible: item.state.nextEligible,
            };
          const planned = attempt.plan ? yield* attempt.plan() : undefined;
          const settled = settle(planned ?? attempt.outcome);
          yield* write(settled.outcome, settled.state, item);
          return settled.outcome;
        })(),
        context,
        signal,
      );
    };
  /** Network calls stop at the attempt's deadline or the host's abort. */
  const call = <T>(signal: AbortSignal, start: () => Promise<T>) =>
    abortable(signal, async () => {
      if (!enabled()) throw new ReplicaProblemError("prepare_failed");
      door.assertStepOpen(signal);
      const value = await start();
      if (!enabled()) throw new ReplicaProblemError("prepare_failed");
      door.assertStepOpen(signal);
      return value;
    });
  /** The coordinator's eligibility policy over a work table's columns. */
  const due = (e: ReplicaEligibility) =>
    `${replicaEligibleAtSql(e)} <= ${e.now}`;
  /** Earliest eligibility among rows of `from` (a table plus WHERE clause). */
  function* earliestIn(
    e: ReplicaEligibility,
    from: string,
  ): Fx<number | undefined> {
    const row = yield* sql.get<{ next: number | null }>(
      `SELECT min(${replicaEligibleAtSql(e)}) AS next FROM ${from}`,
    );
    return row?.next ?? undefined;
  }
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
  type SingletonRow = Work & {
    fingerprint: string | null;
    outcome: string | null;
  };
  function* singleton(phase: ReplicaPhase): Fx<SingletonRow> {
    return (
      (yield* sql.get<SingletonRow>(
        "SELECT * FROM pdpp_transport_phase_state WHERE phase=?",
        phase,
      )) ?? {
        outcome: null,
        attempts: 0,
        next_attempt: 0,
        wait_since: null,
        checked_block: null,
        fingerprint: null,
      }
    );
  }
  function* settleSingleton(
    phase: ReplicaPhase,
    outcome: ReplicaOutcome,
    work: ReplicaWorkState,
    fingerprint?: string,
  ): Fx<void> {
    yield* sql.run(
      `INSERT INTO pdpp_transport_phase_state (phase) VALUES (?) ON CONFLICT(phase) DO NOTHING`,
      phase,
    );
    yield* sql.run(
      `UPDATE pdpp_transport_phase_state SET ${WORK_SET}${fingerprint === undefined ? "" : ",fingerprint=?"} WHERE phase=?`,
      ...(workValues(outcome, work) as (string | number | null)[]),
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
  function* singletonDeadline(
    phase: ReplicaPhase,
    e: ReplicaEligibility,
  ): Fx<number | undefined> {
    const row = yield* singleton(phase);
    return row.outcome === "retry" || row.outcome === "wait"
      ? singletonEligibleAt(row, e)
      : undefined;
  }
  /** The local export has operations not yet retained. One indexed probe. */
  function* tailPending(): Fx<boolean> {
    const s = yield* state();
    if (!s.baseline_done) return true;
    const page = yield* exporter.readTailPage({
      limit: 1,
      ...(s.tail_cursor === null ? {} : { afterSequence: s.tail_cursor }),
    });
    return page.operations.length > 0;
  }
  /**
   * Keep collecting source operations behind one unresolved publication. The
   * current manifest reports its typed wait. Only an explicit no-slot
   * Unsupported batch, a committed manifest, or a proven immutable-slot
   * conflict frees a claim. Every other or unknown batch state blocks.
   */
  const batchSettled = (b: string) => `(
    (${b}.prepared=-1 AND NOT EXISTS (SELECT 1 FROM pdpp_transport_preparation p WHERE p.batch=${b}.batch AND p.wait_json IS NOT NULL))
    OR (${b}.prepared=1 AND NOT EXISTS (SELECT 1 FROM pdpp_transport_preparation p WHERE p.batch=${b}.batch AND p.state<>'prepared')
      AND EXISTS (SELECT 1 FROM pdpp_transport_manifests_out m WHERE m.batch=${b}.batch
        AND (m.state='published' OR (m.state='quarantined' AND m.outcome='quarantine' AND m.reason='immutable_registration_conflict')))))`;
  function* batchInFlight(): Fx<boolean> {
    return !!(yield* sql.get(
      `SELECT 1 FROM pdpp_transport_batches b WHERE NOT ${batchSettled("b")} LIMIT 1`,
    ));
  }
  // A legacy queue can contain several retained batches. It follows the same
  // claim gate as new journal work, including unknown future predecessor states.
  const prepareUnblocked = `NOT EXISTS (SELECT 1 FROM pdpp_transport_batches predecessor
    WHERE predecessor.sequence<b.sequence AND NOT ${batchSettled("predecessor")})`;
  /**
   * Wire bytes an operation adds to a payload: its JSON and each new blob.
   * `shares` is true when it references a blob the payload already carries.
   */
  function operationBytes(op: ReplicaOperation, seen: Set<string>) {
    const snapshot = snapshotReplicaOperation(op);
    if (snapshot.encoding_failed) return { json: 0, blobs: 0, shares: false };
    const json = encoder.encode(snapshot.operation_json!).length + 1;
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
  function* readBatch(
    s: State,
  ): Fx<{ operations: ReplicaOperation[]; next: number; hasMore: boolean }> {
    const read = (afterSequence: number | undefined, limit: number) =>
      s.baseline_done
        ? exporter.readTailPage({
            limit,
            ...(afterSequence === undefined ? {} : { afterSequence }),
          })
        : exporter.readBaselinePage({
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
      let page = yield* read(
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
      if (full) page = yield* read(cursor, fit);
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
  const retain: Handler<Item<Work>> = {
    phase: "retain",
    due(e) {
      return query(
        (function* (): Fx<Item<Work>[]> {
          const row = yield* singleton("retain");
          const at = singletonEligibleAt(row, e);
          if (at === undefined || at > e.now) return [];
          // An idle tail costs one indexed probe and no budget unit.
          if ((yield* batchInFlight()) || !(yield* tailPending())) return [];
          return [
            {
              id: "retain",
              phase: "retain",
              writer: "",
              state: workState(row),
              row,
            },
          ];
        })(),
      );
    },
    async run() {
      const s = await query(state());
      const batch = host.randomId().replaceAll("-", "");
      let page: {
        operations: ReplicaOperation[];
        next: number;
        hasMore: boolean;
      };
      let digest = "",
        totalBytes = 0;
      try {
        page = await query(readBatch(s));
        if (page.operations.length) {
          const envelope: ReplicaEnvelope = {
            format: "vana-pdpp-replica",
            version: 1,
            owner: s.owner,
            batchId: batch,
            operations: page.operations.filter(
              (op) => !snapshotReplicaOperation(op).encoding_failed,
            ),
          };
          const payload = await query(replicaPayloadWriter(batch));
          const hash = sha256.create();
          for await (const bytes of encodeReplicaPayload(
            envelope,
            async function* (id) {
              yield* exporter.readPinnedBlobChunks(id);
            },
          )) {
            await deferred(payload.write(bytes));
            hash.update(bytes);
            totalBytes += bytes.length;
          }
          await query(payload.finish());
          digest = `sha256:${bytesToHex(hash.digest())}`;
        }
      } catch (error) {
        await query(deleteReplicaPayload(batch));
        throw new ReplicaProblemError("retain_failed", { cause: error });
      }
      // Queue + export cursor commit together with the phase outcome. They
      // acknowledge durable local responsibility, not publication.
      return withPlan(
        { tag: "progress", receipt: { phase: "retain", key: batch } },
        function* () {
          const current = yield* state();
          if (
            current.sequence !== s.sequence ||
            current.baseline_cursor !== s.baseline_cursor ||
            current.baseline_done !== s.baseline_done ||
            current.tail_cursor !== s.tail_cursor
          )
            throw new ReplicaProblemError("retain_failed");
          if (page.operations.length) {
            if (!(yield* verifyReplicaPayload(batch, digest, totalBytes)))
              throw new ReplicaProblemError("retain_failed");
            yield* sql.run(
              "INSERT INTO pdpp_transport_batches (batch,sequence,previous_json,collected_at,digest,total_bytes,export_next) VALUES (?,?,?,?,?,?,?)",
              batch,
              s.sequence + 1,
              s.previous_json,
              new Date(now()).toISOString(),
              digest,
              totalBytes,
              s.baseline_done ? page.next : null,
            );
            yield* retainPreparationOperations(batch, page.operations);
            yield* sql.run(
              "UPDATE pdpp_transport_state SET sequence=?, previous_json=? WHERE id=1",
              s.sequence + 1,
              canonicalJson({ batch, digest }),
            );
          }
          if (!s.baseline_done) {
            yield* exporter.acknowledgeBaselinePage(
              yield* exporter.getBaselineCheckpoint(),
              page.next,
            );
            yield* sql.run(
              "UPDATE pdpp_transport_state SET baseline_cursor=?, baseline_done=? WHERE id=1",
              page.next,
              page.hasMore ? 0 : 1,
            );
          } else
            yield* sql.run(
              "UPDATE pdpp_transport_state SET tail_cursor=? WHERE id=1",
              page.next,
            );
        },
      );
    },
    commit: commitIn((outcome, work) =>
      settleSingleton("retain", outcome, work),
    ),
    commitProblem: "retain_failed",
    earliest(e) {
      return query(
        (function* () {
          const deadline = yield* singletonDeadline("retain", e);
          if (deadline !== undefined) return deadline;
          return !(yield* batchInFlight()) && (yield* tailPending())
            ? e.now
            : undefined;
        })(),
      );
    },
  };

  /**
   * The exact retained operations, independent of later journal writes. Read
   * in pages that start below REPLICA_TEXT_PART_BYTES of operation JSON, so
   * one call returns that much plus at most one operation: a batch can hold
   * far more than one phone SQL call carries.
   */
  function* preparationRows(batch: string): Fx<RetainedPreparationOperation[]> {
    const rows: RetainedPreparationOperation[] = [];
    for (let after = -1; ;) {
      const page = yield* sql.all<RetainedPreparationOperation>(
        `SELECT position,operation_json,encoding_failed FROM (
          SELECT position,operation_json,encoding_failed,
            sum(length(CAST(coalesce(operation_json,'') AS BLOB))) OVER (ORDER BY position)
              - length(CAST(coalesce(operation_json,'') AS BLOB)) AS before
          FROM pdpp_transport_operation_outcomes
          WHERE batch=? AND outcome IS NULL AND position>?)
        WHERE before<? ORDER BY position`,
        batch,
        after,
        REPLICA_TEXT_PART_BYTES,
      );
      if (!page.length) return rows;
      rows.push(...page);
      after = page.at(-1)!.position;
    }
  }
  function preparationOf(batch: string) {
    return sql.get<ReplicaPreparation>(
      "SELECT * FROM pdpp_transport_preparation WHERE batch=?",
      batch,
    );
  }
  /** Released framing claims are history; every other reserved version counts. */
  function* nextPreparationVersion(): Fx<number> {
    // An owner call between steps (readmitUnsupported) reads the stored writer.
    const current = bound ? bound.writer : (yield* state()).writer;
    return (yield* sql.get<{ version: number }>(
      `SELECT coalesce(max(version),0)+1 AS version FROM (
      SELECT version FROM pdpp_transport_manifests_out WHERE scope=?
      UNION ALL SELECT version FROM pdpp_transport_preparation WHERE state<>'released')`,
      replicaScope(current),
    ))!.version;
  }
  function* claimPreparation(batch: string): Fx<void> {
    if (yield* preparationOf(batch)) return;
    const manifest = yield* sql.get<{ version: number }>(
      "SELECT version FROM pdpp_transport_manifests_out WHERE batch=?",
      batch,
    );
    yield* sql.run(
      "INSERT INTO pdpp_transport_preparation (batch,version,state) VALUES (?,?,'preparing')",
      batch,
      manifest?.version ?? (yield* nextPreparationVersion()),
    );
  }
  function* outstandingPreparationClaim(except: string): Fx<boolean> {
    return Boolean(
      yield* sql.get(
        `SELECT 1 FROM pdpp_transport_preparation p
      LEFT JOIN pdpp_transport_batches b ON b.batch=p.batch
      WHERE p.batch<>? AND p.state<>'released' AND (b.batch IS NULL OR NOT ${batchSettled("b")}) LIMIT 1`,
        except,
      ),
    );
  }
  /** Reserve readmission atomically; leave outstanding successors free to settle. */
  function* reserveReadmission(batch: string): Fx<boolean> {
    if (yield* outstandingPreparationClaim(batch)) return false;
    const version = yield* nextPreparationVersion();
    yield* sql.run(
      `INSERT INTO pdpp_transport_preparation (batch,version,state) VALUES (?,?,'preparing')
      ON CONFLICT(batch) DO UPDATE SET version=excluded.version,state='preparing',wait_json=NULL`,
      batch,
      version,
    );
    yield* sql.run(
      `UPDATE pdpp_transport_batches SET prepared=0,${RESET_WORK},next_attempt=0 WHERE batch=?`,
      batch,
    );
    return true;
  }
  function assertPreparationClaim(
    batch: string,
    version: number,
    signal: AbortSignal,
  ) {
    // Claim ownership and the final slot are checked together immediately before
    // signing. Signing itself is async and never holds a SQLite transaction open.
    return atomic(
      (function* () {
        door.assertStepOpen(signal);
        const current = yield* preparationOf(batch);
        const next = (yield* sql.get<{ version: number }>(
          "SELECT coalesce(max(version),0)+1 AS version FROM pdpp_transport_manifests_out WHERE scope=?",
          replicaScope(writer()),
        ))!.version;
        const claims = (yield* sql.get<{ n: number }>(
          "SELECT count(*) AS n FROM pdpp_transport_preparation WHERE version=? AND state<>'released'",
          version,
        ))!.n;
        if (
          current?.state !== "preparing" ||
          current.version !== version ||
          version !== next ||
          claims !== 1
        )
          throw new ReplicaProblemError("prepare_failed");
      })(),
    );
  }
  function* retainPreparationOperations(
    batch: string,
    operations: readonly ReplicaOperation[],
  ): Fx<void> {
    yield* claimPreparation(batch);
    for (const [position, op] of operations.entries()) {
      const snapshot = snapshotReplicaOperation(op);
      yield* sql.run(
        `INSERT INTO pdpp_transport_operation_outcomes
      (batch,position,operation_json,encoding_failed,writer_id,operation_id) VALUES (?,?,?,?,?,?)`,
        batch,
        position,
        snapshot.operation_json,
        snapshot.encoding_failed,
        typeof op.revision?.writerId === "string" ? op.revision.writerId : null,
        typeof op.revision?.operationId === "string"
          ? op.revision.operationId
          : null,
      );
    }
  }
  /** A durable pre-I/O fence also covers a PUT whose result is lost on crash. */
  function recordUploadAttempt(
    batch: string,
    kind: "fragment" | "manifest",
    position: number,
    signal: AbortSignal,
  ) {
    return atomic(
      (function* () {
        door.assertStepOpen(signal);
        const prep = yield* preparationOf(batch);
        if (prep && prep.state !== "prepared")
          throw new ReplicaProblemError("publish_failed");
        yield* sql.run(
          `INSERT OR IGNORE INTO pdpp_transport_upload_attempts (batch,kind,position,started_at) VALUES (?,?,?,?)`,
          batch,
          kind,
          position,
          now(),
        );
      })(),
    );
  }
  /** Never infer safety from prepared=0: legacy state and interrupted PUTs count. */
  function* preparationOwnEffects(batch: Batch, version: number): Fx<boolean> {
    return Boolean(
      yield* sql.get(
        `SELECT 1 FROM pdpp_transport_upload_attempts WHERE batch=?
      UNION ALL SELECT 1 FROM pdpp_transport_registration_intents WHERE scope=? AND version=?
      UNION ALL SELECT 1 FROM pdpp_transport_fragments_out WHERE batch=? AND (state<>'ready' OR attempts>0)
      UNION ALL SELECT 1 FROM pdpp_transport_manifests_out WHERE batch=? AND (state<>'ready' OR attempts>0) LIMIT 1`,
        batch.batch,
        replicaScope(writer()),
        version,
        batch.batch,
        batch.batch,
      ),
    );
  }
  function* preparationHasExternalEffects(
    batch: Batch,
    version: number,
  ): Fx<boolean> {
    if (yield* preparationOwnEffects(batch, version)) return true;
    return Boolean(
      yield* sql.get(
        `
      SELECT 1 FROM pdpp_transport_manifests_out m JOIN pdpp_transport_batches b ON b.batch=m.batch
      WHERE b.sequence>? LIMIT 1`,
        batch.sequence,
      ),
    );
  }
  /** Release is legal only at the tail of both durable claim orders. */
  function* preparationIsTail(batch: Batch, version: number): Fx<boolean> {
    if ((yield* state()).sequence !== batch.sequence) return false;
    return !(yield* sql.get(
      `
      SELECT 1 FROM pdpp_transport_batches WHERE sequence>?
      UNION ALL SELECT 1 FROM pdpp_transport_preparation WHERE batch<>? AND state<>'released' AND version>=?
      UNION ALL SELECT 1 FROM pdpp_transport_manifests_out WHERE scope=? AND batch<>? AND version>=? LIMIT 1`,
      batch.sequence,
      batch.batch,
      version,
      replicaScope(writer()),
      batch.batch,
      version,
    ));
  }
  const preparationWait = (
    batch: string,
    reason: "unknown" | "upload_started" | "all_ops_unsupported",
  ): Extract<ReplicaPhaseOutcome, { tag: "wait" }> => ({
    tag: "wait",
    dependency: { kind: "preparation", key: batch, reason },
  });
  function* blockPreparation(
    batch: string,
    reason: "upload_started" | "all_ops_unsupported" = "upload_started",
  ): Fx<ReplicaPhaseOutcome> {
    const wait = preparationWait(batch, reason);
    yield* sql.run(
      "UPDATE pdpp_transport_preparation SET state='prep_failed_permanent',wait_json=? WHERE batch=?",
      canonicalJson(wait),
      batch,
    );
    return wait;
  }
  /** Mark first, rebuild in a later durable transition; replay cannot duplicate an outcome. */
  function permanentPreparation(
    batch: Batch,
    admission: Extract<
      ReplicaPhaseOutcome,
      { tag: "unsupported" }
    >["admission"],
    positions: readonly number[],
  ): Attempt {
    return {
      outcome: { tag: "unsupported", admission },
      plan: function* () {
        const preparation = (yield* preparationOf(batch.batch))!;
        if (yield* preparationOwnEffects(batch, preparation.version))
          return yield* blockPreparation(batch.batch);
        const refused = new Set(positions);
        const remaining = (yield* preparationRows(batch.batch)).filter(
          (row) => !refused.has(row.position),
        );
        if (
          remaining.length &&
          (yield* preparationHasExternalEffects(batch, preparation.version))
        )
          return yield* blockPreparation(batch.batch);
        if (!positions.length) throw new ReplicaProblemError("prepare_failed");
        for (const position of positions)
          yield* sql.run(
            `UPDATE pdpp_transport_operation_outcomes
          SET outcome='unsupported',reason=?,admission_json=? WHERE batch=? AND position=? AND outcome IS NULL`,
            admission.reason,
            canonicalJson(admission),
            batch.batch,
            position,
          );
        yield* sql.run(
          "UPDATE pdpp_transport_batches SET prepared=-2,admission_json=? WHERE batch=?",
          canonicalJson(admission),
          batch.batch,
        );
        if (
          !remaining.length &&
          !(yield* preparationIsTail(batch, preparation.version))
        )
          return yield* blockPreparation(batch.batch, "all_ops_unsupported");
        yield* sql.run(
          "UPDATE pdpp_transport_preparation SET state='prep_failed_permanent',wait_json=NULL WHERE batch=?",
          batch.batch,
        );
      },
    };
  }
  /** Stream a new payload under a temporary key; the rebuild publishes it atomically. */
  async function rebuiltPayload(batch: string, operations: ReplicaOperation[]) {
    const key = `rebuild:${host.randomId()}`;
    const payload = await query(replicaPayloadWriter(key));
    const hash = sha256.create();
    let totalBytes = 0;
    try {
      for await (const bytes of encodeReplicaPayload(
        {
          format: "vana-pdpp-replica",
          version: 1,
          owner: owner(),
          batchId: batch,
          operations,
        },
        async function* (id) {
          yield* exporter.readPinnedBlobChunks(id);
        },
      )) {
        if (!enabled()) throw new ReplicaProblemError("prepare_failed");
        door.assertStepOpen(activeStepSignal!);
        await query(payload.write(bytes));
        hash.update(bytes);
        totalBytes += bytes.length;
      }
      await query(payload.finish());
      return {
        key,
        digest: `sha256:${bytesToHex(hash.digest())}`,
        totalBytes,
      };
    } catch (error) {
      await query(deleteReplicaPayload(key));
      throw error;
    }
  }
  function unknownPreparation(batch: Batch, error: unknown) {
    return withPlan(retryFromError(error, "prepare_failed"), function* () {
      yield* sql.run(
        "UPDATE pdpp_transport_preparation SET state='prep_failed_unknown',wait_json=? WHERE batch=?",
        canonicalJson(preparationWait(batch.batch, "unknown")),
        batch.batch,
      );
    });
  }
  /** One read-only trial preserves unknown-error classification. Every crossing
   * is then attributed by incremental payload bytes and the codec's exact size.
   */
  async function aggregatePreparationFailures(
    batch: Batch,
    error: ReplicaResourceLimitError,
    signal: AbortSignal,
    chunkBytes: number,
  ) {
    const rows = await query(preparationRows(batch.batch));
    const envelope: ReplicaEnvelope = {
      format: "vana-pdpp-replica",
      version: 1,
      owner: owner(),
      batchId: batch.batch,
      operations: rows.map(
        (row) => JSON.parse(row.operation_json!) as ReplicaOperation,
      ),
    };
    if (error.limit === "aggregate_ciphertext_bytes") {
      // An unknown crypto failure in a trial remains Retry; no outcome
      // is persisted until the whole attribution pass completes.
      const bytes = () =>
        encodeReplicaPayload(
          { ...envelope, operations: [] },
          async function* () {},
        );
      const empty = await hashReplicaBytes(bytes);
      let measured = 0;
      try {
        for await (const fragment of fragmentReplicaStream({
          owner: owner(),
          writer: writer(),
          batch: batch.batch,
          sequence: batch.sequence,
          previous: batch.previous_json
            ? (JSON.parse(batch.previous_json) as Predecessor)
            : null,
          collectedAt: batch.collected_at,
          ...empty,
          bytes,
          encrypt: (scope, plaintext) =>
            call(signal, () => transport.encrypt(scope, plaintext)),
          maxBlobBytes: cap,
          targetChunkBytes: chunkBytes,
        }))
          measured += fragment.encrypted.length;
      } catch (trialError) {
        if (
          trialError instanceof ReplicaResourceLimitError &&
          trialError.limit === error.limit
        )
          return rows.map((row) => row.position);
        throw trialError;
      }
      if (measured > error.maximum) return rows.map((row) => row.position);
      if (!transport.encryptedByteLength)
        throw new ReplicaProblemError("prepare_failed");
    }
    const sizes = new Map<number, number>();
    const exceeds = (payloadBytes: number) => {
      if (error.limit === "total_bytes") return payloadBytes > error.maximum;
      let ciphertext = sizes.get(payloadBytes);
      if (ciphertext === undefined) {
        ciphertext = replicaStreamCiphertextByteLength(
          {
            owner: owner(),
            writer: writer(),
            batch: batch.batch,
            sequence: batch.sequence,
            previous: batch.previous_json
              ? (JSON.parse(batch.previous_json) as Predecessor)
              : null,
            collectedAt: batch.collected_at,
            digest: batch.digest,
            totalBytes: payloadBytes,
            targetChunkBytes: chunkBytes,
          },
          transport.encryptedByteLength!,
        );
        sizes.set(payloadBytes, ciphertext);
      }
      return ciphertext > error.maximum;
    };
    return replicaPayloadOperationCrossings(envelope, exceeds).map(
      (index) => rows[index]!.position,
    );
  }
  async function failedPreparation(
    batch: Batch,
    error: unknown,
    signal: AbortSignal,
    chunkBytes = deps.targetChunkBytes ?? REPLICA_DEFAULT_FRAGMENT_BYTES,
    attributedPositions?: readonly number[],
  ): Promise<Attempt> {
    const failure = classifyReplicaPreparationError(error);
    const prep = await query(preparationOf(batch.batch));
    if (failure.kind !== "permanent" || !prep)
      return unknownPreparation(batch, error);
    // Refuse before probing or marking ops whenever durable I/O evidence exists.
    if (await query(preparationOwnEffects(batch, prep.version)))
      return permanentPreparation(batch, failure.admission, []);
    try {
      let positions = failure.positions ?? attributedPositions;
      if (
        !positions &&
        error instanceof ReplicaResourceLimitError &&
        (error.limit === "aggregate_ciphertext_bytes" ||
          error.limit === "total_bytes")
      )
        positions = await aggregatePreparationFailures(
          batch,
          error,
          signal,
          chunkBytes,
        );
      if (positions?.length)
        return permanentPreparation(batch, failure.admission, positions);
    } catch (trialError) {
      return unknownPreparation(batch, trialError);
    }
    // A typed error without attributable operations cannot justify dropping data.
    return unknownPreparation(batch, error);
  }

  async function rebuildPreparation(
    batch: Batch,
    prep: ReplicaPreparation,
  ): Promise<Attempt> {
    const progress: ReplicaPhaseOutcome = {
      tag: "progress",
      receipt: { phase: "prepare", key: batch.batch },
    };
    const rows = await query(preparationRows(batch.batch));
    if (prep.state === "prep_failed_permanent" && rows.length)
      return {
        outcome: progress,
        plan: function* () {
          if (yield* preparationHasExternalEffects(batch, prep.version))
            return yield* blockPreparation(batch.batch);
          yield* sql.run(
            "UPDATE pdpp_transport_preparation SET state='rebuilding' WHERE batch=?",
            batch.batch,
          );
        },
      };
    if (!rows.length)
      return {
        outcome: progress,
        plan: function* () {
          if (yield* preparationOwnEffects(batch, prep.version))
            return yield* blockPreparation(batch.batch);
          if (!(yield* preparationIsTail(batch, prep.version)))
            return yield* blockPreparation(batch.batch, "all_ops_unsupported");
          // The unused tail alone may give back its sequence and wire version.
          yield* discardPreparedFragments(batch.batch);
          yield* releaseClaim(batch.batch);
          yield* deleteReplicaPayload(batch.batch);
          yield* sql.run(
            "DELETE FROM pdpp_transport_batches WHERE batch=?",
            batch.batch,
          );
          yield* sql.run(
            "UPDATE pdpp_transport_state SET sequence=?,previous_json=? WHERE id=1",
            batch.sequence - 1,
            batch.previous_json,
          );
          yield* sql.run(
            "UPDATE pdpp_transport_preparation SET state='released',wait_json=NULL WHERE batch=?",
            batch.batch,
          );
        },
      };
    const payload = await rebuiltPayload(
      batch.batch,
      rows.map((row) => JSON.parse(row.operation_json!) as ReplicaOperation),
    );
    return {
      outcome: progress,
      plan: function* () {
        if (yield* preparationHasExternalEffects(batch, prep.version))
          return yield* blockPreparation(batch.batch);
        yield* discardPreparedFragments(batch.batch);
        yield* releaseClaim(batch.batch);
        yield* deleteReplicaPayload(batch.batch);
        for (const table of ["pdpp_binary_chunks", "pdpp_binary_manifests"])
          yield* sql.run(
            `UPDATE ${table} SET blob_id=? WHERE namespace='payload' AND blob_id=?`,
            batch.batch,
            payload.key,
          );
        yield* sql.run(
          `UPDATE pdpp_transport_batches SET prepared=0,digest=?,total_bytes=?,admission_json=NULL WHERE batch=?`,
          payload.digest,
          payload.totalBytes,
          batch.batch,
        );
        const previous = canonicalJson({
          batch: batch.batch,
          digest: payload.digest,
        });
        yield* sql.run(
          "UPDATE pdpp_transport_state SET previous_json=? WHERE id=1 AND json_extract(previous_json,'$.batch')=?",
          previous,
          batch.batch,
        );
        yield* sql.run(
          "UPDATE pdpp_transport_batches SET previous_json=? WHERE json_extract(previous_json,'$.batch')=?",
          previous,
          batch.batch,
        );
        yield* sql.run(
          "UPDATE pdpp_transport_preparation SET state='preparing',wait_json=NULL WHERE batch=?",
          batch.batch,
        );
      },
      release: () => host.cleanup(deleteReplicaPayload(payload.key)),
    };
  }

  // -------------------------------------------------------------- prepare
  /*
   * Preparation is resumable (host contract §6.1 items 1 and 3). One attempt
   * frames and encrypts one fragment and commits it with a cursor, so a batch
   * of any size is admitted one fragment at a time and a restart resumes after
   * the last committed fragment. The last attempt checks the whole payload,
   * signs the manifest and marks the batch prepared. Fragments wait in
   * pdpp_transport_fragments_out, which publish ignores until the preparation
   * is 'prepared'. The cursor names the statement it framed: a rebuilt
   * payload or any other statement starts again from fragment 0.
   */
  type PreparationProgress = {
    statement: string;
    chunk_bytes: number;
    next_index: number;
    /** The payload chunk row and the offset in it where the next fragment starts. */
    source_position: number;
    source_offset: number;
  };
  const PROGRESS_COLUMNS =
    "statement,chunk_bytes,next_index,source_position,source_offset";
  function preparationStatement(batch: Batch) {
    return {
      owner: owner(),
      writer: writer(),
      batch: batch.batch,
      sequence: batch.sequence,
      previous: batch.previous_json
        ? (JSON.parse(batch.previous_json) as Predecessor)
        : null,
      collectedAt: batch.collected_at,
      digest: batch.digest,
      totalBytes: batch.total_bytes,
    };
  }
  /** The stored cursor when it names this statement, else fragment 0. */
  function progressFor(
    batch: Batch,
    row: PreparationProgress | undefined,
  ): PreparationProgress {
    const statement = canonicalJson(preparationStatement(batch));
    return row?.statement === statement
      ? row
      : {
          statement,
          chunk_bytes: deps.targetChunkBytes ?? REPLICA_DEFAULT_FRAGMENT_BYTES,
          next_index: 0,
          source_position: 0,
          source_offset: 0,
        };
  }
  function* preparationProgress(batch: Batch): Fx<PreparationProgress> {
    return progressFor(
      batch,
      yield* sql.get<PreparationProgress>(
        `SELECT ${PROGRESS_COLUMNS} FROM pdpp_transport_preparation_progress WHERE batch=?`,
        batch.batch,
      ),
    );
  }
  function* savePreparationProgress(
    batch: string,
    next: PreparationProgress,
  ): Fx<void> {
    yield* sql.run(
      `INSERT INTO pdpp_transport_preparation_progress (batch,${PROGRESS_COLUMNS}) VALUES (?,?,?,?,?,?)
      ON CONFLICT(batch) DO UPDATE SET statement=excluded.statement,chunk_bytes=excluded.chunk_bytes,next_index=excluded.next_index,source_position=excluded.source_position,source_offset=excluded.source_offset`,
      batch,
      next.statement,
      next.chunk_bytes,
      next.next_index,
      next.source_position,
      next.source_offset,
    );
  }
  /**
   * In a plan: false when the batch is no longer unprepared (nothing to do).
   * Throws when its cursor moved since this attempt read it, so a stale
   * attempt never commits a second fragment at one position.
   */
  function* preparationCurrent(
    batch: Batch,
    started: PreparationProgress,
  ): Fx<boolean> {
    const row = yield* sql.get<Batch>(
      "SELECT * FROM pdpp_transport_batches WHERE batch=?",
      batch.batch,
    );
    if (!row || row.prepared !== 0) return false;
    const current = yield* preparationProgress(row);
    if (
      current.statement !== started.statement ||
      current.chunk_bytes !== started.chunk_bytes ||
      current.next_index !== started.next_index ||
      current.source_position !== started.source_position ||
      current.source_offset !== started.source_offset
    )
      throw new ReplicaProblemError("prepare_failed");
    return true;
  }
  /** Drop an unpublished batch's fragments and its cursor. */
  function* discardPreparedFragments(batch: string): Fx<void> {
    yield* sql.run(
      "DELETE FROM pdpp_transport_fragments_out WHERE batch=?",
      batch,
    );
    yield* sql.run(
      "DELETE FROM pdpp_transport_preparation_progress WHERE batch=?",
      batch,
    );
  }
  /**
   * Admission of a batch's next prepare attempt: the base64 content of its
   * next fragment, and nothing for the final attempt, whose payload check
   * streams. A rebuild streams the payload like retain and is not charged.
   */
  function preparationAdmission(
    batch: Batch,
    row: PreparationProgress | undefined,
  ) {
    const progress = progressFor(batch, row);
    const offset = progress.next_index * progress.chunk_bytes;
    // A failed attempt leaves the cursor, so the batch waits for the next step.
    const part = `${progress.chunk_bytes}:${progress.next_index}`;
    if (batch.prepared !== 0) return { part };
    return {
      part,
      bytes:
        offset >= batch.total_bytes
          ? 0
          : 4 *
            Math.ceil(
              Math.min(progress.chunk_bytes, batch.total_bytes - offset) / 3,
            ),
    };
  }
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
  const prepare: Handler<Item<Batch>> = {
    phase: "prepare",
    due(e, limit) {
      return then(
        query(
          sql.all<Batch>(
            `SELECT b.* FROM pdpp_transport_batches b WHERE ${prepareUnblocked} AND
              ((b.prepared=0 AND ${due(e)}) OR (b.prepared=-2 AND EXISTS (
                SELECT 1 FROM pdpp_transport_preparation p WHERE p.batch=b.batch AND
                  ((p.state IN ('prep_failed_permanent','rebuilding') AND p.wait_json IS NULL)
                  OR (p.state='prep_failed_unknown' AND ${due(e)}))))) ORDER BY b.next_attempt,b.sequence LIMIT ?`,
            limit.total,
          ),
        ),
        (rows) =>
          then(
            query(
              (function* () {
                const progress = new Map<string, PreparationProgress>();
                for (const row of rows) {
                  const found = yield* sql.get<PreparationProgress>(
                    `SELECT ${PROGRESS_COLUMNS} FROM pdpp_transport_preparation_progress WHERE batch=?`,
                    row.batch,
                  );
                  if (found) progress.set(row.batch, found);
                }
                return progress;
              })(),
            ),
            (progress) =>
              rows.map((row): Item<Batch> => ({
                id: row.batch,
                phase: "prepare",
                writer: "",
                state: workState(row),
                ...preparationAdmission(row, progress.get(row.batch)),
                row,
              })),
          ),
      );
    },
    async run(item, signal) {
      const batch = item.row;
      try {
        let preparation = await query(preparationOf(batch.batch));
        // Upgrade a legacy retained batch from its frozen payload, never from the journal.
        if (
          !preparation ||
          !(await query(
            sql.get(
              "SELECT 1 FROM pdpp_transport_operation_outcomes WHERE batch=? LIMIT 1",
              batch.batch,
            ),
          ))
        ) {
          await atomic(
            (function* () {
              door.assertStepOpen(signal);
              yield* claimPreparation(batch.batch);
            })(),
          );
          const payload = await inspectReplicaPayload(
            () => payloadChunks(batch.batch),
            undefined,
          );
          await atomic(
            (function* () {
              door.assertStepOpen(signal);
              yield* retainPreparationOperations(
                batch.batch,
                payload.envelope.operations,
              );
            })(),
          );
          preparation = (await query(preparationOf(batch.batch)))!;
        }
        if (preparation.state === "released") {
          // A pre-upgrade readmission may still be queued without a reservation.
          // Defer it rather than blocking the successor that already owns a slot.
          const reserved = await atomic(
            (function* () {
              door.assertStepOpen(signal);
              return yield* reserveReadmission(batch.batch);
            })(),
          );
          if (!reserved) {
            const saved = (await query(
              sql.get<{ admission_json: string }>(
                "SELECT admission_json FROM pdpp_transport_batches WHERE batch=?",
                batch.batch,
              ),
            ))!;
            const admission = {
              reason: "replica_framing_unsupported" as const,
              ...(JSON.parse(saved.admission_json) as {
                actual: number;
                limit: number;
                capability: string;
              }),
            };
            return withPlan({ tag: "unsupported", admission }, () =>
              sql.run(
                "UPDATE pdpp_transport_batches SET prepared=-1 WHERE batch=?",
                batch.batch,
              ),
            );
          }
          preparation = (await query(preparationOf(batch.batch)))!;
        }
        if (preparation.wait_json) {
          if (preparation.state === "prep_failed_permanent")
            return verdict(
              JSON.parse(preparation.wait_json) as ReplicaPhaseOutcome,
            );
        }
        if (
          preparation.state === "prep_failed_unknown" &&
          batch.prepared === -2
        ) {
          await atomic(
            (function* () {
              door.assertStepOpen(signal);
              yield* sql.run(
                "UPDATE pdpp_transport_preparation SET state='rebuilding',wait_json=NULL WHERE batch=?",
                batch.batch,
              );
            })(),
          );
          preparation = {
            ...preparation,
            state: "rebuilding",
            wait_json: null,
          };
        }
        if (
          preparation.state === "prep_failed_permanent" ||
          preparation.state === "rebuilding"
        )
          return await rebuildPreparation(batch, preparation);
        await atomic(
          (function* () {
            door.assertStepOpen(signal);
            yield* sql.run(
              "UPDATE pdpp_transport_preparation SET state='preparing',wait_json=NULL WHERE batch=?",
              batch.batch,
            );
          })(),
        );
        const rows = await query(preparationRows(batch.batch));
        const own = rows.map(
          (row) => JSON.parse(row.operation_json!) as ReplicaOperation,
        );
        const failures = preparationOperationFailures(rows, resourceLimits);
        if (failures)
          return failedPreparation(
            batch,
            failures.error,
            signal,
            undefined,
            failures.positions,
          );
        if (batch.total_bytes > resourceLimits.maxTotalBytes)
          return failedPreparation(
            batch,
            new ReplicaResourceLimitError(
              "total_bytes",
              batch.total_bytes,
              resourceLimits.maxTotalBytes,
            ),
            signal,
          );
        decodeReplicaEnvelope(
          canonicalJson({
            format: "vana-pdpp-replica",
            version: 1,
            owner: owner(),
            batchId: batch.batch,
            operations: own,
          }),
          ownBindings(own, await query(exporter.declarationHistory())),
        );
        const identity = await query(host.identity.current());
        const statement = preparationStatement(batch);
        const encrypt = (scope: string, bytes: Uint8Array) =>
          call(signal, () => transport.encrypt(scope, bytes));
        const progress = await query(preparationProgress(batch));
        const receipt: ReplicaPhaseOutcome = {
          tag: "progress",
          receipt: { phase: "prepare", key: batch.batch },
        };
        const unsupportedPlan = (error: ReplicaFramingUnsupported) => {
          const admission = unsupported(error);
          return withPlan({ tag: "unsupported", admission }, function* () {
            yield* sql.run(
              "UPDATE pdpp_transport_preparation SET state='released',wait_json=NULL WHERE batch=?",
              batch.batch,
            );
            yield* sql.run(
              "UPDATE pdpp_transport_batches SET prepared=-1,admission_json=? WHERE batch=?",
              canonicalJson({
                actual: admission.actual,
                limit: admission.limit,
                capability: admission.capability,
              }),
              batch.batch,
            );
            yield* discardPreparedFragments(batch.batch);
          });
        };
        try {
          // Batches belong to the current writer; startWriter drops older ones.
          if (identity?.transportWriter !== statement.writer)
            throw new ReplicaProblemError("prepare_failed");
          const count = Math.ceil(batch.total_bytes / progress.chunk_bytes);
          if (count > REPLICA_MAX_FRAGMENTS)
            return unsupportedPlan(
              new ReplicaFramingUnsupported(
                count,
                REPLICA_MAX_FRAGMENTS,
                "fragment_count",
              ),
            );
          if (progress.next_index < count) {
            // One fragment: read its window, frame, encrypt, commit with the cursor.
            const index = progress.next_index;
            const offset = index * progress.chunk_bytes;
            const window = await query(
              readReplicaPayloadWindow(
                batch.batch,
                {
                  position: progress.source_position,
                  offset: progress.source_offset,
                },
                Math.min(progress.chunk_bytes, batch.total_bytes - offset),
              ),
            );
            let part: Awaited<ReturnType<typeof prepareReplicaFragment>>;
            let framing: ReplicaFramingUnsupported | undefined;
            try {
              part = await prepareReplicaFragment({
                ...statement,
                count,
                index,
                offset,
                chunk: window.bytes,
                encrypt,
              });
              if (part.encrypted.length > cap)
                framing = new ReplicaFramingUnsupported(
                  part.encrypted.length,
                  cap,
                );
            } catch (error) {
              if (!(error instanceof ReplicaFramingUnsupported)) throw error;
              framing = error;
            }
            if (framing) {
              // Resource Unsupported blocks this writer through its durable
              // rebuild; it never quarantines. Framing Unsupported may narrow
              // the chunk size; the batch then starts again from fragment 0.
              // If framing remains impossible, it settles only this batch
              // without claiming a version. Successors may publish but peers
              // wait for the missing predecessor until readmitUnsupported()
              // under a new capability. Other errors retry.
              if (
                framing.dimension === "fragment_bytes" &&
                progress.chunk_bytes > 1
              )
                return withPlan(receipt, function* () {
                  if (!(yield* preparationCurrent(batch, progress))) return;
                  yield* discardPreparedFragments(batch.batch);
                  yield* savePreparationProgress(batch.batch, {
                    statement: progress.statement,
                    chunk_bytes: Math.max(
                      1,
                      Math.floor(progress.chunk_bytes / 2),
                    ),
                    next_index: 0,
                    source_position: 0,
                    source_offset: 0,
                  });
                });
              return unsupportedPlan(framing);
            }
            const prepared = part!;
            if (
              transport.encryptedByteLength &&
              transport.encryptedByteLength(prepared.plaintext.length) !==
                prepared.encrypted.length
            )
              throw new ReplicaProblemError("prepare_failed");
            // One fragment's receipt; the batch's own comes with its manifest.
            const fragmentReceipt: ReplicaPhaseOutcome = {
              tag: "progress",
              receipt: { phase: "prepare", key: `${batch.batch}:${index}` },
            };
            return withPlan(fragmentReceipt, function* () {
              // Randomized ciphertext: only the first committed fragment at
              // this cursor can go on wire.
              if (!(yield* preparationCurrent(batch, progress))) return;
              if (index === 0) yield* discardPreparedFragments(batch.batch);
              yield* sql.run(
                "INSERT INTO pdpp_transport_fragments_out (batch,position,digest,encrypted) VALUES (?,?,?,?)",
                batch.batch,
                index,
                prepared.digest,
                prepared.encrypted,
              );
              yield* savePreparationProgress(batch.batch, {
                statement: progress.statement,
                chunk_bytes: progress.chunk_bytes,
                next_index: index + 1,
                source_position: window.next.position,
                source_offset: window.next.offset,
              });
            });
          }
          // Every fragment is committed. The single-run stream checked the
          // whole-batch digest at EOF; check that the retained payload is
          // still the one the fragments were read from, one chunk per call.
          const retained = await hashReplicaBytes(() =>
            payloadChunks(batch.batch),
          );
          if (
            retained.digest !== batch.digest ||
            retained.totalBytes !== batch.total_bytes
          )
            throw new Error("corrupt replica batch");
          const entries = await query(
            sql.all<ManifestEntry>(
              "SELECT digest,length(encrypted) AS bytes FROM pdpp_transport_fragments_out WHERE batch=? ORDER BY position",
              batch.batch,
            ),
          );
          // A committed fragment went missing: start the batch again.
          if (entries.length !== count)
            return withPlan(
              { tag: "retry", problem: "prepare_failed" },
              function* () {
                if (yield* preparationCurrent(batch, progress))
                  yield* discardPreparedFragments(batch.batch);
              },
            );
          const aggregateCiphertextBytes = entries.reduce(
            (total, entry) => total + entry.bytes,
            0,
          );
          if (
            aggregateCiphertextBytes >
            resourceLimits.maxAggregateCiphertextBytes
          )
            throw new ReplicaResourceLimitError(
              "aggregate_ciphertext_bytes",
              aggregateCiphertextBytes,
              resourceLimits.maxAggregateCiphertextBytes,
            );
          // Sign the durably reserved version. The commit plan rechecks that
          // this is still the scope's next slot before retaining ciphertext.
          const version = preparation.version;
          const manifest = await prepareReplicaManifest({
            ...statement,
            version,
            fragments: entries,
            sign: async (facts) => {
              await assertPreparationClaim(batch.batch, version, signal);
              return signReplicaBatch({
                signer: deps.authority.signer,
                partition: partition(),
                seed: identity.seed,
                facts,
              });
            },
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
          return withPlan(receipt, function* () {
            if (!(yield* preparationCurrent(batch, progress))) return;
            const stored = (yield* sql.get<{ count: number; last: number }>(
              "SELECT count(*) AS count,coalesce(max(position),-1) AS last FROM pdpp_transport_fragments_out WHERE batch=?",
              batch.batch,
            ))!;
            if (stored.count !== count || stored.last !== count - 1)
              throw new ReplicaProblemError("prepare_failed");
            // The batch keeps the version it signed only if that is still the
            // scope's next one, in the same transaction as its manifest, so a
            // retry or a lost acknowledgement can never register it at a
            // second version.
            const { next } = (yield* sql.get<{ next: number }>(
              "SELECT coalesce(max(version),0)+1 AS next FROM pdpp_transport_manifests_out WHERE scope=?",
              manifest.scope,
            ))!;
            if (next !== manifest.version)
              throw new ReplicaProblemError("prepare_failed");
            yield* sql.run(
              "INSERT INTO pdpp_transport_manifests_out (batch,scope,version,plaintext,encrypted,data_hash,metadata_hash) VALUES (?,?,?,?,?,?,?)",
              batch.batch,
              manifest.scope,
              manifest.version,
              manifest.plaintext,
              manifest.encrypted,
              manifest.dataHash,
              manifest.metadataHash,
            );
            yield* sql.run(
              "UPDATE pdpp_transport_batches SET prepared=1 WHERE batch=?",
              batch.batch,
            );
            yield* sql.run(
              "UPDATE pdpp_transport_preparation SET state='prepared',wait_json=NULL WHERE batch=?",
              batch.batch,
            );
            yield* sql.run(
              "DELETE FROM pdpp_transport_preparation_progress WHERE batch=?",
              batch.batch,
            );
          });
        } catch (error) {
          return failedPreparation(batch, error, signal, progress.chunk_bytes);
        }
      } catch (error) {
        return failedPreparation(batch, error, signal);
      }
    },
    commit: commitIn((outcome, work, item) =>
      sql.run(
        `UPDATE pdpp_transport_batches SET ${WORK_SET} WHERE batch=?`,
        ...workValues(outcome, work),
        item.row.batch,
      ),
    ),
    commitProblem: "prepare_failed",
    earliest(e) {
      return query(
        (function* () {
          if (
            yield* sql.get(
              `SELECT 1 FROM pdpp_transport_batches b JOIN pdpp_transport_preparation p ON p.batch=b.batch WHERE ${prepareUnblocked} AND b.prepared=-2 AND p.state IN ('prep_failed_permanent','rebuilding') AND p.wait_json IS NULL LIMIT 1`,
            )
          )
            return e.now;
          return yield* earliestIn(
            e,
            `pdpp_transport_batches b WHERE ${prepareUnblocked} AND (b.prepared=0 OR (b.prepared=-2 AND EXISTS (SELECT 1 FROM pdpp_transport_preparation p WHERE p.batch=b.batch AND p.state='prep_failed_unknown')))`,
          );
        })(),
      );
    },
  };

  // -------------------------------------------------------------- publish
  /** Fragment PUTs and manifests ready for ordered registration. */
  const OUTBOUND = `(SELECT 'fragment' AS kind, batch||':'||position AS id, batch, position,
      NULL AS scope,NULL AS version,attempts,next_attempt,wait_since,checked_block,outcome,dependency
      FROM pdpp_transport_fragments_out WHERE state='ready' AND NOT EXISTS (SELECT 1 FROM pdpp_transport_preparation p WHERE p.batch=pdpp_transport_fragments_out.batch AND p.state<>'prepared')
    UNION ALL
    SELECT 'manifest' AS kind, m.scope||'/'||m.version AS id, m.batch, -1 AS position,
      m.scope,m.version,m.attempts,m.next_attempt,m.wait_since,m.checked_block,m.outcome,m.dependency
      FROM pdpp_transport_manifests_out m WHERE m.state='ready' AND NOT EXISTS (SELECT 1 FROM pdpp_transport_preparation p WHERE p.batch=m.batch AND p.state<>'prepared')
      AND NOT EXISTS (SELECT 1 FROM pdpp_transport_fragments_out f WHERE f.batch=m.batch AND f.state<>'stored'))`;
  type RegistrationIntent = {
    owner: string;
    manifest_hash: string;
    request_id: string;
    created_at: number;
    attempted_at: number;
    attempts: number;
    status: string;
  };
  const registrationIntent = (scope: string, version: number) =>
    sql.get<RegistrationIntent>(
      "SELECT owner,manifest_hash,request_id,created_at,attempted_at,attempts,status FROM pdpp_transport_registration_intents WHERE scope=? AND version=?",
      scope,
      version,
    );
  const pendingRegistration = (
    key: string,
    version: number,
    since: number,
    checkedBlock?: string,
    nextCheckAt?: number,
  ): ReplicaPhaseOutcome => ({
    tag: "wait",
    dependency: {
      kind: "registration_pending",
      key,
      version,
      since,
      ...(checkedBlock !== undefined && { checkedBlock }),
      ...(nextCheckAt !== undefined && { nextCheckAt }),
    },
  });
  function recordRegistrationAttempt(
    expected: ReplicaSlot,
    encrypted: Uint8Array,
    signal: AbortSignal,
  ) {
    const slotOwner = expected.owner;
    const manifestHash = sha256Digest(encrypted);
    const attemptedAt = now();
    return atomic(
      (function* () {
        door.assertStepOpen(signal);
        const held = yield* sql.get<{ encrypted: Uint8Array }>(
          "SELECT encrypted FROM pdpp_transport_manifests_out WHERE scope=? AND version=? AND state='ready'",
          expected.scope,
          expected.version,
        );
        if (!held || replicaDigest(held.encrypted) !== manifestHash)
          throw new ReplicaProblemError("publish_failed");
        const current = yield* registrationIntent(
          expected.scope,
          expected.version,
        );
        if (current) {
          if (
            current.owner !== slotOwner ||
            current.manifest_hash !== manifestHash
          )
            throw new ReplicaProblemError("publish_failed");
          yield* sql.run(
            "UPDATE pdpp_transport_registration_intents SET attempted_at=?,attempts=attempts+1 WHERE scope=? AND version=? AND status IN ('unresolved','accepted')",
            attemptedAt,
            expected.scope,
            expected.version,
          );
          return;
        }
        yield* sql.run(
          `INSERT INTO pdpp_transport_registration_intents
          (scope,version,owner,manifest_hash,request_id,created_at,attempted_at,attempts,status)
          VALUES (?,?,?,?,?,?,?,?, 'unresolved')`,
          expected.scope,
          expected.version,
          slotOwner,
          manifestHash,
          host.randomId(),
          attemptedAt,
          attemptedAt,
          1,
        );
        const { batch } = (yield* sql.get<{ batch: string }>(
          "SELECT batch FROM pdpp_transport_manifests_out WHERE scope=? AND version=?",
          expected.scope,
          expected.version,
        ))!;
        if (yield* recoveryOf(batch))
          yield* sql.run(
            "UPDATE pdpp_transport_registration_recovery SET state='registering' WHERE version=? AND batch IN (SELECT batch FROM pdpp_transport_manifests_out WHERE scope=?)",
            expected.version,
            expected.scope,
          );
      })(),
    );
  }
  const registrationWait = (
    reason: "own_key_conflict" | "version_squat",
  ): ReplicaPhaseOutcome => ({
    tag: "wait",
    dependency: { kind: "registration", key: writer(), reason },
  });
  function recoveryOf(batch: string) {
    return sql.get<{ version: number; state: RegistrationRecoveryState }>(
      "SELECT version,state FROM pdpp_transport_registration_recovery WHERE batch=?",
      batch,
    );
  }
  function setRecovery(
    batch: string,
    version: number,
    status: RegistrationRecoveryState,
  ) {
    return sql.run(
      `INSERT INTO pdpp_transport_registration_recovery (batch,version,state) VALUES (?,?,?)
      ON CONFLICT(batch) DO UPDATE SET version=excluded.version,state=excluded.state`,
      batch,
      version,
      status,
    );
  }
  function* registered(
    m: ManifestOut,
    evidence: ReplicaRegistrationEvidence,
  ): Fx<boolean> {
    if (m.state === "published") return true;
    if (
      ["accepted", "confirmed"].includes(
        (yield* registrationIntent(m.scope, m.version))?.status ?? "",
      )
    )
      return true;
    return (
      (evidence.chain !== null &&
        evidence.chain.owner.toLowerCase() === owner().toLowerCase() &&
        evidence.chain.scope === m.scope &&
        evidence.chain.version === String(m.version) &&
        BigInt(evidence.chain.currentVersion) >= BigInt(m.version) &&
        evidence.chain.commitment.toLowerCase() ===
          replicaChainCommitment(m.data_hash, m.metadata_hash).toLowerCase()) ||
      (evidence.head?.version === String(m.version) &&
        evidence.head.owner.toLowerCase() === owner().toLowerCase() &&
        evidence.head.scope === m.scope &&
        !evidence.head.deleted &&
        evidence.head.dataHash.toLowerCase() === m.data_hash.toLowerCase() &&
        evidence.head.metadataHash.toLowerCase() ===
          m.metadata_hash.toLowerCase())
    );
  }

  function registeredHeight(fact: ReplicaRegistrationEvidence, scope: string) {
    for (const record of [fact.head, fact.chain])
      if (
        record &&
        (record.owner.toLowerCase() !== owner().toLowerCase() ||
          record.scope !== scope)
      )
        throw new ReplicaProblemError("registration_unconfirmed");
    const height = Math.max(
      Number(fact.chain?.currentVersion ?? 0),
      Number(fact.head?.version ?? 0),
    );
    if (!Number.isSafeInteger(height) || height < 0)
      throw new ReplicaProblemError("registration_unconfirmed");
    return height;
  }

  /** Every pass uses the same classification; a snapshot cannot cancel an in-flight request. */
  function* recoveryDisposition(
    m: ManifestOut,
    fact: ReplicaRegistrationEvidence,
    authenticatedForeign = false,
  ): Fx<"accepted" | "movable" | "retry"> {
    if (m.state !== "ready" && m.state !== "published") return "retry";
    if (yield* registered(m, fact)) return "accepted";
    const status = replicaRegistrationState(fact, {
      owner: owner(),
      scope: m.scope,
      version: m.version,
      dataHash: m.data_hash,
      metadataHash: m.metadata_hash,
    });
    // An authenticated immutable foreign holder proves that this particular
    // request cannot ever own its old slot, even if its ACK was lost.
    if (authenticatedForeign && status === "conflict") return "movable";
    if (status !== "absent" || (yield* registrationIntent(m.scope, m.version)))
      return "retry";
    return "movable";
  }

  /** Stage signatures without I/O; the outcome transaction moves the entire unaccepted suffix. */
  async function recoverRegistration(
    row: ManifestOut,
    evidence: ReplicaRegistrationEvidence,
    signal: AbortSignal,
  ): Promise<Attempt> {
    const received = await receiveReplicaManifest({
      scope: row.scope,
      owner: owner(),
      maxBytes: cap,
      signal,
      read: (readSignal) =>
        call(signal, () =>
          transport.get(row.scope, row.version, {
            maxBytes: cap,
            signal: readSignal,
          }),
        ),
      decrypt: (bytes) =>
        call(signal, () => transport.decrypt(row.scope, bytes)),
      committed: (dataHash, metadataHash) =>
        replicaChainCommitment(dataHash, metadataHash).toLowerCase() ===
        evidence.chain?.commitment.toLowerCase(),
    });
    if (received.tag !== "manifest")
      return verdict({ tag: "retry", problem: "commitment_mismatch" });
    const holder = received.manifest;
    const identity = (await query(host.identity.current()))!;
    const original = decodeReplicaManifest(row.plaintext, row.scope, owner());
    if (holder.authority.statement.server === identity.seed.server) {
      const authorized = await authorizeManifest(
        holder,
        { writer: writer(), version: row.version },
        signal,
      );
      if (authorized.tag === "wait")
        return verdict(rosterWait(authorized.server));
      if (authorized.tag === "authorized") {
        if (
          holder.batch === original.batch &&
          holder.digest === original.digest
        )
          return verdict({
            tag: "progress",
            receipt: { phase: "publish", key: slotKey(row.scope, row.version) },
          });
        return withPlan(registrationWait("own_key_conflict"), () =>
          setRecovery(row.batch, row.version, "own_key_conflict"),
        );
      }
    }
    type Claim = {
      batch: string;
      version: number;
      sequence: number;
      prepared: number;
      plaintext: Uint8Array | null;
      encrypted: Uint8Array | null;
      data_hash: `0x${string}`;
      metadata_hash: `0x${string}`;
      state: string;
    };
    const { attempts, claims } = await query(
      (function* () {
        const attempts = (yield* sql.get<{ n: number }>(
          "SELECT count(*) AS n FROM pdpp_transport_version_squats WHERE scope=? AND detected_at>=?",
          row.scope,
          now() - REPLICA_VERSION_SQUAT_WINDOW_MS,
        ))!.n;
        if (attempts >= REPLICA_VERSION_SQUAT_ATTEMPTS)
          return { attempts, claims: [] as Claim[] };
        const claims = yield* sql.all<Claim>(
          `SELECT p.batch,p.version,b.sequence,b.prepared,m.plaintext,m.encrypted,m.data_hash,m.metadata_hash,m.state
      FROM pdpp_transport_preparation p JOIN pdpp_transport_batches b ON b.batch=p.batch
      LEFT JOIN pdpp_transport_manifests_out m ON m.batch=p.batch
      WHERE p.version>=? AND p.state<>'released' ORDER BY b.sequence`,
          row.version,
        );
        return { attempts, claims };
      })(),
    );
    if (attempts >= REPLICA_VERSION_SQUAT_ATTEMPTS)
      return withPlan(registrationWait("version_squat"), () =>
        setRecovery(row.batch, row.version, "version_squat"),
      );
    const moving: Claim[] = [];
    const accepted: Claim[] = [];
    let highest = registeredHeight(evidence, row.scope);
    for (const claim of claims) {
      if (
        ![0, 1, -1, -2].includes(claim.prepared) ||
        (!claim.plaintext &&
          (await query(registrationIntent(row.scope, claim.version))))
      )
        return verdict({ tag: "retry", problem: "registration_unconfirmed" });
      if (claim.plaintext) {
        const m = { ...claim, scope: row.scope } as ManifestOut;
        const fact =
          claim.batch === row.batch
            ? evidence
            : await call(signal, () =>
                transport.evidence(row.scope, claim.version),
              );
        highest = Math.max(highest, registeredHeight(fact, row.scope));
        const disposition = await query(
          recoveryDisposition(m, fact, claim.batch === row.batch),
        );
        if (disposition === "accepted") {
          if (claim.batch === row.batch)
            return verdict({
              tag: "retry",
              problem: "registration_unconfirmed",
            });
          highest = Math.max(highest, claim.version);
          accepted.push(claim);
          continue;
        }
        if (disposition !== "movable")
          return verdict({ tag: "retry", problem: "registration_unconfirmed" });
      }
      moving.push(claim);
    }
    const first = highest + 1;
    if (
      !Number.isSafeInteger(first + moving.length) ||
      !moving.some((c) => c.batch === row.batch)
    )
      throw new ReplicaProblemError("publish_failed");
    const staged = new Map<string, PreparedManifest>();
    for (const [index, claim] of moving.entries()) {
      if (!claim.plaintext) continue;
      const manifest = decodeReplicaManifest(
        claim.plaintext,
        row.scope,
        owner(),
      );
      const replacement = await prepareReplicaManifest({
        ...manifest,
        version: first + index,
        // The predecessor is a batch/digest pointer, so moving wire slots leaves
        // the same valid pointer (and every content-addressed fragment) intact.
        previous: manifest.previous,
        sign: (facts) =>
          signReplicaBatch({
            signer: deps.authority.signer,
            partition: partition(),
            seed: identity.seed,
            facts,
          }),
        encrypt: (scope, bytes) =>
          call(signal, () => transport.encrypt(scope, bytes)),
      });
      if (replacement.encrypted.length > cap)
        throw new ReplicaProblemError("publish_failed");
      staged.set(claim.batch, replacement);
    }
    // I/O in another already-started upload may have completed while signing.
    // Recheck acceptance before releasing any claim; no SQLite transaction spans I/O.
    for (const claim of moving) {
      if (claim.batch === row.batch || !claim.plaintext) continue;
      const fact = await call(signal, () =>
        transport.evidence(row.scope, claim.version),
      );
      if (
        (await query(
          recoveryDisposition(
            { ...claim, scope: row.scope } as ManifestOut,
            fact,
          ),
        )) !== "movable"
      )
        return verdict({ tag: "retry", problem: "registration_unconfirmed" });
    }
    return withPlan(
      pendingRegistration(
        slotKey(row.scope, first),
        first,
        now(),
        undefined,
        now(),
      ),
      function* () {
        // commitIn wraps this whole plan, including its outcome, in one immediate transaction.
        for (const claim of moving) {
          const current = yield* preparationOf(claim.batch);
          const held = yield* sql.get<{
            version: number;
            encrypted: Uint8Array;
            state: string;
          }>(
            "SELECT version,encrypted,state FROM pdpp_transport_manifests_out WHERE batch=?",
            claim.batch,
          );
          if (
            current?.version !== claim.version ||
            (claim.encrypted &&
              (!held ||
                held.version !== claim.version ||
                held.state !== "ready" ||
                !sameBytes(held.encrypted, claim.encrypted))) ||
            (claim.batch !== row.batch &&
              (yield* registrationIntent(row.scope, claim.version)) !==
                undefined) ||
            ["accepted", "confirmed"].includes(
              (yield* registrationIntent(row.scope, claim.version))?.status ??
                "",
            )
          )
            throw new ReplicaProblemError("publish_failed");
        }
        yield* sql.run(
          "INSERT INTO pdpp_transport_version_squats (scope,version,digest,detected_at,batch,state) VALUES (?,?,?,?,?,'squatted')",
          row.scope,
          row.version,
          received.dataHash,
          now(),
          row.batch,
        );
        // Release every old slot before assigning the suffix, including unsigned claims.
        for (const claim of moving) {
          yield* releaseClaim(claim.batch);
          yield* sql.run(
            "DELETE FROM pdpp_transport_registration_intents WHERE scope=? AND version=?",
            row.scope,
            claim.version,
          );
          yield* sql.run(
            "DELETE FROM pdpp_transport_upload_attempts WHERE batch=? AND kind='manifest'",
            claim.batch,
          );
          yield* sql.run(
            "UPDATE pdpp_transport_preparation SET version=0 WHERE batch=?",
            claim.batch,
          );
        }
        for (const [index, claim] of moving.entries()) {
          const version = first + index;
          const m = staged.get(claim.batch);
          if (m)
            yield* sql.run(
              "INSERT INTO pdpp_transport_manifests_out (batch,scope,version,plaintext,encrypted,data_hash,metadata_hash) VALUES (?,?,?,?,?,?,?)",
              claim.batch,
              m.scope,
              m.version,
              m.plaintext,
              m.encrypted,
              m.dataHash,
              m.metadataHash,
            );
          yield* sql.run(
            "UPDATE pdpp_transport_preparation SET version=? WHERE batch=?",
            version,
            claim.batch,
          );
          yield* setRecovery(claim.batch, version, "resigning");
        }
        for (const claim of accepted)
          yield* setRecovery(claim.batch, claim.version, "registering");
        yield* sql.run(
          "UPDATE pdpp_transport_version_squats SET state='resigning' WHERE scope=? AND version=?",
          row.scope,
          row.version,
        );
      },
    );
  }
  /** The verdict for a slot whose registration is pending or awaiting finality. */
  function* pendingVerdict(
    row: ManifestOut,
    key: string,
    evidence: ReplicaRegistrationEvidence,
    intent: RegistrationIntent | undefined,
    previousWaitSince: number | null,
  ): Fx<ReplicaPhaseOutcome> {
    return (yield* tailPending())
      ? pendingRegistration(
          key,
          row.version,
          intent?.created_at ?? previousWaitSince ?? now(),
          evidence.chain?.blockNumber.toString(),
        )
      : finalityWait(evidence, key);
  }
  async function publishManifest(
    batch: string,
    previousWaitSince: number | null,
    signal: AbortSignal,
  ): Promise<Attempt> {
    const row = (await query(
      sql.get<ManifestOut>(
        "SELECT * FROM pdpp_transport_manifests_out WHERE batch=?",
        batch,
      ),
    ))!;
    const key = slotKey(row.scope, row.version);
    const expected: ReplicaSlot = {
      owner: owner(),
      scope: row.scope,
      version: row.version,
      dataHash: row.data_hash,
      metadataHash: row.metadata_hash,
    };
    try {
      // Local order before any network call: a recovery or an unsettled
      // predecessor decides this slot's verdict without evidence.
      const ordered = await query(
        (function* (): Fx<{ outcome?: ReplicaPhaseOutcome }> {
          const recovery = yield* recoveryOf(batch);
          if (
            recovery?.state === "own_key_conflict" ||
            recovery?.state === "version_squat"
          )
            return { outcome: registrationWait(recovery.state) };
          if (recovery) {
            const prior = yield* sql.get<{
              version: number;
              checked_block: string | null;
              next_attempt: number | null;
            }>(
              `SELECT p.version,m.checked_block,m.next_attempt FROM pdpp_transport_batches b
          JOIN pdpp_transport_preparation p ON p.batch=b.batch LEFT JOIN pdpp_transport_manifests_out m ON m.batch=b.batch
          WHERE b.sequence<(SELECT sequence FROM pdpp_transport_batches WHERE batch=?) AND NOT ${batchSettled("b")}
          ORDER BY b.sequence LIMIT 1`,
              batch,
            );
            if (prior)
              return {
                outcome: pendingRegistration(
                  slotKey(row.scope, prior.version),
                  prior.version,
                  previousWaitSince ?? now(),
                  prior.checked_block ?? undefined,
                  prior.next_attempt ?? undefined,
                ),
              };
          }
          if (row.version > 1 && !recovery) {
            const predecessor = yield* sql.get<{
              state: string;
              outcome: string | null;
              reason: string | null;
              checked_block: string | null;
              next_attempt: number;
            }>(
              "SELECT state,outcome,reason,checked_block,next_attempt FROM pdpp_transport_manifests_out WHERE scope=? AND version=?",
              row.scope,
              row.version - 1,
            );
            const predecessorSettled =
              predecessor?.state === "published" ||
              (predecessor?.state === "quarantined" &&
                predecessor.outcome === "quarantine" &&
                predecessor.reason === "immutable_registration_conflict");
            if (!predecessorSettled) {
              const intent = yield* registrationIntent(
                row.scope,
                row.version - 1,
              );
              return {
                outcome: pendingRegistration(
                  slotKey(row.scope, row.version - 1),
                  row.version - 1,
                  intent?.created_at ?? previousWaitSince ?? now(),
                  predecessor?.checked_block ?? undefined,
                  predecessor?.next_attempt,
                ),
              };
            }
          }
          return {};
        })(),
      );
      if (ordered.outcome) return verdict(ordered.outcome);
      let evidence = await call(signal, () =>
        transport.evidence(row.scope, row.version),
      );
      let status = replicaRegistrationState(evidence, expected);
      if (status === "conflict")
        return await recoverRegistration(row, evidence, signal);
      if (status === "confirmed")
        return verdict({
          tag: "progress",
          receipt: { phase: "publish", key },
        });
      let intent = await query(registrationIntent(row.scope, row.version));
      if (status === "pending")
        return verdict(
          await query(
            pendingVerdict(row, key, evidence, intent, previousWaitSince),
          ),
        );
      if (status === "absent") {
        const timestamp = now();
        if (
          intent &&
          timestamp - intent.attempted_at < registrationIntentTimeout
        )
          return verdict(
            pendingRegistration(key, row.version, intent.created_at),
          );
        const manifest: PreparedManifest = {
          scope: row.scope,
          version: row.version,
          plaintext: row.plaintext,
          encrypted: row.encrypted,
          dataHash: row.data_hash,
          metadataHash: row.metadata_hash,
        };
        await recordUploadAttempt(batch, "manifest", -1, signal);
        await call(signal, () => transport.put(manifest, signal));
        await recordRegistrationAttempt(expected, row.encrypted, signal);
        try {
          await call(signal, () => transport.register(manifest));
          await atomic(
            (function* () {
              door.assertStepOpen(signal);
              yield* sql.run(
                "UPDATE pdpp_transport_registration_intents SET status='accepted' WHERE scope=? AND version=? AND manifest_hash=?",
                row.scope,
                row.version,
                replicaDigest(row.encrypted),
              );
            })(),
          );
        } catch {
          return verdict(
            pendingRegistration(
              key,
              row.version,
              intent?.created_at ?? timestamp,
            ),
          );
        }
        evidence = await call(signal, () =>
          transport.evidence(row.scope, row.version),
        );
        status = replicaRegistrationState(evidence, expected);
      }
      if (status === "conflict")
        return await recoverRegistration(row, evidence, signal);
      if (status === "confirmed")
        return verdict({
          tag: "progress",
          receipt: { phase: "publish", key },
        });
      if (status === "pending")
        return verdict(
          await query(
            pendingVerdict(row, key, evidence, intent, previousWaitSince),
          ),
        );
      intent = await query(registrationIntent(row.scope, row.version));
      return verdict(
        pendingRegistration(
          key,
          row.version,
          intent?.created_at ?? previousWaitSince ?? now(),
        ),
      );
    } catch (error) {
      return verdict(retryFromError(error, "publish_failed"));
    }
  }
  type OutboundState = Work & {
    state: string;
    outcome: string | null;
    version?: number;
  };
  /**
   * The batch's registration is finalized: drop its payload and fragment
   * ciphertext in the caller's transaction (host contract §6, "Reclaim").
   * The fragment rows keep their digests and the manifest keeps every
   * fragment's length, which is all later chain decisions read. No outbound
   * phase selects a published batch's fragments or payload again.
   */
  function* reclaimPublished(batch: string): Fx<void> {
    yield* deleteReplicaPayload(batch);
    yield* sql.run(
      "UPDATE pdpp_transport_fragments_out SET encrypted=x'' WHERE batch=? AND length(encrypted)>0",
      batch,
    );
  }
  /** Revisit a released slot if another writer registers it. */
  function* releaseClaim(batch: string): Fx<void> {
    yield* sql.run(
      `UPDATE pdpp_transport_discover_floor
      SET version=min(version,(SELECT version-1 FROM pdpp_transport_manifests_out WHERE batch=?))
      WHERE scope=(SELECT scope FROM pdpp_transport_manifests_out WHERE batch=?)`,
      batch,
      batch,
    );
    yield* sql.run(
      "DELETE FROM pdpp_transport_manifests_out WHERE batch=?",
      batch,
    );
  }
  /** Reclaim batches finalized before reclaim existed. Once per engine. */
  let reclaimSwept = false;
  function* sweepPublished(): Fx<void> {
    if (reclaimSwept) return;
    const batches = yield* sql.all<{ batch: string }>(
      `SELECT m.batch FROM pdpp_transport_manifests_out m WHERE m.state='published'
       AND (EXISTS (SELECT 1 FROM pdpp_binary_manifests p WHERE p.namespace='payload' AND p.blob_id=m.batch)
         OR EXISTS (SELECT 1 FROM pdpp_transport_fragments_out f WHERE f.batch=m.batch AND length(f.encrypted)>0))`,
    );
    for (const { batch } of batches) yield* reclaimPublished(batch);
    const ownAdmissions = `SELECT i.slot FROM pdpp_transport_manifests_in i
      JOIN pdpp_transport_manifests_out o ON o.scope=i.scope AND o.version=i.version AND o.state='published'
      WHERE (i.state='ready' AND i.manifest_json IS NULL) OR (i.state='imported' AND i.batch=o.batch)`;
    yield* sql.run(
      `DELETE FROM pdpp_transport_fragment_parts WHERE slot IN (${ownAdmissions})`,
    );
    yield* sql.run(
      `DELETE FROM pdpp_transport_fragments_in WHERE slot IN (${ownAdmissions})`,
    );
    yield* sql.run(
      `DELETE FROM pdpp_transport_manifests_in WHERE slot IN (${ownAdmissions})`,
    );
    reclaimSwept = true;
  }
  const publish: Handler<Item<Outbound>> = {
    phase: "publish",
    due(e, limit) {
      // Parked waits are filtered before LIMIT so they cannot hide fresh or error work.
      return then(
        query(
          sql.all<Outbound>(
            dueWindow(
              OUTBOUND,
              "batch",
              "next_attempt,kind,coalesce(version,0),position",
              due(e),
            ),
            limit.perWriter,
            limit.after ?? "",
            limit.total,
          ),
        ),
        (rows) =>
          rows.map((row): Item<Outbound> => ({
            id: row.id,
            phase: "publish",
            // Local batches take turns like remote writers do.
            writer: row.batch,
            state: workState(row),
            row,
          })),
      );
    },
    async run(item, signal) {
      const row = item.row;
      if (row.kind === "manifest")
        return publishManifest(row.batch, row.wait_since, signal);
      try {
        const fragment = (await query(
          sql.get<{ digest: string; encrypted: Uint8Array }>(
            "SELECT digest,encrypted FROM pdpp_transport_fragments_out WHERE batch=? AND position=?",
            row.batch,
            row.position,
          ),
        ))!;
        // Unregistered and content-addressed: a PUT is safe to repeat, and
        // nothing references it until the manifest is finalized.
        await recordUploadAttempt(row.batch, "fragment", row.position, signal);
        await call(signal, () =>
          transport.putFragment(
            {
              scope: replicaScope(writer()),
              digest: fragment.digest,
              encrypted: fragment.encrypted,
            },
            signal,
          ),
        );
        return verdict({
          tag: "progress",
          receipt: { phase: "publish", key: row.id },
        });
      } catch (error) {
        return verdict(retryFromError(error, "publish_failed"));
      }
    },
    commit: (item, attempt, settle, context) =>
      commitIn<Item<Outbound>>(
        function* (outcome, work) {
          const next =
            outcome.tag === "progress"
              ? item.row.kind === "manifest"
                ? "published"
                : "stored"
              : outcome.tag === "quarantine"
                ? "quarantined"
                : "ready";
          if (item.row.kind === "manifest")
            yield* sql.run(
              `UPDATE pdpp_transport_manifests_out SET ${WORK_SET},state=? WHERE batch=?`,
              ...workValues(outcome, work),
              next,
              item.row.batch,
            );
          if (item.row.kind === "manifest" && outcome.tag === "progress")
            yield* sql.run(
              "UPDATE pdpp_transport_registration_recovery SET state='committed' WHERE batch=?",
              item.row.batch,
            );
          if (item.row.kind === "manifest" && outcome.tag === "progress") {
            yield* sql.run(
              "UPDATE pdpp_transport_registration_intents SET status='confirmed' WHERE scope=? AND version=?",
              item.row.scope!,
              item.row.version!,
            );
            // The batch is durable on the gateway: its operations leave the
            // host's outbox in the same transaction.
            const exported = yield* sql.get<{ export_next: number | null }>(
              "SELECT export_next FROM pdpp_transport_batches WHERE batch=?",
              item.row.batch,
            );
            if (exported?.export_next != null)
              yield* exporter.acknowledgePublished(exported.export_next);
            yield* reclaimPublished(item.row.batch);
          }
          if (item.row.kind === "manifest" && outcome.tag === "quarantine")
            yield* sql.run(
              "UPDATE pdpp_transport_registration_intents SET status='conflict' WHERE scope=? AND version=?",
              item.row.scope!,
              item.row.version!,
            );
          else
            yield* sql.run(
              `UPDATE pdpp_transport_fragments_out SET ${WORK_SET},state=? WHERE batch=? AND position=?`,
              ...workValues(outcome, work),
              next,
              item.row.batch,
              item.row.position,
            );
          if (item.row.kind === "manifest")
            yield* sql.run(
              `UPDATE pdpp_transport_manifests_out SET next_attempt=?
               WHERE scope=? AND version>? AND state='ready'
                 AND dependency=?`,
              outcome.tag === "quarantine" ? now() : work.nextEligible,
              item.row.scope!,
              item.row.version!,
              `registration_pending:${slotKey(item.row.scope!, item.row.version!)}`,
            );
        },
        function* (selected) {
          const row = selected.row;
          const current =
            row.kind === "manifest"
              ? yield* sql.get<OutboundState>(
                  "SELECT state,version,attempts,next_attempt,wait_since,checked_block,outcome FROM pdpp_transport_manifests_out WHERE batch=?",
                  row.batch,
                )
              : yield* sql.get<OutboundState>(
                  "SELECT state,attempts,next_attempt,wait_since,checked_block,outcome FROM pdpp_transport_fragments_out WHERE batch=? AND position=?",
                  row.batch,
                  row.position,
                );
          return (
            current !== undefined &&
            (row.kind !== "manifest" || current.version === row.version) &&
            current.state === "ready" &&
            current.attempts === row.attempts &&
            current.next_attempt === row.next_attempt &&
            current.wait_since === row.wait_since &&
            current.checked_block === row.checked_block &&
            current.outcome === row.outcome
          );
        },
      )(item, attempt, settle, context),
    commitProblem: "publish_failed",
    earliest(e) {
      return query(earliestIn(e, `${OUTBOUND} outbound`));
    },
  };

  // ------------------------------------------------------------- discover
  const discover: Handler<Item<Work>> = {
    phase: "discover",
    due(e) {
      return then(query(singleton("discover")), (row): Item<Work>[] =>
        (singletonEligibleAt(row, e) ?? Infinity) <= e.now
          ? [
              {
                id: "discover",
                phase: "discover",
                writer: "",
                state: workState(row),
                row,
              },
            ]
          : [],
      );
    },
    async run(_item, signal) {
      let page: Awaited<ReturnType<ReplicaTransportPort["list"]>>;
      try {
        page = await call(signal, async () =>
          transport.list((await query(state())).scan_cursor),
        );
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
        function* () {
          for (const point of page.points) {
            const pointWriter = replicaWriterOf(point.scope);
            if (!pointWriter || !/^[1-9][0-9]{0,14}$/.test(point.version))
              continue;
            // Every version through the floor is claimed or admitted.
            const head = Number(point.version);
            const floor =
              (yield* sql.get<{ version: number }>(
                "SELECT version FROM pdpp_transport_discover_floor WHERE scope=?",
                point.scope,
              ))?.version ?? 0;
            const covered = new Set(
              (yield* sql.all<{ version: number }>(
                `SELECT version FROM pdpp_transport_manifests_out WHERE scope=? AND version>? AND version<=?
               UNION ALL SELECT version FROM pdpp_transport_manifests_in WHERE scope=? AND version>? AND version<=?`,
                point.scope,
                floor,
                head,
                point.scope,
                floor,
                head,
              )).map((row) => row.version),
            );
            let admitted = 0;
            let version = floor + 1;
            for (; version <= head; version++) {
              if (covered.has(version)) continue;
              if (admitted === DISCOVER_SLOTS) break;
              yield* sql.run(
                "INSERT OR IGNORE INTO pdpp_transport_manifests_in (slot,scope,version,writer) VALUES (?,?,?,?)",
                slotKey(point.scope, version),
                point.scope,
                version,
                pointWriter,
              );
              admitted++;
            }
            yield* sql.run(
              "INSERT INTO pdpp_transport_discover_floor (scope,version) VALUES (?,?) ON CONFLICT(scope) DO UPDATE SET version=excluded.version",
              point.scope,
              version - 1,
            );
          }
          yield* sql.run(
            "UPDATE pdpp_transport_state SET scan_cursor=? WHERE id=1",
            page.cursor,
          );
        },
      );
    },
    commit: commitIn((outcome, work) =>
      settleSingleton("discover", outcome, work),
    ),
    commitProblem: "discovery_failed",
    earliest(e) {
      // A polling source: only an outstanding Retry is a deadline.
      return query(singletonDeadline("discover", e));
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
  /**
   * A received fragment's JSON. Fragments fetched before the parts table
   * keep it in `fragment_json`; later ones leave that empty and use parts.
   */
  function* fragmentJson(slot: string, position: number): Fx<string> {
    const whole = yield* sql.get<{ fragment_json: string | null }>(
      "SELECT fragment_json FROM pdpp_transport_fragments_in WHERE slot=? AND position=?",
      slot,
      position,
    );
    if (whole?.fragment_json) return whole.fragment_json;
    let json = "";
    for (let part = 0; ; part++) {
      const row = yield* sql.get<{ json: string }>(
        "SELECT json FROM pdpp_transport_fragment_parts WHERE slot=? AND position=? AND part=?",
        slot,
        position,
        part,
      );
      if (!row) return json;
      json += row.json;
    }
  }
  function* dropFragments(slot: string): Fx<void> {
    yield* sql.run(
      "DELETE FROM pdpp_transport_fragment_parts WHERE slot=?",
      slot,
    );
    yield* sql.run(
      "DELETE FROM pdpp_transport_fragments_in WHERE slot=?",
      slot,
    );
  }
  function* wake(key: string, at: number): Fx<number> {
    return (yield* sql.run(
      "UPDATE pdpp_transport_import_work SET next_attempt=? WHERE outcome='wait' AND dependency=? AND next_attempt>?",
      at,
      key,
      at,
    )).changes;
  }
  /** A slot whose finalized manifest can never be valid: terminal for that slot only. */
  const refuseSlot = (
    slot: string,
    reason: ReplicaAuthorityRefusal | "manifest_invalid",
  ) =>
    withPlan(quarantine(reason, slot), () =>
      sql.run(
        `UPDATE pdpp_transport_manifests_in SET ${QUARANTINE_SET(reason)} WHERE slot=?`,
        slot,
      ),
    );
  const download: Handler<Item<Slot>> = {
    phase: "download",
    due(e, limit) {
      return then(
        query(
          sql.all<Slot>(
            dueWindow(
              `(SELECT rowid AS position,slot,scope,version,writer,attempts,next_attempt,wait_since,checked_block,outcome,dependency FROM pdpp_transport_manifests_in WHERE state='ready' AND manifest_json IS NULL)`,
              "writer",
              "next_attempt,version",
              due(e),
            ),
            limit.perWriter,
            limit.after ?? "",
            limit.total,
          ),
        ),
        (rows) => rows.map(slotItem("download")),
      );
    },
    async run(item, signal) {
      const row = item.row;
      let manifestReservation: (() => void) | undefined;
      let keepManifestReservation = false;
      const slot: ReplicaSlot = {
        owner: owner(),
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
        const reserved = resourceBudget.reserve(
          resourceLimits.maxManifestCiphertextBytes * REPLICA_LIVE_COPY_FACTOR,
        );
        if (typeof reserved !== "function")
          return verdict({ tag: "retry", problem: "resource_busy" });
        manifestReservation = reserved;
        // Every peer-supplied manifest crosses this one boundary. Bytes that
        // are not the finalized commitment are a refetch, never data, so
        // replacing stored bytes cannot get a real manifest refused; after
        // the commitment every failure is terminal. No fragment is fetched
        // before the manifest is authorized.
        const receipt = await receiveReplicaManifest({
          scope: row.scope,
          owner: owner(),
          maxBytes: cap,
          signal,
          read: (readSignal) =>
            call(signal, () =>
              transport.get(row.scope, row.version, {
                maxBytes: cap,
                signal: readSignal,
              }),
            ),
          decrypt: (encrypted) =>
            call(signal, () => transport.decrypt(row.scope, encrypted)),
          committed: (dataHash, metadataHash) =>
            replicaRegistrationState(evidence, {
              ...slot,
              dataHash,
              metadataHash,
            }) === "confirmed",
        });
        if (receipt.tag === "refused")
          return refuseSlot(row.slot, receipt.reason);
        if (receipt.tag === "mismatch")
          throw new ReplicaProblemError("commitment_mismatch");
        const { manifest, dataHash, metadataHash } = receipt;
        const authorized = await authorizeManifest(manifest, row, signal);
        if (authorized.tag === "refused")
          return refuseSlot(row.slot, authorized.reason);
        if (authorized.tag === "wait")
          return verdict(rosterWait(authorized.server));
        const admitted = admit(
          manifest,
          resourceBudget,
          {
            repositoryId: await query(repositoryId()),
            owner: owner(),
            manifestDigest: manifest.digest,
          },
          resourceLimits,
        );
        if ("kind" in admitted) {
          if (admitted.kind === "resource_busy")
            return verdict({ tag: "retry", problem: "resource_busy" });
          return withPlan(
            {
              tag: "unsupported",
              admission: {
                reason: "resource_unsupported",
                limit: admitted.limit,
                limitsVersion: admitted.limitsVersion,
              },
            },
            () =>
              sql.run(
                `UPDATE pdpp_transport_manifests_in
                 SET resource_limits_version=? WHERE slot=?`,
                admitted.limitsVersion,
                row.slot,
              ),
          );
        }
        const record = factOf(row, evidence, manifest);
        keepManifestReservation = true;
        return {
          outcome: {
            tag: "progress",
            receipt: { phase: "download", key: row.slot },
          },
          plan: function* () {
            // A correct writer gives each batch one version. Another slot
            // naming the same batch is equivocation: only the first is used.
            const holder = yield* sql.get(
              "SELECT slot FROM pdpp_transport_manifests_in WHERE writer=? AND batch=? AND slot<>? AND state<>'quarantined'",
              row.writer,
              manifest.batch,
              row.slot,
            );
            if (holder) {
              yield* sql.run(
                `UPDATE pdpp_transport_manifests_in SET ${QUARANTINE_SET("batch_equivocation")} WHERE slot=?`,
                row.slot,
              );
              return quarantine("batch_equivocation", row.slot);
            }
            yield* sql.run(
              "UPDATE pdpp_transport_manifests_in SET manifest_json=?,data_hash=?,metadata_hash=?,batch=?,sequence=? WHERE slot=?",
              canonicalJson(manifest),
              dataHash,
              metadataHash,
              manifest.batch,
              manifest.sequence,
              row.slot,
            );
            for (const [position, entry] of manifest.fragments.entries())
              yield* sql.run(
                "INSERT OR IGNORE INTO pdpp_transport_fragments_in (slot,position,digest,bytes) VALUES (?,?,?,?)",
                row.slot,
                position,
                entry.digest,
                entry.bytes,
              );
            if (record) yield* record();
            return undefined;
          },
          release: () => manifestReservation?.(),
        };
      } catch (error) {
        // Network and unavailable bytes are retryable; authenticated malformed bytes back off.
        return verdict(retryFromError(error, "download_failed"));
      } finally {
        if (!keepManifestReservation) manifestReservation?.();
      }
    },
    commit: commitIn((outcome, work, item) =>
      sql.run(
        `UPDATE pdpp_transport_manifests_in SET ${WORK_SET} WHERE slot=? AND state='ready'`,
        ...workValues(outcome, work),
        item.id,
      ),
    ),
    commitProblem: "download_failed",
    earliest(e) {
      return query(
        earliestIn(
          e,
          "pdpp_transport_manifests_in WHERE state='ready' AND manifest_json IS NULL",
        ),
      );
    },
  };

  // ---------------------------------------------------------------- fetch
  function* manifestOf(slot: string): Fx<ReplicaManifest> {
    return JSON.parse(
      (yield* sql.get<{ manifest_json: string }>(
        "SELECT manifest_json FROM pdpp_transport_manifests_in WHERE slot=?",
        slot,
      ))!.manifest_json,
    ) as ReplicaManifest;
  }
  /** A fragment that disproves its slot quarantines the slot with it. */
  const quarantineFragment = (
    row: FragmentIn,
    reason: "fragment_missing" | "fragment_mismatch",
  ) =>
    withPlan(quarantine(reason, `${row.slot}#${row.position}`), () =>
      sql.run(
        `UPDATE pdpp_transport_manifests_in SET ${QUARANTINE_SET(reason)} WHERE slot=? AND state='ready'`,
        row.slot,
      ),
    );
  const FETCHABLE = `(SELECT f.rowid AS rowid_,f.slot,f.position,f.digest,f.bytes,m.writer,f.attempts,f.next_attempt,f.wait_since,f.checked_block,f.outcome,f.dependency
    FROM pdpp_transport_fragments_in f JOIN pdpp_transport_manifests_in m ON m.slot=f.slot
    WHERE f.state='ready' AND f.fragment_json IS NULL AND m.state='ready')`;
  const fetchFragment: Handler<Item<FragmentIn>> = {
    phase: "fetch",
    due(e, limit) {
      return then(
        query(
          sql.all<FragmentIn>(
            dueWindow(FETCHABLE, "writer", "next_attempt,rowid_", due(e)),
            limit.perWriter,
            limit.after ?? "",
            limit.total,
          ),
        ),
        (rows) =>
          rows.map((row): Item<FragmentIn> => ({
            id: `${row.slot}#${row.position}`,
            phase: "fetch",
            writer: row.writer,
            state: workState(row),
            bytes: row.bytes,
            row,
          })),
      );
    },
    async run(item, signal) {
      const row = item.row;
      const scope = replicaScope(row.writer);
      let fragment: ReplicaFragment;
      let fragmentReservation: (() => void) | undefined;
      let keepFragmentReservation = false;
      try {
        const manifest = await query(manifestOf(row.slot));
        const admitted = admit(
          manifest,
          resourceBudget,
          {
            repositoryId: await query(repositoryId()),
            owner: owner(),
            manifestDigest: manifest.digest,
          },
          resourceLimits,
        );
        if ("kind" in admitted) {
          if (admitted.kind === "resource_busy")
            return verdict({ tag: "retry", problem: "resource_busy" });
          return verdict({ tag: "retry", problem: "resource_busy" });
        }
        const reserved = admitted.reserveObject(row.bytes);
        if (typeof reserved !== "function")
          return verdict({ tag: "retry", problem: "resource_busy" });
        fragmentReservation = reserved;
        const receipt = await receiveReplicaFragment({
          scope,
          owner: owner(),
          manifest,
          index: row.position,
          maxBytes: row.bytes,
          signal,
          read: (readSignal) =>
            call(readSignal, () =>
              transport.getFragment(scope, row.digest, {
                maxBytes: row.bytes,
                signal: readSignal,
              }),
            ),
          decrypt: (encrypted) => transport.decrypt(scope, encrypted),
        });
        if (receipt.tag === "refused")
          return quarantineFragment(row, receipt.reason);
        fragment = receipt.fragment;
        keepFragmentReservation = true;
      } catch (error) {
        if (signal.aborted)
          return verdict(retryFromError(error, "download_failed"));
        if (error instanceof ReplicaObjectRefused)
          return quarantineFragment(row, "fragment_mismatch");
        // Only definitive absence proves a missing fragment. Transient read,
        // deadline and cancellation failures remain retries.
        try {
          if (
            !(await call(signal, () =>
              transport.hasFragment(scope, row.digest, signal),
            ))
          )
            return quarantineFragment(row, "fragment_missing");
        } catch {
          // Preserve the original transient failure.
        }
        return verdict(retryFromError(error, "download_failed"));
      } finally {
        if (!keepFragmentReservation) fragmentReservation?.();
      }
      return {
        outcome: {
          tag: "progress",
          receipt: { phase: "fetch", key: item.id },
        },
        plan: function* () {
          // In parts: a Node fragment is 4 MiB, a phone SQL value 1 MiB.
          const parts = replicaTextParts(
            canonicalJson(fragment),
            REPLICA_TEXT_PART_BYTES,
          );
          yield* sql.run(
            "DELETE FROM pdpp_transport_fragment_parts WHERE slot=? AND position=?",
            row.slot,
            row.position,
          );
          for (const [part, json] of parts.entries())
            yield* sql.run(
              "INSERT INTO pdpp_transport_fragment_parts VALUES (?,?,?,?)",
              row.slot,
              row.position,
              part,
              json,
            );
          yield* sql.run(
            "UPDATE pdpp_transport_fragments_in SET fragment_json='' WHERE slot=? AND position=?",
            row.slot,
            row.position,
          );
          yield* wake(`fragments:${fragment.writer}:${fragment.batch}`, now());
        },
        release: () => fragmentReservation?.(),
      };
    },
    commit: commitIn((outcome, work, item) =>
      sql.run(
        `UPDATE pdpp_transport_fragments_in SET ${WORK_SET},state=? WHERE slot=? AND position=?`,
        ...workValues(outcome, work),
        outcome.tag === "quarantine" ? "quarantined" : "ready",
        item.row.slot,
        item.row.position,
      ),
    ),
    commitProblem: "download_failed",
    earliest(e) {
      return query(earliestIn(e, `${FETCHABLE} fetchable`));
    },
  };

  // ----------------------------------------- revalidate (imported slots)
  /**
   * A finalized fact disagrees with an imported slot. The batch records the
   * fact and takes the copy decision, which is terminal for a disproved
   * promoted copy (contract A, H).
   */
  async function importedConflict(
    row: Slot,
    evidence: ReplicaRegistrationEvidence,
  ): Promise<Attempt> {
    const manifest = await query(manifestOf(row.slot));
    const id = canonicalJson([manifest.writer, manifest.batch]);
    const record = factOf(row, evidence, manifest);
    return {
      outcome: quarantine("immutable_registration_conflict", row.slot),
      plan: function* () {
        if (record) yield* record();
        const decision = yield* receiver.copies.decide(id, {
          attempts: 0,
          budget: deps.refetchBudget ?? REPLICA_REFETCH_BUDGET,
        });
        if (decision.kind !== "terminal")
          return { tag: "retry", problem: "commitment_mismatch" };
        yield* receiver.copies.apply({
          credential: deps.credential,
          id,
          decision,
        });
        yield* quarantineWriterFrom(manifest.writer, manifest.sequence);
        return quarantine("finalized_conflict", id);
      },
    };
  }
  const revalidate: Handler<Item<Slot>> = {
    phase: "revalidate",
    due(e, limit) {
      // Round-robin by last check, so a fixed prefix cannot starve later slots.
      return then(
        query(
          sql.all<Slot>(
            `SELECT slot,scope,version,writer,data_hash,metadata_hash,attempts,next_attempt,wait_since,checked_block FROM pdpp_transport_manifests_in WHERE state='imported' AND ${due(e)} ORDER BY evidence_checked,rowid LIMIT ?`,
            limit.total,
          ),
        ),
        (rows) => rows.map(slotItem("revalidate")),
      );
    },
    async run(item, signal) {
      const row = item.row;
      const slot: ReplicaSlot = {
        owner: owner(),
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
        if (status === "conflict") return await importedConflict(row, evidence);
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
    commit: commitIn(function* (outcome, work, item) {
      const checked = (yield* sql.get<{ value: number }>(
        "SELECT COALESCE(MAX(evidence_checked),0) AS value FROM pdpp_transport_manifests_in WHERE state='imported'",
      ))!.value;
      const interval = deps.revalidateIntervalMs ?? 0;
      // A revalidated slot is never terminal: it is checked again on the sweep interval.
      const next =
        outcome.tag === "progress"
          ? { ...work, nextEligible: now() + interval }
          : work;
      if (outcome.tag === "quarantine")
        yield* sql.run(
          `UPDATE pdpp_transport_manifests_in SET ${QUARANTINE_SET("immutable_registration_conflict")} WHERE slot=? AND state='imported'`,
          item.id,
        );
      else
        yield* sql.run(
          `UPDATE pdpp_transport_manifests_in SET ${WORK_SET},evidence_checked=? WHERE slot=?`,
          ...workValues(outcome, next),
          checked + 1,
          item.id,
        );
    }),
    commitProblem: "evidence_unavailable",
    earliest(e) {
      // A sweep on the host's cadence: only Retry and Wait are deadlines.
      return query(
        earliestIn(
          e,
          "pdpp_transport_manifests_in WHERE state='imported' AND outcome IN ('retry','wait')",
        ),
      );
    },
  };

  // --------------------------------------------------------------- import
  type Refetch = { attempts: number; budget: number };
  type Group = Work & {
    slot: string;
    version: number;
    writer: string;
    batch: string;
    sequence: number;
  };
  /** Ordered verified fragments of one complete slot, read one row at a time. */
  async function retainedBytes(
    slot: string,
    admission?: Admission,
    signal?: AbortSignal,
    reservationGroup?: object,
  ) {
    const positions = await query(
      sql.all<{ position: number; bytes: number }>(
        "SELECT position,bytes FROM pdpp_transport_fragments_in WHERE slot=? ORDER BY position",
        slot,
      ),
    );
    return () =>
      assembleReplicaStream(
        async function* () {
          for (const row of positions) {
            const reservation = admission?.reserveObject(
              row.bytes,
              reservationGroup,
            );
            try {
              if (admission && typeof reservation !== "function")
                throw new ReplicaResourceBusyError();
              yield JSON.parse(
                await query(fragmentJson(slot, row.position)),
              ) as ReplicaFragment;
            } finally {
              if (typeof reservation === "function") reservation();
            }
          }
        },
        {
          ...(admission && { maxBytes: admission.payloadBytes }),
          ...(signal && { signal }),
        },
      );
  }
  /**
   * Fail closed at writer scope (contract H): every retained slot of the
   * writer from `sequence` on leaves import and revalidation.
   */
  function quarantineWriterFrom(slotWriter: string, sequence: number) {
    return sql.run(
      `UPDATE pdpp_transport_manifests_in SET ${QUARANTINE_SET("finalized_conflict")} WHERE writer=? AND sequence>=?`,
      slotWriter,
      sequence,
    );
  }
  /** Durable acknowledgement of an imported batch, and its successor's wake. */
  function* acknowledge(group: Group, manifest: ReplicaManifest): Fx<void> {
    if (
      !(yield* sql.get(
        "SELECT 1 FROM pdpp_transport_imported WHERE writer=? AND batch=?",
        group.writer,
        group.batch,
      ))
    )
      yield* sql.run(
        "INSERT INTO pdpp_transport_imported VALUES (?,?,?,?)",
        group.writer,
        group.batch,
        manifest.sequence,
        manifest.digest,
      );
    yield* sql.run(
      "UPDATE pdpp_transport_manifests_in SET state='imported',error=NULL WHERE slot=?",
      group.slot,
    );
    // The receiver retains its own copy: the fragment bodies are scratch now.
    yield* dropFragments(group.slot);
    yield* wake(`predecessor:${group.writer}:${manifest.sequence}`, now());
  }
  /**
   * The copy decision for one complete download of a batch (contract v3.1
   * §3 "Coordinator step"). Runs inside the import outcome transaction, over
   * the durable copies, facts and disposition it commits with.
   */
  function* decideImport(
    group: Group,
    manifest: ReplicaManifest,
    stage: ((refetch: Refetch) => Fx<void>) | undefined,
  ): Fx<ReplicaPhaseOutcome> {
    const { writer: groupWriter, batch } = group;
    const id = canonicalJson([groupWriter, batch]);
    const key = `${groupWriter}:${batch}`;
    const credential = deps.credential;
    yield* sql.run(
      "INSERT INTO pdpp_transport_import_work (writer,batch,sequence) VALUES (?,?,?) ON CONFLICT(writer,batch) DO NOTHING",
      groupWriter,
      batch,
      group.sequence,
    );
    const refetch: Refetch = {
      attempts: (yield* sql.get<{ refetch_attempts: number }>(
        "SELECT refetch_attempts FROM pdpp_transport_import_work WHERE writer=? AND batch=?",
        groupWriter,
        batch,
      ))!.refetch_attempts,
      budget: deps.refetchBudget ?? REPLICA_REFETCH_BUDGET,
    };
    if (stage) yield* stage(refetch);
    const decision = yield* receiver.copies.decide(id, refetch);
    function* terminal(): Fx<ReplicaPhaseOutcome> {
      yield* quarantineWriterFrom(groupWriter, manifest.sequence);
      return quarantine("finalized_conflict", id);
    }
    const progress: ReplicaPhaseOutcome = {
      tag: "progress",
      receipt: { phase: "import", key },
    };
    switch (decision.kind) {
      case "terminal":
        yield* receiver.copies.apply({ credential, id, decision });
        return yield* terminal();
      case "wait":
        yield* receiver.copies.apply({ credential, id, decision });
        return { tag: "wait", dependency: { kind: "fragments", key } };
      case "owner":
        yield* receiver.copies.apply({ credential, id, decision });
        return { tag: "wait", dependency: { kind: "owner", key } };
      case "refetch": {
        // One completed non-matching observation spends one unit of budget,
        // in the transaction that commits it; a discarded attempt spends none.
        yield* receiver.copies.apply({ credential, id, decision });
        yield* sql.run(
          "UPDATE pdpp_transport_import_work SET refetch_attempts=refetch_attempts+1 WHERE writer=? AND batch=?",
          groupWriter,
          batch,
        );
        const at = now() + defaultReplicaBackoff(refetch.attempts + 1);
        yield* dropFragments(group.slot);
        yield* sql.run(
          `UPDATE pdpp_transport_manifests_in SET manifest_json=NULL,data_hash=NULL,metadata_hash=NULL,batch=NULL,sequence=NULL,state='ready',${RESET_WORK},next_attempt=? WHERE slot=?`,
          at,
          group.slot,
        );
        return { tag: "wait", dependency: { kind: "fragments", key } };
      }
      case "reconcile_promoted":
        yield* receiver.copies.apply({ credential, id, decision });
        yield* acknowledge(group, manifest);
        return progress;
      case "promote": {
        const result = yield* receiver.copies.promote({
          credential,
          id,
          copyKey: decision.copyKey,
        });
        if (result.kind === "terminal") return yield* terminal();
        if (result.kind === "wait_predecessor")
          return {
            tag: "wait",
            dependency: {
              kind: "predecessor",
              key: `${groupWriter}:${manifest.sequence - 1}`,
            },
          };
        // Operations under a missing or incompatible declaration are now
        // retained but pending: reconcile reports them (host contract §4.5).
        // A compatible version applies with the batch and needs no reconcile.
        const untrusted = unretainedDeclarations(
          (yield* replicaCopyEnvelope<C>(id, decision.copyKey)).operations,
        ).find((entry) => entry.status !== "compatible");
        if (untrusted)
          yield* wakeReconcile(
            `declaration:${untrusted.sourceId}:${untrusted.binding.stream}`,
            now(),
          );
        yield* acknowledge(group, manifest);
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
  ): (() => Fx<boolean>) | undefined {
    const chain = evidence.chain;
    if (
      !chain ||
      chain.owner.toLowerCase() !== owner().toLowerCase() ||
      chain.scope !== row.scope ||
      chain.version !== String(row.version) ||
      !/^(0|[1-9][0-9]*)$/.test(chain.currentVersion)
    )
      return undefined;
    const { writer: factWriter, batch } = manifest;
    return function* () {
      const added = yield* receiver.copies.recordFact({
        credential: deps.credential,
        id: canonicalJson([factWriter, batch]),
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
              owner: owner(),
              scope: row.scope,
              version: row.version,
            }) === "confirmed",
        },
      });
      if (added) {
        yield* wake(`fragments:${factWriter}:${batch}`, now());
        yield* wake(`owner:${factWriter}:${batch}`, now());
      }
      return added;
    };
  }
  const importRun: Handler<Item<Group>> = {
    phase: "import",
    due(e, limit) {
      // Slot metadata only: no fragment bodies from incomplete or other slots.
      return then(
        query(
          sql.all<Group>(
            `WITH complete AS (SELECT m.slot,m.version,m.writer,m.batch,m.sequence FROM pdpp_transport_manifests_in m WHERE m.state='ready' AND m.manifest_json IS NOT NULL
              AND NOT EXISTS (SELECT 1 FROM pdpp_transport_fragments_in f WHERE f.slot=m.slot AND (f.fragment_json IS NULL OR f.state<>'ready'))),
            candidates AS (SELECT c.slot,c.version,c.writer,c.batch,c.sequence,coalesce(w.attempts,0) AS attempts,coalesce(w.next_attempt,0) AS next_attempt,w.wait_since,w.checked_block FROM complete c LEFT JOIN pdpp_transport_import_work w ON w.writer=c.writer AND w.batch=c.batch WHERE w.writer IS NULL OR (${replicaEligibleAtSql(e, { outcome: "w.outcome", dependency: "w.dependency", next: "w.next_attempt", since: "w.wait_since", checked: "w.checked_block" })} <= ${e.now} AND coalesce(w.outcome,'') NOT IN ('quarantine','unsupported')))
            SELECT * FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY writer ORDER BY next_attempt,sequence,batch) AS writer_rank FROM candidates) WHERE writer_rank<=? ORDER BY writer_rank, writer<=?, writer, next_attempt, sequence, batch LIMIT ?`,
            limit.perWriter,
            limit.after ?? "",
            limit.total,
          ),
        ),
        (rows) =>
          rows.map((row): Item<Group> => ({
            id: `${row.writer}:${row.batch}`,
            phase: "import",
            writer: row.writer,
            state: workState(row),
            row,
          })),
      );
    },
    async run(item, signal) {
      const { writer: groupWriter, batch, slot } = item.row;
      const id = item.id;
      const pendingId = canonicalJson([groupWriter, batch]);
      const { manifest, hashes, imported, sequenceHolder } = await query(
        (function* () {
          const manifest = yield* manifestOf(slot);
          const hashes = (yield* sql.get<{
            data_hash: `0x${string}`;
            metadata_hash: `0x${string}`;
          }>(
            "SELECT data_hash,metadata_hash FROM pdpp_transport_manifests_in WHERE slot=?",
            slot,
          ))!;
          const imported = yield* sql.get<{ digest: string; sequence: number }>(
            "SELECT digest,sequence FROM pdpp_transport_imported WHERE writer=? AND batch=?",
            groupWriter,
            batch,
          );
          const sequenceHolder = yield* sql.get<{ batch: string }>(
            "SELECT batch FROM pdpp_transport_imported WHERE writer=? AND sequence=?",
            groupWriter,
            manifest.sequence,
          );
          return { manifest, hashes, imported, sequenceHolder };
        })(),
      );
      /** Terminal for this batch; the receiver drops any staged copy of it. */
      const refuse = (
        reason: ReplicaAuthorityRefusal | "batch_equivocation",
        receiverReason: string = reason,
      ) =>
        withPlan(quarantine(reason, id), function* () {
          yield* receiver.quarantine({
            credential: deps.credential,
            id: pendingId,
            reason: receiverReason,
          });
          yield* sql.run(
            `UPDATE pdpp_transport_manifests_in SET ${QUARANTINE_SET(reason)} WHERE slot=?`,
            slot,
          );
        });
      // A different batch reusing an imported writer sequence (or a changed
      // digest) is proven equivocation: terminal, never a hot retry.
      if (
        (imported &&
          (imported.digest !== manifest.digest ||
            imported.sequence !== manifest.sequence)) ||
        (sequenceHolder && sequenceHolder.batch !== batch)
      )
        return refuse("batch_equivocation", "batch equivocation");
      // Every import attempt asks the roster again, so a batch admitted at
      // download on an answer up to REPLICA_ROSTER_MAX_AGE_MS old is
      // revalidated before it is staged or promoted.
      const authorized = await authorizeManifest(manifest, item.row, signal);
      if (authorized.tag === "wait")
        return verdict(rosterWait(authorized.server));
      if (authorized.tag === "refused") return refuse(authorized.reason);
      const admitted = admit(
        manifest,
        resourceBudget,
        {
          repositoryId: await query(repositoryId()),
          owner: owner(),
          manifestDigest: manifest.digest,
        },
        resourceLimits,
      );
      if ("kind" in admitted) {
        if (admitted.kind === "resource_busy")
          return verdict({ tag: "retry", problem: "resource_busy" });
        return withPlan(
          {
            tag: "unsupported",
            admission: {
              reason: "resource_unsupported",
              limit: admitted.limit,
              limitsVersion: admitted.limitsVersion,
            },
          },
          () =>
            sql.run(
              `UPDATE pdpp_transport_manifests_in
               SET resource_limits_version=? WHERE slot=?`,
              admitted.limitsVersion,
              slot,
            ),
        );
      }
      const admission = admitted;
      let stageStore: ReplicaEngineStaging<C> | undefined;
      const stagedObjects = new Map<
        number,
        ReplicaEngineStagedWriter<unknown>
      >();
      /**
       * Copy custody of this download, if its copy is not retained yet. It
       * commits only inside this attempt's outcome transaction, so a crash
       * or a discarded attempt never leaves custody without its outcome.
       */
      let stage: ((refetch: Refetch) => Fx<void>) | undefined;
      let keepForPlan = false;
      let transferEnvelopeReservations = false;
      const envelopeReservations: (() => void)[] = [];
      const envelopeReservationGroup = {};
      // A batch's one registered slot is its copy's one commitment.
      const fragments = [
        {
          dataHash: hashes.data_hash.toLowerCase(),
          metadataHash: hashes.metadata_hash.toLowerCase(),
        },
      ];
      try {
        // Keep both fallible staging calls before the first byte reservation.
        stageStore = await stagingStore();
        await stageStore.reclaimAdmission(admission);
        const currentStageStore = stageStore;
        const target = (blobIndex: number) => {
          let staged = stagedObjects.get(blobIndex);
          if (!staged) {
            staged = currentStageStore.begin(admission);
            stagedObjects.set(blobIndex, staged);
          }
          return staged;
        };
        const copyKey = replicaCopyKey([
          replicaChainCommitment(hashes.data_hash, hashes.metadata_hash),
        ]);
        const retained = (await query(receiver.copies.list(pendingId))).some(
          (copy) => copy.copyKey === copyKey,
        );
        if (!retained) {
          const payload = await inspectReplicaPayload(
            await retainedBytes(
              slot,
              admission,
              signal,
              envelopeReservationGroup,
            ),
            undefined,
            (_blobId, chunk, blobIndex) => target(blobIndex).write(chunk),
            {
              limits: streamedLimits,
              signal,
              reserveEnvelopeBytes: (bytes) => {
                const reservation = admission.reserveEnvelope(
                  bytes,
                  envelopeReservationGroup,
                );
                if (typeof reservation !== "function")
                  throw new ReplicaResourceBusyError();
                envelopeReservations.push(reservation);
              },
            },
          );
          // A discarded attempt stops before it prepares any custody.
          signal.throwIfAborted();
          if (payload.envelope.batchId !== manifest.batch)
            throw new ReplicaProblemError("payload_invalid");
          // Check 7: every operation names the signer's operation writer.
          const misattributed = replicaOperationWriterRefusal(
            payload.envelope.operations,
            authorized.writers,
          );
          if (misattributed) return refuse(misattributed);
          // Trusted retained declarations, never claims copied from the
          // envelope. An operation under a declaration this host does not
          // retain (another version of a retained stream, a stream it does
          // not declare yet, or an incompatible shape) is retained without
          // trust, and the merge decides it. It must not stop the writer's
          // chain, or one upgrade would hold back every later batch of that
          // writer (host contract §4.5).
          const expected = deps.expected();
          const unretained = unretainedDeclarations(
            payload.envelope.operations,
          );
          // Decoded only for shape; trust is decided by the merge.
          decodeReplicaEnvelope(canonicalJson(payload.envelope), {
            owner: expected.owner,
            declarations: [...expected.declarations, ...unretained],
          });
          const stagedBlobs: {
            blobId: string;
            handle: unknown;
            expected: (typeof payload.blobs)[number];
            sizeBytes: number;
          }[] = [];
          for (const [index, blob] of payload.blobs.entries()) {
            const handle = await target(index).complete();
            await currentStageStore.verify(handle, blob);
            stagedBlobs.push({
              blobId: blob.blobId,
              handle,
              expected: blob,
              sizeBytes: blob.sizeBytes,
            });
          }
          stage = function* (refetch) {
            const attached: {
              blobId: string;
              key: string;
              sizeBytes: number;
            }[] = [];
            for (const blob of stagedBlobs)
              attached.push({
                blobId: blob.blobId,
                key: yield* currentStageStore.attach(
                  blob.handle,
                  blob.expected,
                ),
                sizeBytes: blob.sizeBytes,
              });
            yield* receiver.copies.stage({
              credential: deps.credential,
              copy: {
                id: pendingId,
                writer: groupWriter,
                batch,
                sequence: manifest.sequence,
                previous: manifest.previous,
                envelopeDigest: manifest.digest,
                envelope: payload.envelope,
                fragments,
              },
              stagedBlobs: attached,
              refetch,
            });
          };
          keepForPlan = true;
        }
        const plan = stage;
        // The copy decision runs inside the outcome transaction, over the
        // durable copies, facts and disposition it commits with.
        transferEnvelopeReservations = true;
        return {
          outcome: {
            tag: "progress",
            receipt: { phase: "import", key: id },
          },
          plan: () => decideImport(item.row, manifest, plan),
          release: () => {
            for (const release of envelopeReservations) release();
          },
        };
      } catch (error) {
        stage = undefined;
        keepForPlan = false;
        if (error instanceof ReplicaResourceBusyError)
          return verdict({ tag: "retry", problem: "resource_busy" });
        if (error instanceof ReplicaResourceLimitError) {
          return withPlan(
            {
              tag: "unsupported",
              admission: {
                reason: "resource_unsupported",
                limit: error.limit,
                limitsVersion: REPLICA_LIMITS_VERSION,
              },
            },
            () =>
              sql.run(
                `UPDATE pdpp_transport_manifests_in
                 SET resource_limits_version=? WHERE slot=?`,
                REPLICA_LIMITS_VERSION,
                slot,
              ),
          );
        }
        return verdict(retryFromError(error, "import_failed"));
      } finally {
        // A completed but uncommitted handle is a leased orphan after a crash.
        try {
          if (!keepForPlan) await stageStore?.abort(admission);
        } finally {
          if (!transferEnvelopeReservations)
            for (const release of envelopeReservations) release();
        }
      }
    },
    commit: commitIn(function* (outcome, work, item) {
      yield* sql.run(
        "INSERT INTO pdpp_transport_import_work (writer,batch,sequence) VALUES (?,?,?) ON CONFLICT(writer,batch) DO NOTHING",
        item.row.writer,
        item.row.batch,
        item.row.sequence,
      );
      yield* sql.run(
        `UPDATE pdpp_transport_import_work SET ${WORK_SET} WHERE writer=? AND batch=?`,
        ...workValues(outcome, work),
        item.row.writer,
        item.row.batch,
      );
    }),
    commitProblem: "import_failed",
    earliest(e) {
      return query(
        earliestIn(
          e,
          "pdpp_transport_import_work WHERE coalesce(outcome,'') NOT IN ('progress','quarantine','unsupported')",
        ),
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
  function* dependencyFingerprint(): Fx<string> {
    const bindings = yield* host.bindings();
    const declarations = deps
      .expected()
      .declarations.map((d) => [d.sourceId, d.binding.digest, d.binding.stream])
      .sort();
    return bytesToHex(
      sha256(encoder.encode(canonicalJson({ bindings, declarations }))),
    );
  }
  let fingerprint = "";
  /**
   * What this device's own operations may name: the host's trusted set plus
   * every binding it retained, and a version of a retained stream that a
   * rebaseline copied from a peer's operation (`resolveDeclaration`
   * compatible). A missing or incompatible binding is never published.
   */
  function ownBindings(
    operations: readonly ReplicaOperation[],
    history: EnvelopeExpectation["declarations"],
  ): EnvelopeExpectation {
    const expected = deps.expected();
    const retained = [...expected.declarations, ...history];
    return {
      owner: expected.owner,
      declarations: [
        ...retained,
        ...operations.flatMap((op) =>
          "declaration" in op &&
          resolveDeclaration(retained, op.sourceId, op.declaration).status ===
            "compatible"
            ? [{ sourceId: op.sourceId, binding: op.declaration }]
            : [],
        ),
      ],
    };
  }
  /**
   * The declarations operations name that the host does not retain, with how
   * the merge resolves each (`resolveDeclaration`).
   */
  function unretainedDeclarations(operations: readonly ReplicaOperation[]) {
    const retained = deps.expected().declarations;
    return operations.flatMap((op) => {
      if (!("declaration" in op)) return [];
      const { status } = resolveDeclaration(
        retained,
        op.sourceId,
        op.declaration,
      );
      return status === "retained"
        ? []
        : [{ sourceId: op.sourceId, binding: op.declaration, status }];
    });
  }
  /**
   * Bring the reconcile phase forward to `at`. A declaration notification can
   * change validation of any retained operation; other keys matter only when
   * they are what it waits on. Returns how many phases it woke.
   */
  function* wakeReconcile(key: string, at: number): Fx<number> {
    const row = yield* singleton("reconcile");
    const outstanding = (yield* sql.get<{ dependency: string | null }>(
      "SELECT dependency FROM pdpp_transport_phase_state WHERE phase='reconcile'",
    ))?.dependency;
    if (
      row.next_attempt <= at ||
      (!key.startsWith("declaration:") && key !== outstanding)
    )
      return 0;
    yield* sql.run(
      "UPDATE pdpp_transport_phase_state SET next_attempt=? WHERE phase='reconcile'",
      at,
    );
    return 1;
  }
  /** The first unmet dependency a reconcile reported, in a stable order. */
  function pendingDependency(
    plan: Pick<ReplicaMergePlan, "pending">,
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
        // This device retains another shape of that stream, and a rebinding
        // cannot change a retained shape: only the owner can resolve it.
        else if (
          issue.reason === "incompatible_declaration" &&
          "declaration" in op
        )
          found.push({
            kind: "owner",
            key: `declaration:${op.sourceId}:${op.declaration.stream}`,
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
   * Whether the reconcile phase runs now, and whether it starts a new pass.
   * A Retry inside an open pass keeps its backoff and then continues the
   * pass; a changed fingerprint or a due Wait starts a new one.
   */
  function* reconcileDue(
    row: SingletonRow,
    e: ReplicaEligibility,
  ): Fx<{ restart: boolean; run: boolean }> {
    const eligible = (singletonEligibleAt(row, e) ?? Infinity) <= e.now;
    const retrying = row.outcome === "retry";
    if (row.fingerprint !== fingerprint) return { restart: true, run: true };
    if (retrying && !eligible) return { restart: false, run: false };
    const resume = retrying && (yield* openPass()) !== undefined;
    if (eligible && !resume) return { restart: true, run: true };
    return {
      restart: false,
      run: resume || (yield* receiver.reconcileQueued()),
    };
  }
  /** The dependency a pass reported so far; absent when no pass is open. */
  function* openPass(): Fx<
    { dependency: ReplicaDependency | null } | undefined
  > {
    const row = yield* sql.get<{ dependency_json: string | null }>(
      "SELECT dependency_json FROM pdpp_transport_reconcile_pass WHERE id=1",
    );
    return (
      row && {
        dependency: row.dependency_json && JSON.parse(row.dependency_json),
      }
    );
  }
  /**
   * Canonical reconcile of retained history, in bounded pages. A full pass
   * starts only when a dependency changed: the fingerprint moved, a host
   * notification woke it, or an outstanding Wait reached its bounded
   * fallback. Each attempt then does one page, and the phase stays due while
   * the receiver has queued work. With nothing queued and nothing
   * outstanding it is never due on a timer, and its probe reads no retained
   * history.
   */
  const reconcile: Handler<Item<Work> & { restart: boolean }> = {
    phase: "reconcile",
    due(e) {
      return query(
        (function* () {
          const row = yield* singleton("reconcile");
          const { restart, run } = yield* reconcileDue(row, e);
          return run
            ? [
                {
                  id: "reconcile",
                  phase: "reconcile" as const,
                  writer: "",
                  state: workState(row),
                  row,
                  restart,
                  bytes: reconcilePage.bytes,
                },
              ]
            : [];
        })(),
      );
    },
    async run(item) {
      const release = resourceBudget.reserve(
        reconcilePage.bytes * REPLICA_ENVELOPE_LIVE_COPY_FACTOR,
      );
      if (typeof release !== "function")
        return { outcome: { tag: "retry", problem: "resource_busy" } };
      // The canonical commit runs inside this attempt's outcome transaction:
      // the plan reconciles one page and returns the verdict it implies.
      const seen = fingerprint;
      return {
        outcome: {
          tag: "progress",
          receipt: { phase: "reconcile", key: seen },
        },
        plan: function* () {
          const { plan, complete } = yield* receiver.reconcileStep({
            credential: deps.credential,
            page: reconcilePage,
            restart: item.restart,
          });
          const pass = item.restart ? { dependency: null } : yield* openPass();
          if (!pass) return undefined; // Evidence work outside a pass waits on nothing.
          const dependency = [pass.dependency, pendingDependency(plan)]
            .filter((found): found is ReplicaDependency => !!found)
            .sort((x, y) =>
              dependencyKey(x).localeCompare(dependencyKey(y)),
            )[0];
          if (!complete) {
            yield* sql.run(
              "INSERT INTO pdpp_transport_reconcile_pass VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET dependency_json=excluded.dependency_json",
              dependency ? JSON.stringify(dependency) : null,
            );
            return undefined;
          }
          yield* sql.run("DELETE FROM pdpp_transport_reconcile_pass");
          return dependency
            ? ({ tag: "wait", dependency } as const)
            : undefined;
        },
        release,
      };
    },
    commit: commitIn((outcome, work) =>
      settleSingleton(
        "reconcile",
        outcome,
        // With nothing outstanding it waits for a dependency change only;
        // queued pages keep it due without a timer.
        outcome.tag === "progress"
          ? { ...work, nextEligible: REPLICA_TERMINAL }
          : work,
        fingerprint,
      ),
    ),
    commitProblem: "reconcile_failed",
    earliest(e) {
      return query(
        (function* () {
          const row = yield* singleton("reconcile");
          if (row.fingerprint !== fingerprint) return e.now;
          // Queued pages are due now, unless a Retry is backing off.
          if (row.outcome !== "retry" && (yield* receiver.reconcileQueued()))
            return e.now;
          return singletonEligibleAt(row, e);
        })(),
      );
    },
    wake: (key, at) => query(wakeReconcile(key, at)),
  };

  const coordinator = createAsyncReplicaCoordinator({
    state: host.coordinatorState({
      owner: () => coordinatorOwner,
      signal: () => activeStepSignal,
      enabled,
    }),
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
    ],
    quantum: {
      retain: 1,
      // One prepare unit is one fragment, as for publish and fetch.
      prepare: 50,
      publish: 50,
      discover: 1,
      fetch: 50,
      revalidate: 50,
      import: 50,
      reconcile: 1,
      ...deps.quantum,
      // A host may reduce this quantum, but a deep inbox cannot remove the
      // per-step memory bound by increasing it (even to Infinity).
      download: Math.min(50, deps.quantum?.download ?? 50),
    },
    perWriter: deps.perWriter,
    deadlineMs: deps.deadlineMs ?? REPLICA_RECEIVE_TIMEOUT_MS,
    background: ["revalidate"],
    clock: now,
    ...(transport.finality && {
      hint: {
        head: (signal: AbortSignal) =>
          abortable(signal, () => transport.finality!.head()),
      },
    }),
  });

  let running = false;
  const idle = (): ProgressReport => ({
    receipts: [],
    waits: [],
    problems: [],
    quarantines: [],
    unsupported: [],
    nextWake: undefined,
  });

  /**
   * The host's step({now,budget,signal}). The optional clock and budget use
   * finite host defaults; this is not a whole-I/O/history bound. The
   * authority context is validated before any phase; a mismatch rejects the
   * step without encrypt, network or receiver calls.
   */
  async function step(
    input: { now?: number; budget?: ReplicaBudget; signal?: AbortSignal } = {},
  ): Promise<ProgressReport> {
    if (isPromiseLike(ready)) await ready;
    const context = {
      now: input.now ?? now(),
      // Bytes omitted: the coordinator's 64 MiB default, under which a batch
      // larger than the whole budget still runs alone.
      budget: input.budget ?? { units: 256 },
      signal: input.signal,
    };
    validateReplicaStep(context);
    // A closed door stops replication for good: no identity, capture or
    // publish work.
    if (!enabled() || running || host.lock.busy() || !door.admitted())
      return idle();
    const lifetime = door.beginStep(input.signal);
    let writerToken: string | undefined;
    try {
      if (lifetime.signal.aborted) return idle();
      // Writer ids come from this server's signed registration. Until it is
      // registered under the owner, no replication phase runs. The same
      // lifetime signal also stops this read if the door closes mid-step.
      running = true;
      let own;
      try {
        own = await host.identity.enable({
          owner: deps.expected().owner,
          server,
          roster,
          signal: lifetime.signal,
        });
      } finally {
        running = false;
      }
      if (lifetime.signal.aborted || own.tag === "refused") return idle();
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
      writerToken = host.randomId();
      // Claimed before the lock, so no second step starts while it is taken.
      running = true;
      await host.lock.acquire(writerToken);
      coordinatorOwner = writerToken;
      activeStepSignal = lifetime.signal;
      // Under the writer lock: a new identity resets its chain transactionally.
      const authorized = await authority(own.identity);
      if (!authorized) return idle();
      bound = authorized;
      const stagedObjects = await stagingStore(false);
      await stagedObjects.cleanup();
      await stagedObjects.cleanupAttachedTemporaryBytes();
      // Only this process owns the worker. None of these hidden stages can be published.
      await atomic(
        (function* () {
          yield* sql.run("DELETE FROM pdpp_transport_staged_fragments");
          yield* host.sweepStages();
          for (const table of ["pdpp_binary_chunks", "pdpp_binary_manifests"])
            yield* sql.run(
              `DELETE FROM ${table} WHERE namespace='payload' AND NOT EXISTS (SELECT 1 FROM pdpp_transport_batches b WHERE b.batch=${table}.blob_id)`,
            );
          yield* sweepPublished();
          if (host.compactCanonical)
            yield* host.compactCanonical(
              Math.min(
                4 * 1024 * 1024,
                Math.floor((context.budget.bytes ?? REPLICA_STEP_BYTES) / 4),
              ),
            );
        })(),
      );
      const current = await query(dependencyFingerprint());
      if (current !== fingerprint) {
        fingerprint = current;
        await query(
          sql.run(
            "UPDATE pdpp_transport_import_work SET next_attempt=? WHERE outcome='wait' AND (dependency LIKE 'mapping:%' OR dependency LIKE 'declaration:%') AND next_attempt>?",
            now(),
            now(),
          ),
        );
      }
      const report = await coordinator.step({
        ...context,
        signal: lifetime.signal,
      });
      const diagnosticRoom = () =>
        REPLICA_REPORT_LIMIT -
        report.receipts.length -
        report.waits.length -
        report.problems.length -
        report.quarantines.length -
        report.unsupported.length;
      const { waits, recoveries } = await query(
        (function* () {
          const waits = yield* sql.all<{ batch: string; wait_json: string }>(
            "SELECT batch,wait_json FROM pdpp_transport_preparation WHERE wait_json IS NOT NULL ORDER BY batch LIMIT ?",
            REPLICA_REPORT_LIMIT + 1,
          );
          const recoveries = yield* sql.all<{
            batch: string;
            state: "own_key_conflict" | "version_squat";
          }>(
            "SELECT batch,state FROM pdpp_transport_registration_recovery WHERE state IN ('own_key_conflict','version_squat') ORDER BY batch LIMIT ?",
            REPLICA_REPORT_LIMIT + 1,
          );
          return { waits, recoveries };
        })(),
      );
      for (const row of waits) {
        if (diagnosticRoom() <= 0) {
          report.diagnosticsTruncated = true;
          break;
        }
        const wait = JSON.parse(row.wait_json) as Extract<
          ReplicaPhaseOutcome,
          { tag: "wait" }
        >;
        if (
          !report.waits.some(
            (entry) => entry.id === row.batch && entry.phase === "prepare",
          )
        )
          report.waits.push({
            id: row.batch,
            phase: "prepare",
            dependency: wait.dependency,
          });
      }
      for (const row of recoveries) {
        if (diagnosticRoom() <= 0) {
          report.diagnosticsTruncated = true;
          break;
        }
        if (
          !report.waits.some(
            (entry) =>
              entry.phase === "publish" &&
              entry.dependency.kind === "registration" &&
              entry.dependency.reason === row.state,
          )
        )
          report.waits.push({
            id: row.batch,
            phase: "publish",
            dependency: {
              kind: "registration",
              key: writer(),
              reason: row.state,
            },
          });
      }
      return report;
    } finally {
      lifetime.close();
      activeStepSignal = undefined;
      coordinatorOwner = undefined;
      bound = undefined;
      running = false;
      if (writerToken) await host.lock.release(writerToken);
    }
  }
  return {
    ready,
    step,
    /** Owner acknowledgement resumes an exhausted writer after its wait and recovery window. */
    retryVersionSquats() {
      return then(ready, () => {
        if (!enabled() || !door.admitted()) return 0;
        return atomic(
          (function* () {
            if (!enabled() || !door.admitted()) return 0;
            return (yield* sql.run(
              `UPDATE pdpp_transport_registration_recovery SET state='resigning'
          WHERE state='version_squat' AND batch IN (SELECT m.batch FROM pdpp_transport_manifests_out m
            WHERE m.next_attempt<=? AND (SELECT count(*) FROM pdpp_transport_version_squats s WHERE s.scope=m.scope AND s.detected_at>=?)<?)`,
              now(),
              now() - REPLICA_VERSION_SQUAT_WINDOW_MS,
              REPLICA_VERSION_SQUAT_ATTEMPTS,
            )).changes;
          })(),
        );
      });
    },
    /** Legacy entry point: one finite default step. Rejects when a whole phase failed. */
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
    readmitUnsupported() {
      return then(ready, () => {
        if (!enabled() || !door.admitted()) return 0;
        return atomic(
          (function* () {
            if (!enabled() || !door.admitted()) return 0;
            // One outstanding admission at a time also permits a repeated framing
            // refusal to release its unused wire slot before another batch claims it.
            const row = yield* sql.get<{ batch: string }>(
              `SELECT batch FROM pdpp_transport_batches
          WHERE prepared=-1 AND coalesce(json_extract(admission_json,'$.capability'),'')<>? ORDER BY sequence LIMIT 1`,
              `cap:${cap}`,
            );
            return row && (yield* reserveReadmission(row.batch)) ? 1 : 0;
          })(),
        );
      });
    },
    /**
     * Owner decision after storage was repaired: fetch again every slot that
     * was quarantined for a missing or mismatched fragment. The finalized
     * manifest still decides which bytes are accepted. Returns the number of
     * slots re-admitted.
     */
    readmitFragments() {
      return then(ready, () =>
        deferred(
          (function* () {
            const reasons = "('fragment_missing','fragment_mismatch')";
            const slots = (yield* sql.all<{ slot: string }>(
              `SELECT slot FROM pdpp_transport_manifests_in WHERE state='quarantined' AND reason IN ${reasons}`,
            )).map((r) => r.slot);
            for (const slot of slots) {
              yield* sql.run(
                "DELETE FROM pdpp_transport_fragment_parts WHERE slot=? AND position IN (SELECT position FROM pdpp_transport_fragments_in WHERE slot=? AND state='quarantined')",
                slot,
                slot,
              );
              yield* sql.run(
                `UPDATE pdpp_transport_fragments_in SET state='ready',fragment_json=NULL,${RESET_WORK},next_attempt=0 WHERE slot=? AND state='quarantined'`,
                slot,
              );
              yield* sql.run(
                `UPDATE pdpp_transport_manifests_in SET state='ready',${RESET_WORK},next_attempt=0 WHERE slot=?`,
                slot,
              );
            }
            return slots.length;
          })(),
        ),
      );
    },
    /** A host-observed dependency change (e.g. `mapping:<connection>`). Idempotent. */
    onDependencyChanged(key: string) {
      return then(ready, () =>
        then(query(wake(key, now())), (woken) =>
          then(
            coordinator.onDependencyChanged(key, now()),
            (phases) => woken + phases,
          ),
        ),
      );
    },
  };
}
