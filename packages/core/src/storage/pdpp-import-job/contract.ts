/**
 * PDPP import job contract, version 1. See docs/261028-pdpp-import-job.md.
 *
 * A connector run's records reach the canonical store through one job:
 * `begin`, then numbered `append` batches read from an immutable spool, then
 * `commit` (one atomic publication) or `abort`. A job may begin on a spool the
 * host is still writing (`ImportOpenSpoolHandle`), so batches stage while the
 * connector downloads; the batch that ends the spool seals it. The Personal Server engine
 * (`createPdppImportJobs`) owns every rule: owner and connection binding,
 * record identity, declaration checks, operation digests and idempotency.
 * A storage adapter implements `PdppImportJobCapability`; it only persists
 * what the engine decided and applies the staged operations at publication
 * through the host's existing ingest rules (`planIngest`).
 *
 * Browser-safe: no Node built-ins. Later changes to this file are additive.
 */

import type { DeclarationBinding } from "../../replication/envelope.js";
import type { StreamCompletionProof } from "../pdpp-records/completion.js";
import type { RecordDataValidator } from "../pdpp-records/ingest-plan.js";
import type { StreamSemantics } from "../pdpp-records/types.js";

/** The contract an adapter implements. The engine refuses any other value. */
export const PDPP_IMPORT_JOB_CONTRACT_VERSION = 1 as const;

/** Spool encoding: UTF-8, one JSON record object per `\n`-terminated line. */
export const PDPP_IMPORT_SPOOL_FORMAT = "pdpp-ndjson-v1" as const;

/** Default and largest batch budget, in UTF-8 bytes of batch text. */
export const IMPORT_JOB_DEFAULT_BATCH_BYTES = 1024 * 1024;
export const IMPORT_JOB_MAX_BATCH_BYTES = 4 * 1024 * 1024;
/**
 * Largest single record line. A batch may exceed the batch budget only when
 * it holds exactly one record no larger than this. A larger record fails the
 * batch with `record_too_large` before it is parsed.
 */
export const IMPORT_JOB_MAX_RECORD_BYTES = 16 * 1024 * 1024;
/**
 * Batches one job may have in flight, queued or running. Appends of one job
 * run one at a time; an append beyond this limit fails `job_busy` at once.
 */
export const IMPORT_JOB_MAX_IN_FLIGHT = 1;
/** Largest connector state committed with a job, in UTF-8 bytes. */
export const IMPORT_JOB_MAX_CONNECTOR_STATE_BYTES = 64 * 1024;
/** Rejections listed by reason in one batch receipt; the rest are counted. */
export const IMPORT_JOB_MAX_LISTED_REJECTIONS = 32;

/** Who may write: the server owner, through one connection's bound method and generation. */
export interface ImportJobBinding {
  /** The Personal Server owner, compared case-insensitively. */
  owner: string;
  /** The connection (PDPP instance) every record of the job belongs to. */
  instance: string;
  sourceId: string;
  method: string;
  /** Positive. A reset of the connection makes every open job of the old generation unpublishable. */
  generation: number;
}

/** An immutable host file of `PDPP_IMPORT_SPOOL_FORMAT` lines. */
export interface ImportSpoolHandle {
  /** Opaque host id. The bytes behind it never change. */
  id: string;
  format: typeof PDPP_IMPORT_SPOOL_FORMAT;
  byteLength: number;
  /** Lower-case hex SHA-256 of the whole spool, as the host computed it. */
  sha256: string;
}

/**
 * A spool the host is still writing. Bytes already written never change; the
 * length and digest are unknown until the batch that ends the spool carries
 * them (`ImportBatchInput.seal`). Until then every batch ends at a line break.
 */
export interface ImportOpenSpoolHandle {
  id: string;
  format: typeof PDPP_IMPORT_SPOOL_FORMAT;
  byteLength?: never;
  sha256?: never;
}

/** The length and digest that end an open spool. */
export type ImportSpoolSeal = Pick<ImportSpoolHandle, "byteLength" | "sha256">;

/** The spool's handle once its length and digest are known. */
export function sealedSpool(
  spool: ImportSpoolHandle | ImportOpenSpoolHandle,
): ImportSpoolHandle | undefined {
  return spool.byteLength === undefined ? undefined : spool;
}

/**
 * One spool line. `instance` is optional and, when present, must equal the
 * job's instance; the engine always stores the job's instance.
 */
export interface ImportSpoolRecord {
  stream: string;
  key: string | string[];
  data?: Record<string, unknown> | null;
  emitted_at: string;
  op?: "upsert" | "delete" | null;
  instance?: string;
}

export interface ImportJobBeginInput {
  /** Caller-chosen stable id, `[A-Za-z0-9._:-]{1,128}`. A retried begin reuses it. */
  jobId: string;
  binding: ImportJobBinding;
  spool: ImportSpoolHandle | ImportOpenSpoolHandle;
  /** Streams this job may write; each must be declared for the instance. */
  streams: string[];
  /** UTF-8 bytes per batch; default `IMPORT_JOB_DEFAULT_BATCH_BYTES`. */
  batchBytes?: number;
}

export type ImportJobState = "open" | "committed" | "aborted";

/** The durable job row. The engine computes every field; adapters store it verbatim. */
export interface ImportJobRecord {
  contractVersion: typeof PDPP_IMPORT_JOB_CONTRACT_VERSION;
  jobId: string;
  /** SHA-256 of the canonical begin input. A changed retry of the same id is refused. */
  fingerprint: string;
  binding: ImportJobBinding;
  /** Open until the batch that ends it is durable; a commit needs it sealed. */
  spool: ImportSpoolHandle | ImportOpenSpoolHandle;
  streams: string[];
  batchBytes: number;
  state: ImportJobState;
  /** The next batch number expected; also the count of durable batches. */
  nextSeq: number;
  /** The next staged operation order. */
  nextOrder: number;
  /** Spool bytes covered by durable batches: where a resumed run reads next. */
  spoolOffset: number;
  /** Record lines in durable batches. */
  records: number;
  /** Lines refused at append; they are never staged. */
  rejected: number;
  createdAt: string;
  updatedAt: string;
  abortReason?: string;
  commit?: ImportCommitReceipt;
}

export interface ImportBatchInput {
  jobId: string;
  /** From 0, consecutive. */
  seq: number;
  /** Exactly the spool bytes `[spoolStart, spoolEnd)`, whole lines only. */
  text: string;
  /** Lower-case hex SHA-256 of the UTF-8 bytes of `text`. */
  sha256: string;
  /** Must equal the job's `spoolOffset`. */
  spoolStart: number;
  spoolEnd: number;
  /**
   * Only on the batch that ends an open spool: its `byteLength` must equal
   * `spoolEnd`. The job stores the sealed handle with this batch. On a sealed
   * spool it must equal the stored length and digest.
   */
  seal?: ImportSpoolSeal;
}

export interface ImportRejection {
  /** 0-based line within the batch. */
  line: number;
  reason: string;
}

/** Durable idempotency receipt of one batch. A replay returns it unchanged. */
export interface ImportBatchReceipt {
  jobId: string;
  seq: number;
  sha256: string;
  spoolStart: number;
  spoolEnd: number;
  records: number;
  /** Operations handed to the adapter; at most one row per key survives in the job's index. */
  staged: number;
  rejectedCount: number;
  /** At most `IMPORT_JOB_MAX_LISTED_REJECTIONS` entries. */
  rejected: ImportRejection[];
  /** Order of this batch's first staged operation. */
  firstOrder: number;
}

/** One validated record operation, ready for the host's ingest rules. */
export interface ImportStagedOperation {
  /** Strictly increasing within a job, in spool order. */
  order: number;
  stream: string;
  /** `encodeRecordKey(key)`: the index key. */
  recordKey: string;
  /** `JSON.stringify(key)`: the envelope key handed to ingest at publication. */
  keyJson: string;
  op: "upsert" | "delete";
  /** `JSON.stringify(data)` for an upsert; null for a delete. */
  dataJson: string | null;
  emittedAt: string;
  /**
   * The latest-operation rule for the job's `(stream, recordKey)` index row:
   * `last` (mutable_state) replaces an existing row, `first` (append_only)
   * keeps it, because the first write of an append_only key stands.
   */
  keep: "first" | "last";
  /** Lower-case hex SHA-256 of `canonicalJson([stream, recordKey, op, data, emittedAt])`. */
  digest: string;
}

export interface ImportCompletionInput {
  /** UTC with exactly three fractional digits. */
  sourceCollectedAt: string;
  /** Proofs checked against the live set after publication, as `completeStreams` does. */
  streams: StreamCompletionProof[];
}

export interface ImportCommitInput {
  jobId: string;
  /** Durable batches the caller sent. Must equal the job's `nextSeq`. */
  batches: number;
  /** Opaque connector state (cursor) JSON text, stored with the data. */
  connectorState?: string;
  completion?: ImportCompletionInput;
}

/** What one publication did. A retried commit returns the stored receipt. */
export interface ImportCommitReceipt {
  jobId: string;
  contractVersion: typeof PDPP_IMPORT_JOB_CONTRACT_VERSION;
  instance: string;
  generation: number;
  batches: number;
  records: number;
  /** Net operations published (one per staged key). */
  operations: number;
  accepted: number;
  unchanged: number;
  /** Lines refused at append plus operations refused at publication. */
  rejected: number;
  completedStreams: string[];
  connectorStateSha256: string | null;
  committedAt: string;
}

/** The connector state of a connection, written only by a publication. */
export interface ImportConnectorState {
  instance: string;
  generation: number;
  jobId: string;
  state: string;
  committedAt: string;
}

/** The connection's binding as the store holds it now. */
export interface ImportBindingSnapshot {
  sourceId: string | null;
  method: string | null;
  generation: number;
  deleted: boolean;
}

/** Trusted declaration of one stream of one instance. Never built from a request. */
export interface ImportStreamDeclaration {
  semantics: StreamSemantics;
  primaryKey: string[];
  /** The retained binding replication captures with the write, when it does. */
  binding?: DeclarationBinding;
}

export interface ImportDeclarations {
  forInstance(
    instance: string,
    stream: string,
  ): ImportStreamDeclaration | undefined;
  /** Declared schema check for upsert data; null when it conforms. */
  validateData?: RecordDataValidator;
}

export interface ImportPublishInput {
  /** The job as the engine last read it. The adapter re-reads and re-checks it in the transaction. */
  job: ImportJobRecord;
  connectorState?: string;
  connectorStateSha256: string | null;
  completion?: ImportCompletionInput;
  committedAt: string;
  declarations: ImportDeclarations;
}

/**
 * The storage adapter capability. Every method is atomic on its own; none
 * may expose staged data to readers. Errors are `ImportJobError`s with the
 * listed codes, or the host's own binding/storage errors.
 */
/** One canonical key/value write of a native store. `value: null` deletes the key. */
export interface ImportCanonicalEntry {
  key: string;
  value: string | null;
}

/**
 * What a batch's canonical entries were encoded against: the value of one
 * canonical key (the Lite clock, which every record-writing commit advances)
 * as the encoder read it. A later batch reads it through the job's staged
 * entries, so batch 0's fence is the job's base.
 */
export interface ImportCanonicalFence {
  key: string;
  value: string | null;
}

/** One batch's encoded entries and the fence they hold only against. */
export interface ImportCanonicalBatch {
  entries: ImportCanonicalEntry[];
  fence: ImportCanonicalFence;
}

/**
 * How an adapter publishes. Absent means
 * `{ mode: "transactional-apply", outbox: "captured-in-transaction" }`, the
 * version 1 behaviour of the Node SQLite and memory adapters.
 */
export interface ImportPublicationProfile {
  /**
   * - `transactional-apply`: `publish` applies the staged index through the
   *   host's ingest rules inside one transaction (the `publish` steps below).
   * - `native-staged-copy`: `stageBatch` also stores the batch's encoded
   *   canonical entries (`canonical`) in an invisible staging table of the
   *   same database, in the same transaction as the receipt. `publish` is one
   *   native set-based copy (`INSERT … SELECT`) from that table into the
   *   canonical tables, together with connector state, completion receipts,
   *   the commit receipt and deletion of the staging rows. The copy never
   *   re-encodes; the engine requires `encodeBatch` for this mode. Entries
   *   encoded against an older canonical state would overwrite later writes,
   *   so `publish` refuses `canonical_moved` unless the committed value at
   *   batch 0's `fence.key` still equals its `fence.value` and no other
   *   canonical transaction committed since batch 0 was staged. The host
   *   aborts the job and starts it again.
   */
  mode: "transactional-apply" | "native-staged-copy";
  /**
   * - `captured-in-transaction`: replica capture writes its outbox rows, with
   *   their payloads, inside the publish transaction.
   * - `by-reference`: an outbox entry names the committed operation
   *   (`{ batchId, operationKey, sequence }` in the Lite canonical store) and
   *   never copies record bytes.
   */
  outbox: "captured-in-transaction" | "by-reference";
}

export interface PdppImportJobCapability {
  /** Must equal `PDPP_IMPORT_JOB_CONTRACT_VERSION`. */
  readonly contractVersion: number;
  readonly publication?: ImportPublicationProfile;
  readBinding(instance: string): Promise<ImportBindingSnapshot>;
  /** Insert if absent. Returns the stored row, which may be an older one with this id. */
  createJob(job: ImportJobRecord): Promise<ImportJobRecord>;
  readJob(jobId: string): Promise<ImportJobRecord | undefined>;
  /**
   * One transaction: apply `operations` to the job's latest-operation index
   * (`keep` decides a key collision), store `receipt`, store `job`. If a
   * receipt for `(jobId, seq)` exists, write nothing and return it. Refuse
   * with `job_not_open` / `batch_out_of_order` unless the stored job is open
   * and its `nextSeq` equals `receipt.seq`.
   */
  stageBatch(input: {
    job: ImportJobRecord;
    receipt: ImportBatchReceipt;
    operations: ImportStagedOperation[];
    /** Present exactly for `native-staged-copy`: store these in the same transaction. */
    canonical?: ImportCanonicalBatch;
  }): Promise<ImportBatchReceipt>;
  readBatchReceipt(
    jobId: string,
    seq: number,
  ): Promise<ImportBatchReceipt | undefined>;
  /**
   * One transaction, all or nothing:
   *  1. re-read the job; if committed, return its stored receipt and write nothing;
   *     refuse `job_not_open` if aborted, `batch_count_mismatch` if its
   *     `nextSeq` differs from `input.job.nextSeq`;
   *  2. check the binding (method, generation, not deleted) as ingest does;
   *  3. apply the index rows in ascending `order`, in bounded pages, through
   *     the host's ingest rules (`planIngest` against current rows), with the
   *     host's history, arrival and replication capture when enabled;
   *  4. check `completion` proofs against the resulting live set and store receipts;
   *  5. store `connectorState`, the commit receipt and `state: "committed"`;
   *  6. drop the job's index rows.
   * Pages bound memory; the transaction bounds visibility.
   */
  publish(input: ImportPublishInput): Promise<ImportCommitReceipt>;
  /** Drop the index rows and mark the job aborted. Idempotent; a committed job stays committed. */
  abort(
    jobId: string,
    reason: string,
    at: string,
  ): Promise<ImportJobRecord | undefined>;
  readConnectorState(
    instance: string,
  ): Promise<ImportConnectorState | undefined>;
  /**
   * Optional spool access: at most `maxBytes` bytes from `offset`. Fewer bytes
   * only at the end of the spool. Never reads the whole spool at once.
   */
  readSpool?(
    spool: ImportSpoolHandle | ImportOpenSpoolHandle,
    offset: number,
    maxBytes: number,
  ): Promise<Uint8Array>;
}

export type ImportJobErrorCode =
  | "capability_version_mismatch"
  | "invalid_request"
  | "owner_mismatch"
  | "binding_mismatch"
  | "stream_not_declared"
  | "job_conflict"
  | "job_not_found"
  | "job_not_open"
  | "batch_out_of_order"
  | "batch_conflict"
  | "batch_digest_mismatch"
  | "batch_too_large"
  | "record_too_large"
  | "spool_offset_mismatch"
  | "batch_count_mismatch"
  | "state_too_large"
  /** Commit before every spool byte is in a durable batch. */
  | "spool_incomplete"
  /** An append beyond `IMPORT_JOB_MAX_IN_FLIGHT`; retry after the pending one. */
  | "job_busy"
  /** A record with `data.blob_ref`; version 1 stages no blobs. */
  | "blob_ref_unsupported"
  /** A native staged copy whose canonical base moved after batch 0; abort and start again. */
  | "canonical_moved"
  | "completion_failed";

export class ImportJobError extends Error {
  constructor(
    readonly code: ImportJobErrorCode,
    message: string = code,
  ) {
    super(message);
    this.name = "ImportJobError";
  }
}

export interface ImportJobStatus {
  job: ImportJobRecord;
  /** Where a resumed run continues: the next batch number and spool byte. */
  resume: { seq: number; spoolOffset: number } | null;
}

/** The engine API a host exposes to its collector. */
export interface PdppImportJobs {
  begin(input: ImportJobBeginInput): Promise<ImportJobStatus>;
  append(
    batch: ImportBatchInput,
  ): Promise<ImportBatchReceipt & { replay: boolean }>;
  status(jobId: string): Promise<ImportJobStatus>;
  commit(input: ImportCommitInput): Promise<ImportCommitReceipt>;
  abort(jobId: string, reason?: string): Promise<ImportJobStatus>;
  connectorState(instance: string): Promise<ImportConnectorState | undefined>;
}
