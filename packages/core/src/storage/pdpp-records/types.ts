/**
 * PDPP record persistence types (spec-core.md Section 4 "Record Model").
 *
 * This is a NEW, separate index for PDPP-shaped records. It is deliberately
 * not the legacy `packages/core/src/storage/index/` DPP fileId/scope model —
 * that module serves existing non-PDPP callers and is left untouched.
 */

export type StreamSemantics = "append_only" | "mutable_state";

export type EnvelopeKey = string | string[];

/** The RECORD envelope, spec §4 "The RECORD envelope". */
export interface PdppRecordEnvelopeInput {
  instance: string;
  stream: string;
  key: EnvelopeKey;
  data: Record<string, unknown> | null;
  emitted_at: string;
  /** Absent or `null` means upsert. */
  op?: "upsert" | "delete" | null;
}

export interface PdppStoredRecord {
  instance: string;
  stream: string;
  recordKey: string;
  data: Record<string, unknown>;
  version: number;
  emittedAt: string;
  deleted: false;
}

export interface PdppTombstoneRecord {
  instance: string;
  stream: string;
  recordKey: string;
  version: number;
  deletedAt: string;
  emittedAt: string;
  deleted: true;
}

export type PdppRecordRow = PdppStoredRecord | PdppTombstoneRecord;

export interface IngestRejection {
  index: number;
  reason: string;
}

/**
 * What ingest did with one envelope.
 *
 * - `accepted`: a new version was written.
 * - `unchanged`: the stored content already equals the envelope, so nothing
 *   was written (no version, history row, or write-clock tick). For an
 *   `append_only` key whose stored data differs, the first write stands and
 *   the outcome carries `flag: "append_only_conflict"`.
 * - `rejected`: the envelope is invalid; nothing was written for it.
 */
export type IngestOutcome =
  | { index: number; outcome: "accepted" }
  | { index: number; outcome: "unchanged"; flag?: "append_only_conflict" }
  | { index: number; outcome: "rejected"; reason: string };

export interface IngestResult {
  accepted: number;
  unchanged: number;
  rejected: IngestRejection[];
  /** One entry per input envelope, in input order. */
  results: IngestOutcome[];
}

export interface ListRecordsOptions {
  /** Grant eligibility, evaluated on raw snapshot rows before pagination/projection. */
  isVisible?: (row: PdppStoredRecord) => boolean;
  instanceIds: string[];
  limit: number;
  cursor?: string;
  order: "asc" | "desc";
  /** undefined = no projection restriction (owner reads / unrestricted). */
  fields?: string[];
}

export interface ListRecordsPage {
  data: PdppStoredRecord[];
  hasMore: boolean;
  nextCursor?: string;
  /** Write clock this listing is fenced at; a re-encoded cursor must carry it. */
  horizon?: string;
}

/**
 * Raw history one sync page reads. Only the sync session owner
 * (`sync-session.ts`) calls this; it holds no visibility, paging or token policy.
 */
export interface SyncWindowRequest {
  instanceIds: string[];
  /** Earlier horizon of an incremental session; null for a first sync. */
  low: string | null;
  /** Fixed horizon of an anchored session. Absent captures the current one. */
  high?: string;
}

/** One record key written in (low, high], or present at high for a first sync. */
export interface SyncWindowChange {
  /** The key's version at the high horizon. */
  after: PdppRecordRow;
  /** The key's version at the low horizon, if any. */
  before(): PdppRecordRow | undefined;
  /** True when a deletion of this key committed after the high horizon. */
  deletedAfterHigh(): boolean;
}

export interface SyncWindow {
  high: string;
  /** Ordered by `compareRecordIdentity`, ascending. */
  changes: SyncWindowChange[];
}

/** Store identity for sync tokens. Both change when the store is rebuilt. */
export interface SyncTokenScope {
  /** Store reset epoch carried by current-profile tokens. */
  epoch: string;
  /** 32-byte secret that seals candidate-profile tokens. */
  key: Uint8Array;
}

export interface ChangesSincePage {
  data: PdppRecordRow[];
  hasMore: boolean;
  nextCursor?: string;
  /** Present only on the terminal page. */
  nextChangesSince?: string;
}

export interface StreamListing {
  stream: string;
  recordCount: number;
  lastUpdated: string | null;
}

export interface PdppBlobMeta {
  blobId: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
}

/**
 * A blob_id whose bytes are already stored under a DIFFERENT mime type than
 * requested, or whose previously-stored bytes no longer hash/size-match
 * their own recorded metadata. blob_id is content-derived from the bytes'
 * SHA-256 as an IMPLEMENTATION convention of this store (spec-core.md §4
 * "Binary data (blob_ref)" does not itself mandate content-derived ids), so
 * a same-blob_id conflict can only happen when the same bytes are re-stored
 * with a different declared mimeType, or when the existing stored bytes are
 * corrupt relative to their own metadata — refusing beats guessing which
 * caller's intent should win, and refusing beats silently reporting success
 * over corrupt content.
 */
export class BlobConflictError extends Error {
  constructor(
    public readonly blobId: string,
    public readonly existing: PdppBlobMeta,
  ) {
    super(
      `blob ${blobId} conflicts with its stored metadata (mimeType '${existing.mimeType}', sizeBytes ${existing.sizeBytes}, sha256 ${existing.sha256})`,
    );
  }
}

export class CursorExpiredError extends Error {
  constructor() {
    super("changes_since cursor has expired");
  }
}

export class InvalidCursorError extends Error {}

export class RecordIdentityMismatchError extends Error {}
