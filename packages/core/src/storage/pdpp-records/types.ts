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
  /** Present only on an explicitly permitted provisional replica read. */
  confirmation?: "not yet confirmed";
  visibility?: "pending" | "conflicted";
  status?: "account conflict";
  instance: string;
  stream: string;
  recordKey: string;
  data: Record<string, unknown>;
  version: number;
  emittedAt: string;
  deleted: false;
}

export interface PdppTombstoneRecord {
  confirmation?: "not yet confirmed";
  visibility?: "pending" | "conflicted";
  status?: "account conflict";
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
  isVisible?: (row: PdppRecordRow) => boolean;
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

export interface ChangesSinceOptions {
  /** Candidate visibility policy, evaluated at BOTH historical horizons. */
  isVisible?: (row: PdppStoredRecord) => boolean;
  /**
   * Candidate: a page that reaches a record deleted after the session horizon
   * fails with `CursorExpiredError` instead of serving that record. Withholding
   * it could lose it: the next session compares against this horizon, so a
   * record deleted and recreated unchanged would never reach the client.
   * The current contract serves every page at the session horizon.
   */
  expireOnErasure?: boolean;
  instanceIds: string[];
  /** Absent = start a new session anchored at "now". */
  changesSince?: string;
  /** Page cursor within an already-anchored session. */
  cursor?: string;
  limit: number;
  fields?: string[];
}

export interface ChangesSincePage {
  data: PdppRecordRow[];
  hasMore: boolean;
  nextCursor?: string;
  /** Present only on the terminal page. */
  nextChangesSince?: string;
}

export interface StreamListing {
  confirmation?: "not yet confirmed";
  visibility?: "pending" | "conflicted";
  status?: "account conflict";
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

/** A read-time removal is explicit and contains no withdrawn record fields. */
export interface PdppPendingRemoval extends Omit<PdppStoredRecord, "deleted"> {
  deleted: true;
  deletedAt: string;
  confirmation: "not yet confirmed";
  visibility: "pending";
  /** Empty on removals; never expose the withdrawn value as current data. */
  data: Record<string, never>;
}
export type PdppVisibleRecord = PdppStoredRecord | PdppPendingRemoval;
export interface ListVisibleRecordsPage extends Omit<ListRecordsPage, "data"> {
  data: PdppVisibleRecord[];
}
export interface PdppReplicaReadStore {
  /** Confirmed history only; an identity conflict cannot establish row provenance. */
  changesSince?(stream: string, options: ChangesSinceOptions): ChangesSincePage;
  getRecord(
    instance: string,
    stream: string,
    key: string,
  ): PdppVisibleRecord | undefined;
  listRecords(
    stream: string,
    options: ListRecordsOptions,
  ): ListVisibleRecordsPage;
  listStreams(instanceIds: string[]): StreamListing[];
}
