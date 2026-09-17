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
  op?: "upsert" | "delete";
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

export interface IngestResult {
  accepted: number;
  rejected: IngestRejection[];
}

export interface ListRecordsOptions {
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
}

export interface ChangesSinceOptions {
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

export class CursorExpiredError extends Error {
  constructor() {
    super("changes_since cursor has expired");
  }
}

export class InvalidCursorError extends Error {}

export class RecordIdentityMismatchError extends Error {}
