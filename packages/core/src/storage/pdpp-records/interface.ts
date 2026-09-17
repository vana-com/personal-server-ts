import type {
  ChangesSinceOptions,
  ChangesSincePage,
  IngestResult,
  ListRecordsOptions,
  ListRecordsPage,
  PdppBlobMeta,
  PdppRecordEnvelopeInput,
  PdppStoredRecord,
  StreamListing,
  StreamSemantics,
} from "./types.js";

/**
 * Persistence index for PDPP records. Implementable by a SQLite backend
 * (desktop, `sqlite-store.ts`) and an in-memory backend that stands in for
 * the Enclave runtime (`memory-store.ts`) — real Enclave persistence
 * integration needs the supplied Enclave runtime and is out of scope here.
 */
export interface PdppRecordStore {
  /**
   * Validates key/data agreement per envelope, computes the canonical
   * record_key, allocates the next version for mutable_state streams, and
   * writes the whole batch atomically: a failure partway through rolls back
   * every write from this call, it never leaves partial version/history
   * state. Per-envelope validation failures (e.g. key/data mismatch) are
   * reported in `rejected` and do not fail the rest of the batch.
   */
  ingestBatch(
    envelopes: PdppRecordEnvelopeInput[],
    streamSemantics: (stream: string) => StreamSemantics,
    primaryKeyFields: (stream: string) => string[],
  ): IngestResult;

  getRecord(
    instance: string,
    stream: string,
    recordKey: string,
  ): PdppStoredRecord | undefined;

  listRecords(stream: string, options: ListRecordsOptions): ListRecordsPage;

  /**
   * Owner-authenticated explicit delete directive (DELETE endpoint). Only
   * valid for mutable_state streams; returns false if the stream is
   * append_only or the record does not exist.
   */
  deleteRecord(
    instance: string,
    stream: string,
    recordKey: string,
    deletedAt: string,
    streamSemantics: StreamSemantics,
  ): boolean;

  changesSince(stream: string, options: ChangesSinceOptions): ChangesSincePage;

  listStreams(instanceIds: string[]): StreamListing[];

  putBlobMeta(meta: PdppBlobMeta): void;

  getBlobMeta(blobId: string): PdppBlobMeta | undefined;

  close(): void;
}
