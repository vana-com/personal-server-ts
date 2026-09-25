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
   * Decides each envelope with `planIngest` and writes the accepted ones
   * atomically: a thrown error rolls back every write from this call, it
   * never leaves partial version/history state. Each envelope gets exactly
   * one outcome in `results`. A rejected envelope writes nothing and does
   * not fail the rest of the batch. An `unchanged` envelope writes nothing
   * either: no version, no history row, no write-clock tick.
   *
   * Declarations are looked up per envelope by `(stream, instance)`, since
   * one stream name can belong to several sources.
   *
   * The SQLite PS backend also accepts a method and generation. It validates
   * the generation in this transaction and binds an empty instance to that
   * method with its first accepted write. Omitting the binding for an
   * instance already under method authority is rejected by that backend.
   */
  ingestBatch(
    envelopes: PdppRecordEnvelopeInput[],
    streamSemantics: (stream: string, instance: string) => StreamSemantics,
    primaryKeyFields: (stream: string, instance: string) => string[],
    binding?: { method: string; generation: number },
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

  /**
   * Atomically persists blob bytes and their metadata together (metadata and
   * bytes are never written as two separate, independently-failable steps —
   * the existing-row check and the write happen inside one transaction, not
   * a check followed by a racing upsert). blob_id is derived from the bytes
   * themselves (content-addressed: `sha256:<hex>`, this store's own
   * convention, not a spec-core requirement), not supplied by the caller —
   * a producer cannot claim an arbitrary id for its bytes, and identical
   * bytes always resolve to the same blob_id regardless of which ingest
   * wrote them first.
   *
   * Re-storing bytes that hash to an already-known blob_id is a verified
   * no-op only when mimeType matches AND the previously-stored bytes
   * actually still hash/size-match their own recorded metadata:
   *   - metadata-only row (no bytes ever stored, e.g. a legacy fixture that
   *     called `putBlobMeta` directly): completed by writing the bytes now.
   *   - existing bytes verified intact and mimeType matches: idempotent
   *     no-op, returns the existing metadata unchanged.
   *   - existing bytes present but corrupt/truncated relative to their own
   *     metadata: throws BlobConflictError rather than silently reporting
   *     success over content that can no longer be trusted, or silently
   *     overwriting it as if this were the first write.
   *   - mimeType differs from the existing record (regardless of byte
   *     health): throws BlobConflictError — refusing to let a second write
   *     silently redefine what an existing blob_id means.
   */
  storeBlobBytes(bytes: Uint8Array, mimeType: string): PdppBlobMeta;

  /**
   * Reads back bytes for a blob_id, verifying the stored payload's actual
   * size and SHA-256 still match the recorded metadata before returning
   * anything. Returns undefined when the blob has metadata-only rows (legacy
   * or test fixtures that called `putBlobMeta` directly), no bytes were ever
   * stored, or the stored bytes are corrupt/truncated relative to their own
   * metadata -- fail closed rather than deliver unverified bytes under a
   * trusted-looking 200.
   */
  getBlobBytes(blobId: string): Uint8Array<ArrayBuffer> | undefined;

  /**
   * Finds every non-deleted record that references a `blob_id` via
   * `data.blob_ref.blob_id` (spec §4 "Binary data (blob_ref)"). Identical
   * blob bytes can legitimately be referenced by more than one record or
   * instance, so callers must check every returned reference and grant
   * access if ANY one passes their authorization constraints (spec §8 "Get
   * a blob") -- an inaccessible reference must never hide an accessible
   * one. A `blob_id` alone is never sufficient to authorize access: the
   * resource server must verify the grant includes a stream containing a
   * record that references this blob, that record passes all grant
   * filters, and `blob_ref` is in the grant's authorized field projection.
   * Returns an empty array if no ingested record currently references this
   * blob_id.
   */
  findBlobReferences(blobId: string): BlobReference[];

  close(): void;
}

export interface BlobReference {
  instance: string;
  stream: string;
  recordKey: string;
}
