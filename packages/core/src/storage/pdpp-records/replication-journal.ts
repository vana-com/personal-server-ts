import type { PdppRecordRow } from "./types.js";

/** Durable local evidence only. Sequence and record version are not replica revisions. */
export interface CanonicalMutation {
  readonly sequence: number;
  readonly operationId: string;
  readonly writerId: string;
  /** Null only for legacy records whose binding has no retained source/method. */
  readonly sourceId: string | null;
  readonly connectionId: string;
  readonly method: string | null;
  /** Null if no binding row exists for a legacy owner deletion. */
  readonly generation: number | null;
  readonly stream: string;
  readonly recordKey: string;
  readonly operation: "upsert" | "delete";
  /** Full stored value or tombstone, including its original emitted time. */
  readonly value: PdppRecordRow;
  readonly blobIds: readonly string[];
}

export interface MutationJournalPageOptions {
  /** Exclusive local offset. Omit to start at the beginning. */
  afterSequence?: number;
  /** Integer in [1, 1000]. Bounds row count, not serialized byte size. */
  limit: number;
}

export interface MutationJournalPage {
  mutations: CanonicalMutation[];
  hasMore: boolean;
  /** Last returned offset, or the input offset on an empty page. Retain even at the tail. */
  nextAfterSequence: number;
}

/**
 * Internal journal reads, separate from grant-relative PDPP cursors. No publisher.
 * Capture currently covers incremental ingest and owner record deletion only;
 * lifecycle capture and a fenced baseline are required before publication.
 * Writer identity belongs to this database installation; cloning/restoring the
 * database copies it. Rotation after restore is required before replication.
 */
export interface MutationJournalReader {
  getInstallationWriterId(): string;
  readMutationJournalPage(
    options: MutationJournalPageOptions,
  ): MutationJournalPage;
}
