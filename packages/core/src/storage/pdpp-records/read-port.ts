import type { PdppRecordStore } from "./interface.js";
import type {
  StreamDeclaration,
  StreamDeclarationRegistry,
} from "./stream-declaration.js";
import type {
  ListRecordsOptions,
  ListRecordsPage,
  PdppStoredRecord,
  StreamListing,
} from "./types.js";

/** Async read boundary for synchronous and native-bridge record stores. */
export interface PdppRecordReadPort {
  /**
   * Reads a keyset page using the synchronous store's cursor contract.
   *
   * In cursor.ts, tokens are base64url JSON containing kind "list", stream,
   * store epoch, order, the last row's sortValue and recordKey, and optionally
   * a write-clock horizon. Clients must treat tokens as opaque: never parse,
   * construct, or re-encode them.
   *
   * The SQLite store (server pdpp-records-sqlite-store.ts) and memory-store.ts
   * order by (emitted_at, record_key), both reversed for descending order.
   * Continuations select tuples strictly beyond the cursor in that direction.
   * There is no instance tiebreaker: equal tuples in different instances can
   * straddle a page boundary and be skipped. Stream/epoch mismatch expires
   * the cursor; an order mismatch is invalid.
   *
   * Each call reads current non-deleted rows; the SQLite horizon only fences
   * instance resets, it does not filter rows. A walk is not a snapshot: a
   * record unchanged for the whole walk is returned exactly once (subject to
   * the instance tie above), inserts beyond the cursor may appear, inserts
   * behind it are missed, an update that changes emitted_at may repeat or
   * skip that record, and deletes remove unread records.
   *
   * Implementations must return byte-identical pages to the synchronous store
   * for the same data, request, and cursor context (including epoch/horizon),
   * preserving row order, projections, cursor bytes, and terminal-page shape.
   */
  listRecords(
    stream: string,
    options: ListRecordsOptions,
  ): Promise<ListRecordsPage>;

  getRecord(
    instance: string,
    stream: string,
    recordKey: string,
  ): Promise<PdppStoredRecord | undefined>;

  listStreams(instanceIds: string[]): Promise<StreamListing[]>;

  /** Uses the existing registry lookup with its instance/stream order reversed. */
  getStreamDeclaration(
    stream: string,
    instance: string,
  ): Promise<StreamDeclaration | undefined>;
}

/**
 * Adapts sync reads without changing their values, cursors, or error objects.
 * Supply the existing registry's forInstance lookup alongside the store reads.
 * Async method bodies turn synchronous throws into rejected promises.
 */
export function fromSyncRecordStore(
  store: Pick<PdppRecordStore, "listRecords" | "getRecord" | "listStreams"> &
    Pick<StreamDeclarationRegistry, "forInstance">,
): PdppRecordReadPort {
  return {
    async listRecords(stream, options) {
      return store.listRecords(stream, options);
    },
    async getRecord(instance, stream, recordKey) {
      return store.getRecord(instance, stream, recordKey);
    },
    async listStreams(instanceIds) {
      return store.listStreams(instanceIds);
    },
    async getStreamDeclaration(stream, instance) {
      return store.forInstance(instance, stream);
    },
  };
}
