import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";

export type LiteBlobDescriptor = Extract<
  ReplicaOperation,
  { kind: "blob-claim" }
>["blob"];
declare const liteStagingIdBrand: unique symbol;
export type LiteStagingId = string & {
  readonly [liteStagingIdBrand]: true;
};
export interface LiteStorageEntry {
  key: string;
  value: string;
}
export interface LiteStoragePage {
  entries: LiteStorageEntry[];
  after?: string;
}

/** One serializable, owner-partitioned SQLite transaction. No await escapes its lifetime. */
export interface LiteCanonicalTransaction {
  get(key: string): Promise<string | undefined>;
  put(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
  /** Exclusive bytewise key cursor; snapshot stable for this transaction. */
  scan(prefix: string, after?: string): Promise<LiteStoragePage>;
  /** Verify staged length/hash/MIME and publish its immutable reference in THIS transaction. */
  attachBlob(
    stagingId: LiteStagingId,
    expected: LiteBlobDescriptor,
  ): Promise<void>;
  blob(blobId: string): Promise<LiteBlobDescriptor | undefined>;
}

/**
 * Slice 7b implements this over PsNativeStore, not browser storage. Each scan is
 * <=100 entries and <=512 KiB; individual values <=256 KiB. An oversized entry
 * throws, never truncates. Roll back on callback error, bridge loss or host kill.
 */
export interface LiteCanonicalPersistence {
  transaction<T>(run: (tx: LiteCanonicalTransaction) => Promise<T>): Promise<T>;
  /** Backpressured <=128 KiB frames. Final hash is computed natively, not trusted from JS. */
  stageBlob(
    descriptor: LiteBlobDescriptor,
    chunks: AsyncIterable<Uint8Array>,
  ): Promise<LiteStagingId>;
  /** Internal bytes, not a grant-authorized read API. Missing/uncommitted blobs throw. */
  readBlob(blobId: string): AsyncIterable<Uint8Array>;
}
