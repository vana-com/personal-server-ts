import type { LocalSyncDeps } from "./deps.js";

/**
 * E.1: run blobs (at most 32 MiB). `PUT /v1/stream-sync/runs/:runId/blobs/:sha256`
 * lands here: bytes into `blobs`, a ref into `blob_refs` for the record that
 * names it. Publish uploads `g<gen>-b-<sha256>`; apply fetches lazily.
 */
export interface BlobStore {
  put(input: {
    readonly runId: string;
    readonly sha256: string;
    readonly mimeType: string;
    readonly bytes: Uint8Array;
  }): Promise<void>;
  /** Local bytes, else a lazy fetch from Vana storage; `null` when absent. */
  get(
    blobId: string,
  ): Promise<{ readonly mimeType: string; readonly bytes: Uint8Array } | null>;
}

export function createBlobStore(deps: LocalSyncDeps): BlobStore {
  void deps;
  throw new Error("PS-2: not built");
}
