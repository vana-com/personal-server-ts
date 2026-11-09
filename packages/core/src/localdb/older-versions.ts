import type { LocalSyncDeps } from "./deps.js";

/** A version a read can fetch now. */
export interface VersionInfo {
  readonly version: number;
  /** `stream_versions.head_blob`; the `?fileId=` value. */
  readonly fileId: string;
  readonly observedAt: number;
  readonly recordCount: number;
  readonly complete: boolean;
}

/** `/sync/status` field; counted since process start (D.3 usage count). */
export interface OlderVersionCounts {
  readonly served: number;
  readonly gone: number;
  readonly off: number;
}

/**
 * D.3: everything about older versions lives behind this one interface, in
 * this one module. Route code calls `list` and `read` and knows nothing else.
 * Deleting the feature later = this file, the flag and the call; the 410
 * remains. Current-version reads never come here.
 *
 * The `/additions`, `/versions` and `/lineage` routes on the database live in
 * `history.ts` (r5.2 1.4), not here; this interface is unchanged by them.
 *
 * Flag on: versions come from `stream_versions` of the connection's CURRENT
 * generation; head and parts are fetched on demand, decrypted, projected, and
 * nothing is stored. A missing part = `"gone"` and that `stream_versions` row
 * is removed. Flag off: `read` = `"gone"` and `list` = the current version
 * only. Each `read` logs `older-version read outcome=<served|gone|off>` with
 * no scope or owner, and bumps `counts()`.
 */
export interface OlderVersions {
  list(connectionId: string, stream: string): Promise<readonly VersionInfo[]>;
  read(
    scope: string,
    select: { readonly fileId?: string; readonly at?: string },
  ): Promise<ReadableStream<Uint8Array> | "gone">;
  counts(): OlderVersionCounts;
}

export function createOlderVersions(
  deps: LocalSyncDeps,
  options: {
    /** The `olderVersionReads` server config value, read at each call (default true). */
    readonly enabled: () => boolean;
  },
): OlderVersions {
  void deps;
  void options;
  throw new Error("PS-2: not built");
}
