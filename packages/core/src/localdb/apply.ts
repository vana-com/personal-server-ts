import type { LocalSyncDeps } from "./deps.js";

/** What one apply did, for the caller's status line. */
export interface ApplyResult {
  readonly stream: string;
  /** "noop" = the registry version equals `head_version` and parts exist. */
  readonly outcome: "applied" | "noop" | "purged" | "gone";
  readonly partsDownloaded: number;
  readonly partsKept: number;
}

/**
 * C.3: apply the registry head of one stream into `records`, in the
 * connection queue (kind "apply", single-flight). Download and verify the
 * head (keyCheck, ns, generation; a generation past a delete purges first),
 * merge changed parts with origin `remote` (one batch per part, keys into
 * `apply_keys`), keep unchanged parts via `keep_ranges`, then the one
 * `applyDelete` batch with head identity, `head_parts`, `stream_versions`,
 * `complete`. At most one part in memory. Idempotent after a crash.
 */
export async function applyStream(
  deps: LocalSyncDeps,
  connectionId: string,
  stream: string,
): Promise<ApplyResult> {
  void deps;
  void connectionId;
  void stream;
  throw new Error("PS-2: not built");
}

/**
 * Apply every stream of a connection whose registry version differs from
 * `head_version`, or whose `head_parts` is empty while `head_version > 0`.
 * Joins an apply already running (B.1).
 */
export async function applyConnection(
  deps: LocalSyncDeps,
  connectionId: string,
): Promise<readonly ApplyResult[]> {
  void deps;
  void connectionId;
  throw new Error("PS-2: not built");
}
