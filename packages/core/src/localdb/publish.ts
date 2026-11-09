import type { LocalSyncDeps } from "./deps.js";
import type { HeadExtras } from "./encode.js";

/** One stream's publish result. */
export interface PublishResult {
  readonly stream: string;
  readonly outcome:
    | "published"
    | "noop"
    | "deferred"
    | "refused"
    | "discarded"
    | "purged"
    | "backoff";
  /** `max(seq)` read in step 1; the new `publish_watermark` on success. */
  readonly watermark: number | null;
}

/**
 * C.2: publish one connection, in the connection queue, after apply. Per
 * stream with work: snapshot (watermark W = newest log entry READ), registry
 * check (newer row = apply and restart; `deleted` = purge and stop),
 * re-plan (refusal = `unwriteRefusedRun`), encode (`encodePrefixes`), head
 * then registry CAS from `head_version` (conflict = apply the winner and
 * re-plan; at most 5 tries, then back off), then one batch: replace deletes,
 * head identity, `publish_watermark = W`, `head_parts`, `stream_versions`,
 * compaction of `record_changes`. Seeds publish into generation 1 only.
 * `options.headExtras` supplies per-head extra fields (pending r5.2, the
 * first-seen checkpoint); absent today.
 */
export async function publishConnection(
  deps: LocalSyncDeps,
  connectionId: string,
  options?: {
    readonly headExtras?: (stream: string) => Promise<HeadExtras | undefined>;
  },
): Promise<readonly PublishResult[]> {
  void options;
  void deps;
  void connectionId;
  throw new Error("PS-2: not built");
}
