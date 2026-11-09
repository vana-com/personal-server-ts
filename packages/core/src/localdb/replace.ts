/**
 * H: full refresh replaces. Pure decision, no I/O. `replace = 1` only for a
 * stream in `coveredStreams` AND `provenFullStreams`, with
 * `collection_mode='full_refresh'` and outcome `succeeded`. Spec: H, the
 * conformance table (one JSON file, SHA-256 pinned).
 */
export interface ReplaceInput {
  readonly stream: string;
  readonly outcome:
    "succeeded" | "partial" | "retry_pending" | "failed" | "cancelled";
  readonly collectionMode: "full_refresh" | "incremental";
  readonly coveredStreams: readonly string[];
  readonly provenFullStreams: readonly string[];
}

export function decideReplace(input: ReplaceInput): boolean {
  void input;
  throw new Error("PS-2: not built");
}

/**
 * At publish: the head leaves out rows below the run's stamp only if the
 * registry head identity equals the run's recorded basis (never refreshed).
 * Otherwise the stream merges. Returns whether replace may apply now.
 */
export function replaceMayApply(
  basis: {
    readonly basisVersion: number | null;
    readonly basisDataHash: string | null;
  },
  registryHead: { readonly version: number; readonly dataHash: string } | null,
): boolean {
  void basis;
  void registryHead;
  throw new Error("PS-2: not built");
}
