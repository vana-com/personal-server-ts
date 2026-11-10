/**
 * Collection profile §3.5 + r5 H: only a declared full_inventory can
 * replace. Pure decision, no I/O. Run end supplies the server full-read fact;
 * this predicate also requires coverage AND complete producer evidence, with
 * `collection_mode='full_refresh'` and that stream succeeded. A partial
 * run can certify its successful streams; an errored/gapped sibling has no
 * proof. Spec: H, the conformance table (one JSON file, SHA-256 pinned).
 */
export interface ReplaceInput {
  readonly stream: string;
  readonly coverageStrategy?: string | null;
  readonly outcome:
    "succeeded" | "partial" | "retry_pending" | "failed" | "cancelled";
  readonly collectionMode: "full_refresh" | "incremental";
  readonly coveredStreams: readonly string[];
  readonly provenFullStreams: readonly string[];
}

export function decideReplace(input: ReplaceInput): boolean {
  return (
    input.coverageStrategy === "full_inventory" &&
    (input.outcome === "succeeded" || input.outcome === "partial") &&
    input.collectionMode === "full_refresh" &&
    input.coveredStreams.includes(input.stream) &&
    input.provenFullStreams.includes(input.stream)
  );
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
    /** For an absent head, true only after an authoritative begin read. */
    readonly basisKnown?: boolean;
  },
  registryHead: { readonly version: number; readonly dataHash: string } | null,
): boolean {
  if (registryHead === null)
    return (
      basis.basisKnown === true &&
      basis.basisVersion === null &&
      basis.basisDataHash === null
    );
  return (
    basis.basisVersion === registryHead.version &&
    basis.basisDataHash?.toLowerCase() === registryHead.dataHash.toLowerCase()
  );
}
