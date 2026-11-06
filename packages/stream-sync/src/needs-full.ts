/**
 * §2.4, §2.7 durable `needsFull[c, ns, s]`.
 *
 * - Publishing `complete:false` sets `needsFull[c, ns, s]` and clears the
 *   checkpoint for c, so the next run is full.
 * - A full run that commits `complete:true` clears it.
 * - Any `needsFull` for c forces the next run of c to be full.
 *
 * Every device that publishes onto an incomplete base sets its own entry, so
 * incomplete heads converge. The set is a sorted array so hosts can store it
 * as JSON and compare it byte for byte.
 */

export interface NeedsFullKey {
  readonly connector: string;
  readonly ns: string;
  readonly stream: string;
}

export type NeedsFull = readonly NeedsFullKey[];

function compareKeys(a: NeedsFullKey, b: NeedsFullKey): number {
  for (const field of ["connector", "ns", "stream"] as const) {
    if (a[field] !== b[field]) return a[field] < b[field] ? -1 : 1;
  }
  return 0;
}

function same(a: NeedsFullKey, b: NeedsFullKey): boolean {
  return compareKeys(a, b) === 0;
}

export function runMustBeFull(
  needsFull: NeedsFull,
  connector: string,
): boolean {
  return needsFull.some((key) => key.connector === connector);
}

export interface CommitEffect {
  readonly needsFull: NeedsFull;
  /** Clear the checkpoint for the connector. */
  readonly clearCheckpoint: boolean;
}

/** Apply one committed head to the `needsFull` set. */
export function afterCommit(
  needsFull: NeedsFull,
  commit: NeedsFullKey & {
    /** `complete` of the committed head. */
    readonly complete: boolean;
    /** The run used no checkpoint. */
    readonly runFull: boolean;
  },
): CommitEffect {
  const key: NeedsFullKey = {
    connector: commit.connector,
    ns: commit.ns,
    stream: commit.stream,
  };
  if (!commit.complete) {
    const next = needsFull.some((k) => same(k, key))
      ? [...needsFull]
      : [...needsFull, key];
    return { needsFull: next.sort(compareKeys), clearCheckpoint: true };
  }
  if (commit.runFull) {
    return {
      needsFull: needsFull.filter((k) => !same(k, key)).sort(compareKeys),
      clearCheckpoint: false,
    };
  }
  return {
    needsFull: [...needsFull].sort(compareKeys),
    clearCheckpoint: false,
  };
}
