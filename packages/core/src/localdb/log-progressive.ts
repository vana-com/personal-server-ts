// What a progressive load of a log pass needs to know about removals, and
// nothing else. Pure: no database, no fetch. `log-apply.ts` runs it.
//
// A pass applies batches in log order (a snapshot's parts, then the segments
// after it), each one a consistent state: its operations are stamp merges, and
// a tombstone is kept beside every row. Showing the rows of the applied prefix
// is the contract `stream_partial` already holds for a head's parts, with one
// more rule: the view never shows a row the finished result lacks. A row a
// LATER batch deletes or omits is stored but kept out of the view until a later
// batch writes it again (`holdKeys`).
//
// The pass knows which keys a later batch removes without reading every
// segment first. Each ref of the log head says whether its segment removes
// anything (`SegmentRef.removes`), and the pass reads the segments that say so
// before it applies the first batch; the others arrive while the batches apply.
// A ref without the fact counts as removing.
//
// Every stream of the pass finishes in its last batch: its head, and with it
// `complete`, is not written before. A per-batch `complete` would end the load
// (see `partial_complete_au`) at the first batch.

import type {
  LogOmitted,
  LogOperation,
} from "@opendatalabs/personal-server-ts-stream-sync";

/** What the plan needs of a batch: its place in the pass, and its operations. */
export interface RemovingBatch {
  readonly index: number;
  readonly operations: readonly (LogOperation | LogOmitted)[];
}

/** Stream -> key -> index of the last batch that deletes or omits the key. */
export type Removals = ReadonlyMap<string, ReadonlyMap<string, number>>;

/** The removals of the batches given: the ones that remove, as the refs say. */
export function removalsOf(batches: readonly RemovingBatch[]): Removals {
  const removed = new Map<string, Map<string, number>>();
  const note = (stream: string, pkHash: string, index: number) => {
    let keys = removed.get(stream);
    if (!keys) removed.set(stream, (keys = new Map()));
    keys.set(pkHash, Math.max(keys.get(pkHash) ?? -1, index));
  };
  for (const { index, operations } of batches)
    for (const operation of operations)
      if (operation.kind === "delete" || operation.kind === "omitted")
        note(operation.stream, operation.pkHash, index);
      else if (operation.kind === "complete")
        for (const { pkHash } of operation.omitted)
          note(operation.stream, pkHash, index);
  return removed;
}

/**
 * The keys of batch `index` that the view keeps out: a LATER batch deletes or
 * omits them. A key that is removed at `index` itself, or only before it, is
 * shown: one batch is one transaction, and a key written again after its last
 * removal is in the finished result.
 */
export function heldKeys(
  removed: Removals,
  stream: string,
  index: number,
  operations: readonly (LogOperation | LogOmitted)[],
): string[] {
  const keys = removed.get(stream);
  if (!keys) return [];
  const held = new Set<string>();
  for (const operation of operations)
    if (operation.kind === "upsert" && operation.stream === stream) {
      const at = keys.get(operation.pkHash);
      if (at !== undefined && at > index) held.add(operation.pkHash);
    }
  return [...held];
}
