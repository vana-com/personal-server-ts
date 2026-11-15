// Which streams of a log pass load progressively, and what each batch of the
// pass does for them. Pure: no database, no fetch. `log-apply.ts` runs it.
//
// A pass applies batches in log order (a snapshot's parts, then the segments
// after it), each one a consistent state: its operations are stamp merges, and
// a tombstone is kept beside every row. Showing the rows of the applied prefix
// is the contract `stream_partial` already holds for a head's parts, with one
// more rule. The pass has fetched every segment of its tail before it applies
// the first batch, so it knows which keys a LATER batch deletes or omits. A row
// of such a key is stored but kept out of the view until a later batch writes
// it again (`holdKeys`): the view never shows a row the finished result lacks.
//
// A stream finishes in the last batch whose metas name it. Until then the
// stream's head is not written, so `complete` is not set: a per-batch
// `complete` would end the load (see `partial_complete_au`) at the first batch.

import type {
  LogOmitted,
  LogOperation,
  LogStreamMeta,
} from "@opendatalabs/personal-server-ts-stream-sync";

/** What the plan needs of one batch of the pass, in apply order. */
export interface PlannedBatch {
  readonly streams: readonly LogStreamMeta[];
  readonly operations: readonly (LogOperation | LogOmitted)[];
}

export interface StreamLoadPlan {
  readonly stream: string;
  /** Batches whose metas name the stream. */
  readonly total: number;
  /** Index of the first and of the last of them. */
  readonly first: number;
  readonly last: number;
  /** Key -> index of the last batch that deletes or omits it. */
  readonly removedAt: ReadonlyMap<string, number>;
}

/**
 * The streams that load progressively. `skip` holds streams that already read
 * as complete (they are not a first load). A stream with one batch has nothing
 * to show early, and one whose last meta says it is not complete never ends:
 * neither loads progressively.
 */
export function planLogLoad(
  batches: readonly PlannedBatch[],
  skip: ReadonlySet<string>,
): Map<string, StreamLoadPlan> {
  const found = new Map<
    string,
    {
      total: number;
      first: number;
      last: number;
      complete: boolean;
      removedAt: Map<string, number>;
    }
  >();
  batches.forEach((batch, index) => {
    for (const meta of batch.streams) {
      const entry = found.get(meta.stream);
      if (entry) {
        entry.total++;
        entry.last = index;
        entry.complete = meta.complete;
      } else
        found.set(meta.stream, {
          total: 1,
          first: index,
          last: index,
          complete: meta.complete,
          removedAt: new Map(),
        });
    }
    for (const operation of batch.operations) {
      const entry = found.get(operation.stream);
      if (!entry) continue;
      if (operation.kind === "delete" || operation.kind === "omitted")
        entry.removedAt.set(operation.pkHash, index);
      else if (operation.kind === "complete")
        for (const pk of operation.omitted) entry.removedAt.set(pk, index);
    }
  });
  const plans = new Map<string, StreamLoadPlan>();
  for (const [stream, entry] of found)
    if (!skip.has(stream) && entry.complete && entry.total > 1)
      plans.set(stream, { stream, ...entry });
  return plans;
}

/**
 * The keys of batch `index` that the view keeps out: a LATER batch deletes or
 * omits them. A key that is removed at `index` itself, or only before it, is
 * shown: one batch is one transaction, and a key written again after its last
 * removal is in the finished result.
 */
export function heldKeys(
  plan: StreamLoadPlan,
  index: number,
  operations: readonly (LogOperation | LogOmitted)[],
): string[] {
  const held = new Set<string>();
  for (const operation of operations)
    if (operation.kind === "upsert" && operation.stream === plan.stream) {
      const removed = plan.removedAt.get(operation.pkHash);
      if (removed !== undefined && removed > index) held.add(operation.pkHash);
    }
  return [...held];
}
