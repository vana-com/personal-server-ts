// The commit phase of a connection's streams, as one registry request.
//
// Streams of one connection finish their transfers at different times. Each
// one hands its commit to a CommitGroup. This is group commit, as a database
// does it: the first commit that arrives asks for a slot turn at once, and
// when the turn starts it takes every commit that is waiting and sends them
// together. A commit that becomes ready while that request is in flight waits
// in the group and goes in the next turn, with every other commit that became
// ready meanwhile. Batching comes from the latency of the request itself, not
// from a timer. The group never waits for a stream that has not arrived, so a
// stream whose transfer is slow, finished without a commit (no change, purged,
// failed) or not started does not hold the others back. The slot is never held
// while waiting: a turn runs `flush` only.
//
// What this file does not know: how a commit is made (sign, send, local write).
// The caller's `flush` does that, inside the slot, for the entries it is given.

import type {
  RegistryBatchRow,
  RegistryRequirementFailure,
} from "../stream-sync/ports.js";
import type { LocalSyncDeps } from "./deps.js";

/**
 * The gateway's limit on rows in one batch request: it answers 400 ("rows must
 * be an array of 1 to 16 entries") above it. Mirrored from `MAX_BATCH_ROWS` in
 * the data gateway's `lib/data-point-batch.ts`, which owns the number. It is a
 * protocol limit, not a tuning knob: a turn with more waiting commits sends
 * the first rows and the rest take the next turn.
 */
export const GATEWAY_MAX_BATCH_ROWS = 16;

/**
 * The gateway's limit on conditions in one batch request (`MAX_BATCH_REQUIRES`
 * in the same file). One of them is the connection's control row.
 */
export const GATEWAY_MAX_BATCH_REQUIRES = 16;

export interface CommitGroup<E, R> {
  /** Resolves when the entry's commit turn ends; rejects if the turn failed. */
  submit(entry: E): Promise<R>;
}

/**
 * `runInSlot` runs `work` in one slot turn of the connection and may throw
 * before it starts (a purge stopped the run). `flush` receives the entries that
 * waited and returns one settled result per entry, in the same order; a throw
 * from `flush` fails every entry of that turn.
 */
export function createCommitGroup<E, R>(options: {
  readonly runInSlot: <T>(
    work: (held: LocalSyncDeps) => Promise<T>,
  ) => Promise<T>;
  readonly flush: (
    held: LocalSyncDeps,
    entries: readonly E[],
  ) => Promise<readonly PromiseSettledResult<R>[]>;
  /**
   * Whether `next` fits in the turn that already holds `taken`. The first
   * entry always fits. By default a turn holds `GATEWAY_MAX_BATCH_ROWS`.
   */
  readonly canJoin?: (taken: readonly E[], next: E) => boolean;
}): CommitGroup<E, R> {
  const canJoin =
    options.canJoin ??
    ((taken: readonly E[]) => taken.length < GATEWAY_MAX_BATCH_ROWS);
  type Waiting = {
    readonly entry: E;
    readonly resolve: (result: R) => void;
    readonly reject: (error: unknown) => void;
  };
  const waiting: Waiting[] = [];
  let turnQueued = false;

  const runTurn = (): void => {
    options
      .runInSlot(async (held) => {
        // From here an arriving entry waits for the next turn.
        turnQueued = false;
        let count = 0;
        while (count < waiting.length) {
          const fits =
            count === 0 ||
            canJoin(
              waiting.slice(0, count).map(({ entry }) => entry),
              waiting[count]!.entry,
            );
          if (!fits) break;
          count++;
        }
        const taken = waiting.splice(0, count);
        if (waiting.length > 0) queueTurn();
        let settled: readonly PromiseSettledResult<R>[];
        try {
          settled = await options.flush(
            held,
            taken.map(({ entry }) => entry),
          );
          if (settled.length !== taken.length) {
            throw new Error(
              `commit group: ${taken.length} entries, ${settled.length} results`,
            );
          }
        } catch (error) {
          for (const { reject } of taken) reject(error);
          return;
        }
        taken.forEach(({ resolve, reject }, at) => {
          const result = settled[at]!;
          if (result.status === "fulfilled") resolve(result.value);
          else reject(result.reason);
        });
      })
      .catch((error: unknown) => {
        // The slot refused the turn before `flush` ran: nobody was taken.
        turnQueued = false;
        for (const { reject } of waiting.splice(0)) reject(error);
      });
  };

  const queueTurn = (): void => {
    if (turnQueued) return;
    turnQueued = true;
    runTurn();
  };

  return {
    submit: (entry) =>
      new Promise<R>((resolve, reject) => {
        waiting.push({ entry, resolve, reject });
        queueTurn();
      }),
  };
}

/** What a stream's commit does with the registry's answer to its row. */
export type RowSettlement = "committed" | "conflict";

/**
 * A row the gateway answered as a conflict whose winner is this very row (same
 * version, same data hash) was written by an earlier send of the same request:
 * it is published, not lost.
 */
export function settleRow(
  row: RegistryBatchRow,
  sent: { readonly expectedVersion: string; readonly dataHash: string },
): RowSettlement {
  if (row.kind === "committed") return "committed";
  return row.latestVersion === sent.expectedVersion &&
    row.latestDataHash !== null &&
    row.latestDataHash.toLowerCase() === sent.dataHash.toLowerCase()
    ? "committed"
    : "conflict";
}

/**
 * What a failed condition means. A tombstone of the control
 * row is a delete: purge, fenced by the tombstone's version. Anything else
 * (no row, another version) means this lifetime is not the one the registry
 * holds: defer, as a control read that is not this lifetime's active row does.
 */
export type RequirementOutcome =
  | { readonly kind: "purge"; readonly controlVersion: number }
  | { readonly kind: "defer" }
  /**
   * A fence on a stream row failed, not the control row: that stream's
   * registry row is not the one it was planned over. Nothing was written.
   */
  | { readonly kind: "stream_moved"; readonly scope: string };

export function settleRequirementFailure(
  failure: RegistryRequirementFailure,
  control: string,
): RequirementOutcome {
  if (failure.scope !== control) {
    return { kind: "stream_moved", scope: failure.scope };
  }
  const version = Number(failure.latestVersion);
  if (failure.deleted && Number.isSafeInteger(version) && version >= 1) {
    return { kind: "purge", controlVersion: version };
  }
  return { kind: "defer" };
}
