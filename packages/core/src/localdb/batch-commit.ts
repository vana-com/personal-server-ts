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
 * What every gateway that has the batch route accepts: 16 rows and 16
 * conditions in one request (the fixed caps of the first gateway to ship it).
 * A caller uses these until a batch answer advertises the gateway's own bounds
 * (`Batch-Policy`, read by `registry.batchPolicy()`), and for a gateway that
 * never does. They are not tuning knobs: see `batchBounds`.
 */
export const GATEWAY_MAX_BATCH_ROWS = 16;
export const GATEWAY_MAX_BATCH_REQUIRES = 16;

/**
 * The bounds of one batch request on this registry: what its last batch answer
 * advertised, else the fixed caps every gateway accepts.
 */
export function batchBounds(registry: LocalSyncDeps["registry"]): {
  readonly rows: number;
  readonly requires: number;
  /** See `RegistryBatchPolicy.lockedScopes`; absent when the gateway sends none. */
  readonly lockedScopes?: number;
} {
  const policy = registry.batchPolicy?.();
  return {
    rows: policy?.rows ?? GATEWAY_MAX_BATCH_ROWS,
    requires: policy?.requires ?? GATEWAY_MAX_BATCH_REQUIRES,
    ...(policy?.lockedScopes !== undefined && {
      lockedScopes: policy.lockedScopes,
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
