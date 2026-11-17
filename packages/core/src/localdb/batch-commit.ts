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

import {
  RegistryBatchRouteMissingError,
  type RegistryBatchPolicy,
  type RegistryBatchRow,
  type RegistryRequirementFailure,
  type StreamSyncRegistry,
} from "../stream-sync/ports.js";
import type { LocalSyncDeps } from "./deps.js";

/**
 * The bounds of one batch request on this registry: the policy the gateway
 * advertised (`Batch-Policy`). `undefined` when it has advertised none: the
 * caller sends no batch then, and no number stands in for the gateway's. A
 * caller that needs it before its first request reads it with
 * `registry.readBatchPolicy()`.
 */
export function batchBounds(
  registry: LocalSyncDeps["registry"],
): RegistryBatchPolicy | undefined {
  return registry.batchPolicy?.();
}

/**
 * The gateway's `Batch-Policy` has no room for a request the caller cannot
 * split (a first save's control row and log row commit together). Not a race:
 * nothing goes until the gateway advertises a larger policy.
 */
export class RegistryBatchPolicyTooSmallError extends Error {
  constructor(
    readonly policy: RegistryBatchPolicy,
    readonly rows: number,
    readonly requires: number,
  ) {
    super(
      `Batch-Policy rows=${policy.rows};requires=${policy.requires} has no room for one request of ${rows} rows and ${requires} conditions`,
    );
    this.name = "RegistryBatchPolicyTooSmallError";
  }
}

/** Throws when a known policy has no room for a request of this shape. */
export function checkBatchRoom(
  policy: RegistryBatchPolicy | undefined,
  request: {
    readonly rows: readonly unknown[];
    readonly requires: readonly unknown[];
  },
): void {
  if (
    policy !== undefined &&
    (request.rows.length > policy.rows ||
      request.requires.length > policy.requires)
  )
    throw new RegistryBatchPolicyTooSmallError(
      policy,
      request.rows.length,
      request.requires.length,
    );
}

/**
 * The gateway's batch bounds, for a caller that commits only in batches (a
 * connection delete, a log publish). Read once per process. Throws
 * `RegistryBatchRouteMissingError` when the gateway serves no batch contract,
 * and `AmbiguousRegistryReplyError` when the policy read got no answer.
 */
export async function requireBatchPolicy(
  registry: StreamSyncRegistry,
): Promise<RegistryBatchPolicy> {
  if (registry.postBatch === undefined)
    throw new RegistryBatchRouteMissingError("this registry has no batch port");
  const policy = await (registry.readBatchPolicy?.() ??
    Promise.resolve(registry.batchPolicy?.()));
  if (policy === undefined)
    throw new RegistryBatchRouteMissingError("no Batch-Policy advertised");
  return policy;
}

/**
 * What a commit does with the registry's answer to its row in a refused
 * request. `not_written`: the row lost nothing of its own; another row of the
 * request lost, and this one may be sent again.
 */
export type RowSettlement = "committed" | "conflict" | "not_written";

/**
 * A row the gateway answered as a conflict whose winner is this very row (same
 * version, same data hash) was written by an earlier send of the same request:
 * it is published, not lost.
 */
export function settleRow(
  row: RegistryBatchRow,
  sent: { readonly expectedVersion: string; readonly dataHash: string },
): RowSettlement {
  if (row.kind !== "conflict") return row.kind;
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
