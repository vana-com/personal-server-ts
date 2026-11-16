// A registry behind this device (a rollback, or a restore from a backup) lost
// the log rows of its newest positions. The segments those rows named are
// still in storage: a segment is content-addressed and never deleted (see
// `log-compact.ts`). This device applied them, so its rows, tombstones and
// checkpoints are their fold. It commits them again, one row per position, in
// order, each against the registry's current row, as Git pushes back commits a
// remote lost. Every effect of the lost positions comes back as it was, deletes
// and omissions included, and every reader converges by applying them.
//
// The registry's row must be one this device applied: the segment the log
// names at its position is the one this device has at that position. Any other
// row is another history: this throws `LogDivergedError`, and `applyLog`
// rebases onto that history instead (`log-rebase.ts`).

import {
  controlScope,
  logScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { settleRow } from "./batch-commit.js";
import type { LocalSyncDeps } from "./deps.js";
import { fetchSegment, type LogApplyContext } from "./log-apply.js";
import { LogDivergedError, type LogState } from "./log-state.js";
import { metadataHashFor, postBatchOnce } from "./publish.js";

/**
 * Commit again, in order, the segments this device applied above the
 * registry's position. Returns when the registry is at this device's position,
 * or when another writer moved it first (the next apply reads it again).
 * Throws `LogDivergedError` when the registry's row is not one this device
 * applied, or a segment to commit is not of this lifetime.
 */
export async function recommitApplied(
  deps: LocalSyncDeps,
  connectionId: string,
  context: LogApplyContext,
  local: LogState,
  read: { readonly version: number; readonly dataHash: string },
): Promise<void> {
  const scope = logScope(context.connector, context.ns);
  if (!deps.registry.postBatch)
    throw new Error("apply: the registry has no batch route for the log");
  const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
  const named = local.refs.find((ref) => ref.position === read.version);
  if (!named || !same(named.dataHash, read.dataHash))
    throw new LogDivergedError(
      `apply: the log registry is at position ${read.version}, behind this device at ${local.position}, and names a segment this device did not apply there`,
    );
  const lost = local.refs
    .filter((ref) => ref.position > read.version)
    .sort((a, b) => a.position - b.position);
  // Every position above the registry's, up to this device's, is one this
  // device holds a ref of; otherwise it cannot put that history back.
  if (
    lost.length !== local.position - read.version ||
    lost.some((ref, i) => ref.position !== read.version + 1 + i)
  )
    throw new LogDivergedError(
      `apply: the log registry is at position ${read.version}, behind this device at ${local.position}, which holds no segment of each position between`,
    );
  deps.logger.warn(
    { connectionId, registry: read.version, device: local.position },
    "stream sync: the log registry is behind this device; committing the segments it lost again",
  );
  let head = named.dataHash;
  for (const ref of lost) {
    const fetched = await fetchSegment(
      deps,
      scope,
      context,
      ref.dataHash,
      ref.position,
    );
    if (fetched.segment.generation !== context.generation)
      throw new LogDivergedError(
        `apply: the log segment at position ${ref.position} this device applied is of another lifetime`,
      );
    const metadataHash = await metadataHashFor(
      scope,
      new Date(deps.now()).toISOString(),
      fetched.cipherBytes,
      deps.streamCrypto,
    );
    const signature = await deps.signer.signAddData({
      ownerAddress: deps.ownerAddress,
      scope,
      dataHash: ref.dataHash,
      metadataHash,
      expectedVersion: BigInt(ref.position),
    });
    const row = {
      scope,
      dataHash: ref.dataHash,
      metadataHash,
      expectedVersion: String(ref.position),
      signature,
      expectedHeadDataHash: head,
    };
    const answer = await postBatchOnce(deps.registry, {
      ownerAddress: deps.ownerAddress,
      rows: [row],
      requires: [
        {
          scope: controlScope(context.connector, context.ns),
          expectedVersion: String(context.generation),
          notDeleted: true,
          expectedDataHash: context.hashes.activeData,
        },
      ],
    });
    // The connection changed (deleted, another lifetime): the next apply
    // reads that first.
    if (answer.kind === "precondition_failed") return;
    // A refused one-row request: the row lost, unless the winner is this very
    // row (a resend).
    if (answer.kind === "refused" && settleRow(answer.rows[0]!, row) !== "committed")
      return;
    head = ref.dataHash;
  }
}
