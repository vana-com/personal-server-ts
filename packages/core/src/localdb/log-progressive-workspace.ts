// One verified unit at a time. Facts and receipts, rather than decoded promises,
// carry removal holdback and restart authority between units.
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import {
  segmentBlobName,
  snapshotPartBlobName,
  segmentRemoves,
  canonicalJson,
  type Segment,
  type SegmentRef,
  type SnapshotPointer,
  type LogKey,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";
import type { LogApplyContext } from "./log-apply.js";
import { fetchSegmentWire, fetchSnapshotPartWire } from "./log-input.js";
import { resolveBodies } from "./log-bodies.js";
import { prepareOperations, type BatchIdentity } from "./log-batch.js";
import { openProgressiveLogWorkspace } from "./workspace-consumer.js";
import { runtimeAdmission } from "./workspace.js";
import type { WorkspaceBinding } from "./workspace-capability.js";
import { announceApplied } from "./apply-progress.js";
import { failureCode } from "./partial-load.js";
import { FalseRemovalFact } from "./log-bootstrap.js";
import type { LogState } from "./log-state.js";

export async function loadProgressively(
  deps: LocalSyncDeps,
  connectionId: string,
  scope: string,
  context: LogApplyContext,
  head: Segment,
  allRefs: readonly SegmentRef[],
  snapshot: SnapshotPointer | null,
  tail: readonly SegmentRef[],
): Promise<number> {
  const last = allRefs.at(-1);
  if (!last) return 0;
  const expectedHead = last.dataHash.toLowerCase();
  const metadata = (
    await deps.db.query<{
      owner: string;
      network: string;
      device_id: string;
      created_at: number;
    }>("SELECT owner,network,device_id,created_at FROM db_meta WHERE id=1")
  )[0];
  if (!metadata) throw new Error("workspace_missing_database_identity");
  const databaseIncarnation = JSON.stringify([
    metadata.network,
    metadata.device_id,
    metadata.created_at,
  ]);
  const binding: Omit<WorkspaceBinding, "operation"> = {
    owner: metadata.owner,
    databaseIncarnation,
    connection: connectionId,
    generation: context.generation,
    keyCheck: context.keyCheck,
    expectedHead,
    codecVersion: 1,
  };
  const hadPartial =
    (
      await deps.db.query(
        "SELECT 1 n FROM stream_partial WHERE connection_id=? LIMIT 1",
        [connectionId],
      )
    )[0] !== undefined;
  const initialPosition =
    (
      await deps.db.query<{ position: number }>(
        "SELECT position FROM log_state WHERE connection_id=?",
        [connectionId],
      )
    )[0]?.position ?? 0;
  // A new registry identity fences old facts before any new visibility is adopted.
  const ws = await openProgressiveLogWorkspace(deps.db, binding, deps.newOp);
  const operation = ws.binding.operation;
  const saved = await ws.partial.plan();
  if (saved) {
    snapshot = saved.snapshot ? (head.snapshot ?? null) : null;
    tail = allRefs.filter((ref) => ref.position > saved.start);
  } else {
    // Incomplete rows of a previous registry head must be rebuilt from the
    // current base; a newer tail alone cannot validate their old visibility.
    if (hadPartial) {
      snapshot = head.snapshot ?? null;
      tail = allRefs.filter((ref) => ref.position > head.base);
    }
  }
  const parts = snapshot?.parts ?? [];
  const total = parts.length + tail.length;
  if (total === 0) return 0;
  const identityAt = (index: number): BatchIdentity =>
    index < parts.length
      ? {
          dataHash: parts[index]!.dataHash.toLowerCase(),
          blobName: snapshotPartBlobName(parts[index]!.dataHash),
        }
      : {
          dataHash: tail[index - parts.length]!.dataHash.toLowerCase(),
          blobName: segmentBlobName(tail[index - parts.length]!.dataHash),
        };
  await ws.partial.initialize(
    saved ?? {
      start: snapshot?.position ?? tail[0]!.position - 1,
      snapshot: snapshot !== null,
      total,
      finalIdentity: identityAt(total - 1),
      observedAt: head.observedAt,
    },
  );
  const lease = await ws.acquire(128 * 1024 * 1024);
  const readUnit = async (index: number) => {
    if (index < parts.length) {
      const part = await fetchSnapshotPartWire(
        deps,
        scope,
        context,
        parts[index]!.dataHash,
        snapshot!.position,
      );
      if (part.index !== index || part.generation !== context.generation)
        throw new Error("apply: invalid log snapshot part (inconsistent)");
      return {
        generation: part.generation,
        observedAt: 0,
        streams: part.streams,
        operations: part.entries,
      };
    }
    const ref = tail[index - parts.length]!;
    const { segment } = await fetchSegmentWire(
      deps,
      scope,
      context,
      ref.dataHash,
      ref.position,
    );
    if (ref.removes === false && segmentRemoves(segment.operations))
      throw new FalseRemovalFact();
    return segment;
  };
  const stateAt = (index: number): LogState | undefined => {
    if (index < parts.length)
      return index === parts.length - 1 && snapshot!.position > initialPosition
        ? {
            position: snapshot!.position,
            base: head.base,
            refs: allRefs.filter((ref) => ref.position <= snapshot!.position),
            snapshot,
          }
        : undefined;
    const ref = tail[index - parts.length]!;
    if (ref.position <= initialPosition) return undefined;
    return {
      position: ref.position,
      base: head.base,
      refs: allRefs.filter((r) => r.position <= ref.position),
      snapshot: head.snapshot,
    };
  };
  try {
    for (const meta of head.streams)
      await ws.partial.name(total - 1, meta, head, identityAt(total - 1), true);
    announceApplied(deps, connectionId);
    // The scan never resolves an out-of-line body or retains the unit it read.
    // A receipt is written only after every fact of that verified unit is durable.
    for (let index = 0; index < total; index++) {
      const identity = identityAt(index);
      if (await ws.partial.hasScan(index, identity)) continue;
      const batch = await readUnit(index);
      if (index < parts.length) {
        await ws.partial.snapshotSchema(
          bytesToHex(
            sha256(new TextEncoder().encode(canonicalJson(batch.streams))),
          ),
        );
      }
      for (const meta of batch.streams)
        await ws.partial.name(index, meta, batch, identity);
      let facts: Parameters<typeof ws.partial.noteKeys>[1][number][] = [];
      let factBytes = 0;
      const note = async (
        fact: Parameters<typeof ws.partial.noteKeys>[1][number],
      ) => {
        const bytes = new TextEncoder().encode(JSON.stringify(fact)).length;
        if (facts.length === 64 || factBytes + bytes > 60 * 1024) {
          await ws.partial.noteKeys(index, facts);
          facts = [];
          factBytes = 0;
        }
        facts.push(fact);
        factBytes += bytes;
      };
      for (const op of batch.operations) {
        if (op.kind === "complete") {
          for (const omission of op.omitted)
            await note({
              stream: op.stream,
              pkHash: omission.pkHash,
              key: omission.key,
              removal: op.cutoff,
            });
        } else if (op.kind === "delete" || op.kind === "omitted")
          await note({
            stream: op.stream,
            pkHash: op.pkHash,
            key: op.key,
            removal: op.stamp,
          });
        else {
          const meta = batch.streams.find((meta) => meta.stream === op.stream)!;
          const key: LogKey | null =
            op.kind === "upsert-ref"
              ? null
              : (meta.primaryKey.map((field) => op.value[field]) as LogKey);
          await note({
            stream: op.stream,
            pkHash: op.pkHash,
            key,
            removal: null,
          });
        }
      }
      if (facts.length) await ws.partial.noteKeys(index, facts);
      await ws.partial.scanned(index, identity);
    }
    for (let index = 0; index < total; index++) {
      const identity = identityAt(index);
      if (await ws.partial.applied(index, identity)) continue;
      await ws.partial.clearPart(index);
      const batch = await readUnit(index);
      for (const operation of batch.operations) {
        if (operation.kind === "upsert-ref")
          await ws.partial.admitRecord(operation.body.bytes, lease);
        const resolved = await resolveBodies(deps, scope, [operation]);
        const prepared = await prepareOperations(batch.streams, resolved);
        for (const row of prepared)
          await ws.partial.stageOperation(index, row, lease);
      }
      await ws.partial.commitPart(
        index,
        { ...batch, operations: [] },
        identity,
        deps.newOp,
        lease,
        stateAt(index),
      );
      announceApplied(deps, connectionId);
    }
    await ws.partial.close();
    while (await ws.cleanupOne()) {
      /* One indexed metadata row/value per call. */
    }
    return total;
  } catch (error) {
    await ws.partial
      .failed(failureCode(error), error instanceof FalseRemovalFact)
      .then(
        () => announceApplied(deps, connectionId),
        () => undefined,
      );
    throw error;
  } finally {
    await lease.release();
    await runtimeAdmission.finish(deps.db, operation);
  }
}
