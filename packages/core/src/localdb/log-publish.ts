// The writer of the stream-sync log (stream-sync/src/log.ts).
//
// One round publishes one batch: the changes of every stream that has work,
// as ONE immutable segment object (one PUT) and ONE registry commit that
// advances the connection's log position. The per-stream path writes a head
// and parts per stream; here request count does not grow with stream count.
//
//   SNAPSHOT (slot)   Decide, for each stream, what its publish is: apply the
//     retained runs' plan (`planStream`), select the changes since the stream's
//     watermark, read the changed records, and, for a stream whose newest
//     replacing run still applies, list the keys that run dropped. Build the
//     segment, encode, hash, encrypt. Read nothing from the registry unless the
//     connection's control row is not yet known to be active here.
//   TRANSFER (no slot)  Upload the attachments, then the segment.
//   COMMIT (slot)     Re-read the basis. Post one row for the log scope at
//     version position+1 with a condition on the control row, in one request.
//     A 409 applies the winner and starts the round over; a failed control
//     condition purges or defers. On success one local batch: replace
//     deletes, each touched stream's local head, watermarks, run evidence, the
//     log position, and compaction of `record_changes`.
//
// A batch is bounded by the part target: a round takes the changes of streams
// in order until the target is reached and leaves the rest for the next round,
// except that a stream whose replacing run applies goes whole (its omission
// completion and its changes are one unit). A single record larger than the
// target still goes, alone.
//
// What this writer leaves to the per-stream path: nothing is published through
// it. Runs it cannot place (refused, fenced, from another lifetime) are
// cleaned up with the same helpers publish uses, and the round starts over;
// runs it cannot order yet (deferred) hold only their own stream.
//
// Compaction rides the batch's own commit (log-compact.ts): when the cost rule
// or the head's bound says so, the segment carries a snapshot pointer, a new
// `base`, and no refs at or below it.

import { keccak_256 } from "@noble/hashes/sha3";
import {
  LOG_FORMAT,
  DEFAULT_PART_TARGET_BYTES,
  classifyControl,
  compactionRequired,
  controlHashes,
  controlScope,
  deriveKeyCheck,
  digestSegment,
  encodeSegment,
  logScope,
  streamScope,
  verifySegment,
  type ControlHashes,
  type LogOperation,
  type LogStreamMeta,
  type Segment,
  type SegmentRef,
  type SnapshotPointer,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { type StreamSyncRegistry } from "../stream-sync/ports.js";
import { sameHead, type PlanHead } from "../stream-sync/publish-plan.js";
import { applyConnection } from "./apply.js";
import { listStreamBlobs, uploadBlobs, type BlobDescriptor } from "./blobs.js";
import { settleRequirementFailure, settleRow } from "./batch-commit.js";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";
import { tombstoneOmissions } from "./admit.js";
import { planCompaction } from "./log-compact.js";
import { readLogState, writeLogState, type LogState } from "./log-apply.js";
import {
  replaceDelete,
  seenBeforeParams,
  SEEN_BEFORE,
  withOrigin,
} from "./merge.js";
import {
  discardFencedRuns,
  discardForeignLifetimeRuns,
  excludeSeedsIfAny,
  hasDeleteIntent,
  lifetimeHolds,
  metadataHashFor,
  planStream,
  postBatchOnce,
  runPublicationStatements,
  type ConnectionRow,
  type LocalStream,
  type PublishResult,
  type StreamPlan,
} from "./publish.js";
import { purgeConnection } from "./purge.js";
import { insideQueue } from "./slot.js";
import { unwriteRefusedRun } from "./unwrite.js";

const keccak = async (bytes: Uint8Array) => keccak_256(bytes);
const MAX_ATTEMPTS = 5;
const KEYS_PER_QUERY = 400;

/** Registries that answered the batch route with 404 or 405: the log needs it. */
const withoutBatchRoute = new WeakSet<StreamSyncRegistry>();

type StreamRow = LocalStream & { stream: string };

type Planned = {
  readonly stream: string;
  readonly local: LocalStream;
  readonly plan: StreamPlan;
  /** MAX(seq) of the stream's changes at the snapshot. */
  readonly watermark: number;
  /** What a successful commit acknowledges for the stream. */
  readonly ack: number;
  /** In this round's segment. */
  readonly included: boolean;
  /** Changes of the stream wait for a later round. */
  readonly rest: boolean;
  readonly operations: LogOperation[];
  readonly meta: LogStreamMeta | null;
  readonly runIds: readonly string[];
  readonly replace: { readonly o: number; readonly r: string } | null;
  readonly omitted: readonly string[];
  readonly bytes: number;
};

type Candidate = {
  readonly basis: string;
  readonly state: LogState;
  /** What the segment carries: after a compaction, `base` is the folded position and `refs` is empty. */
  readonly base: number;
  readonly refs: readonly SegmentRef[];
  readonly snapshot: SnapshotPointer | null;
  /** Snapshot part objects to upload before the segment. */
  readonly snapshotParts: readonly {
    readonly name: string;
    readonly cipher: Uint8Array;
  }[];
  readonly position: number;
  readonly generation: number;
  readonly dataHash: `0x${string}`;
  readonly blobName: string;
  readonly cipher: Uint8Array;
  readonly clearBytes: number;
  readonly observedAt: number;
  readonly planned: readonly Planned[];
  readonly attachments: readonly BlobDescriptor[];
  readonly controlDataHash: `0x${string}`;
  readonly prevHash: `0x${string}` | null;
};

type Snapshot =
  | {
      readonly kind: "done";
      readonly results: PublishResult[];
      /** Attachments to upload even though no segment is committed. */
      readonly attachments?: readonly BlobDescriptor[];
    }
  | { readonly kind: "retry" }
  | { readonly kind: "candidate"; readonly candidate: Candidate };

type Committed =
  | {
      readonly kind: "done";
      readonly results: PublishResult[];
      readonly more: boolean;
    }
  | { readonly kind: "retry"; readonly conflict: boolean }
  | { readonly kind: "unsupported" };

/**
 * Publish a connection through the log. `null`: this registry has no batch
 * route, so the caller publishes per stream.
 */
export async function publishLog(
  deps: LocalSyncDeps,
  connectionId: string,
): Promise<readonly PublishResult[] | null> {
  if (!deps.registry.postBatch || withoutBatchRoute.has(deps.registry))
    return null;
  const results = new Map<string, PublishResult>();
  const keep = (list: readonly PublishResult[]) => {
    for (const result of list) {
      const earlier = results.get(result.stream);
      if (earlier?.outcome === "published" && result.outcome !== "published")
        continue;
      results.set(result.stream, result);
    }
  };
  let attempts = 0;
  for (;;) {
    const turn = await deps.queue.run(connectionId, "publish", async () => {
      const held = insideQueue(deps, connectionId);
      return snapshotRound(held, connectionId);
    });
    if (turn.kind === "done") {
      // Bytes that arrived after their records were published still go up.
      if (turn.attachments && turn.attachments.length > 0)
        await uploadBlobs(deps, turn.attachments);
      keep(turn.results);
      break;
    }
    if (turn.kind === "retry") {
      if (++attempts >= MAX_ATTEMPTS) {
        keep(await backoff(deps, connectionId));
        break;
      }
      continue;
    }
    const { candidate } = turn;
    // TRANSFER: no slot. Objects are content addressed and authorize nothing
    // until the registry commit.
    if (candidate.attachments.length > 0)
      await uploadBlobs(deps, candidate.attachments);
    const scope = await logScopeOf(deps, connectionId);
    // Snapshot parts, then the segment that names them.
    await Promise.all(
      candidate.snapshotParts.map((part) =>
        deps.blobs.put(`${scope}/${part.name}`, part.cipher),
      ),
    );
    await deps.blobs.put(`${scope}/${candidate.blobName}`, candidate.cipher);

    const committed = await deps.queue.run(connectionId, "publish", () =>
      commitRound(insideQueue(deps, connectionId), connectionId, candidate),
    );
    if (committed.kind === "unsupported") {
      withoutBatchRoute.add(deps.registry);
      return results.size > 0 ? [...results.values()] : null;
    }
    if (committed.kind === "retry") {
      if (++attempts >= MAX_ATTEMPTS) {
        keep(await backoff(deps, connectionId));
        break;
      }
      continue;
    }
    keep(committed.results);
    attempts = 0;
    if (!committed.more) break;
  }
  return [...results.values()].sort((a, b) => a.stream.localeCompare(b.stream));
}

async function logScopeOf(
  deps: LocalSyncDeps,
  connectionId: string,
): Promise<string> {
  const [row] = await deps.db.query<{ connector: string; ns: string }>(
    "SELECT connector, ns FROM connections WHERE connection_id = ?",
    [connectionId],
  );
  return logScope(row!.connector, row!.ns);
}

async function backoff(
  deps: LocalSyncDeps,
  connectionId: string,
): Promise<PublishResult[]> {
  const streams = await deps.db.query<{ stream: string }>(
    "SELECT stream FROM stream_state WHERE connection_id = ? ORDER BY stream",
    [connectionId],
  );
  return streams.map(({ stream }) => ({
    stream,
    outcome: "backoff" as const,
    watermark: null,
  }));
}

const chunked = <T>(items: readonly T[], size: number): T[][] => {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size)
    out.push(items.slice(i, i + size));
  return out;
};

async function snapshotRound(
  held: LocalSyncDeps,
  connectionId: string,
): Promise<Snapshot> {
  const [connection] = await held.db.query<
    ConnectionRow & { control_state: string }
  >(
    "SELECT connector, ns, generation, control_state FROM connections WHERE connection_id = ?",
    [connectionId],
  );
  if (!connection)
    throw new Error(`publish: unknown connection ${connectionId}`);
  const streams = await held.db.query<StreamRow>(
    `SELECT stream, primary_key, profile_key, profile_version, complete,
            floor_version, floor_o, floor_r, last_delete_version,
            head_version, head_generation, head_data_hash, publish_watermark
       FROM stream_state WHERE connection_id = ? ORDER BY stream`,
    [connectionId],
  );
  const all = (outcome: PublishResult["outcome"]): Snapshot => ({
    kind: "done",
    results: streams.map(({ stream }) => ({
      stream,
      outcome,
      watermark: null,
    })),
  });
  if (await hasDeleteIntent(held, connection.connector)) return all("deferred");
  if (streams.length === 0) return { kind: "done", results: [] };
  const keyCheck = await deriveKeyCheck(held.keys.namespaceHmac);
  const hashes = await controlHashes(keccak, keyCheck);

  // Control. A connection this device already holds as active is confirmed by
  // the commit's own condition; only an unknown one is read here.
  const controlDataHash = hashes.activeData;
  if (connection.control_state !== "active") {
    const settled = await establishControl(
      held,
      connectionId,
      connection,
      hashes,
    );
    if (settled === "retry") return { kind: "retry" };
    if (settled !== "active") return all(settled);
  }
  if (
    await discardForeignLifetimeRuns(held, connectionId, connection.generation)
  ) {
    await applyConnection(held, connectionId);
    return { kind: "retry" };
  }
  await held.db.batch([
    {
      sql: "UPDATE connections SET control_state='active',control_version=? WHERE connection_id=?",
      params: [connection.generation, connectionId],
    },
    {
      sql: "UPDATE runs SET generation=? WHERE connection_id=? AND generation IS NULL AND state='ended'",
      params: [connection.generation, connectionId],
    },
  ]);

  const log = await readLogState(held, connectionId);
  const planned: Planned[] = [];
  const target = held.partTargetBytes ?? DEFAULT_PART_TARGET_BYTES;
  let budget = 0;
  let first = true;
  for (const row of streams) {
    const { stream } = row;
    if (await discardFencedRuns(held, connectionId, stream)) {
      await applyConnection(held, connectionId);
      return { kind: "retry" };
    }
    if (connection.generation !== 1)
      await excludeSeedsIfAny(held, connectionId, stream);
    const plan = await planStream(
      held,
      connectionId,
      connection,
      stream,
      row,
      null,
      row.head_version,
      row.head_data_hash,
    );
    if (plan.refused) {
      await unwriteRefusedRun(held, {
        connectionId,
        stream,
        runId: plan.refused.runId,
        reason: plan.refused.reason,
      });
      await applyConnection(held, connectionId);
      return { kind: "retry" };
    }
    const [wRow] = await held.db.query<{ w: number | null }>(
      "SELECT MAX(seq) AS w FROM record_changes WHERE connection_id = ? AND stream = ?",
      [connectionId, stream],
    );
    const watermark = wRow?.w ?? row.publish_watermark;
    const base: Planned = {
      stream,
      local: row,
      plan,
      watermark,
      ack: watermark,
      included: false,
      rest: false,
      operations: [],
      meta: null,
      runIds: plan.steps.map((step) => step.runId),
      replace: null,
      omitted: [],
      bytes: 0,
    };
    if (plan.deferred) {
      planned.push({ ...base, ack: row.publish_watermark });
      continue;
    }
    // The stream's local head stands for the log's last segment that touched
    // it (see `applySegmentOperations`): a replacing run applies only if no
    // segment touched the stream since the run began.
    const replace = plan.replaceBelow ?? null;
    const omitted = replace
      ? await omittedBy(held, connectionId, stream, replace)
      : [];
    const groups = await changedKeys(
      held,
      connectionId,
      stream,
      row.publish_watermark,
      watermark,
    );
    // A stream with no head yet (a first collection that publishes while it
    // collects) is described by its local state, as the per-stream path does.
    const head: PlanHead | null =
      plan.finalHead ??
      (groups.length > 0
        ? {
            generation: row.head_generation ?? connection.generation,
            primaryKey: JSON.parse(row.primary_key),
            profile: {
              key: row.profile_key ?? connection.connector,
              version: row.profile_version ?? row.floor_version ?? "0",
            },
            complete: false,
          }
        : null);
    const metaChanged =
      head !== null &&
      (row.head_version === 0 ||
        !sameHead(head, {
          generation: row.head_generation ?? head.generation,
          primaryKey: JSON.parse(row.primary_key),
          profile: {
            key: row.profile_key ?? connection.connector,
            version: row.profile_version ?? "0",
          },
          complete: row.complete === 1,
        }));
    const hasWork =
      groups.length > 0 ||
      replace !== null ||
      (metaChanged && plan.steps.some((s) => s.decision.kind === "publish"));
    if (!hasWork || head === null) {
      planned.push({ ...base, runIds: base.runIds });
      continue;
    }
    // Changes go in the order they were made, until the segment reaches the
    // part target, measured on the operations themselves. A stream that
    // replaces goes whole (its completion and its changes are one unit), but
    // still waits for the next round if the segment is full. The first thing
    // in a segment always goes, however large, so a round always progresses.
    const room = (size: number) => first || budget + size <= target;
    const atomic = replace !== null;
    const selected: { pk: string; seq: number }[] = [];
    const taken: LogOperation[] = [];
    let bytes = omitted.length * 70 + 100;
    let rest = false;
    if (atomic) {
      const found = await operationsFor(
        held,
        connectionId,
        stream,
        groups.map((g) => g.pk),
        row.publish_watermark,
        watermark,
      );
      const size =
        bytes + [...found.values()].reduce((n, op) => n + opSize(op), 0);
      if (!room(size)) {
        planned.push({ ...base, ack: row.publish_watermark, rest: true });
        continue;
      }
      selected.push(...groups);
      taken.push(...found.values());
      bytes = size;
    } else {
      scan: for (const batch of chunked(groups, KEYS_PER_QUERY)) {
        const found = await operationsFor(
          held,
          connectionId,
          stream,
          batch.map((g) => g.pk),
          row.publish_watermark,
          watermark,
        );
        for (const group of batch) {
          const op = found.get(group.pk);
          const size = op ? opSize(op) : 0;
          if (!room(bytes + size)) {
            rest = true;
            break scan;
          }
          selected.push(group);
          if (op) taken.push(op);
          bytes += size;
          first = false;
        }
      }
      if (selected.length === 0 && groups.length > 0) {
        planned.push({ ...base, ack: row.publish_watermark, rest: true });
        continue;
      }
    }
    budget += bytes;
    first = false;
    const ack = rest ? selected.at(-1)!.seq : watermark;
    planned.push({
      ...base,
      included: true,
      rest,
      ack,
      operations: [
        ...orderedOperations(taken),
        ...(replace
          ? [
              {
                kind: "complete" as const,
                stream,
                cutoff: { o: replace.o, r: replace.r },
                omitted,
              },
            ]
          : []),
      ],
      meta: {
        stream,
        primaryKey: head.primaryKey,
        profile: head.profile as LogStreamMeta["profile"],
        complete: head.complete,
      },
      replace,
      omitted,
      bytes,
    });
  }

  const included = planned.filter((p) => p.included);
  const settle = (outcomeFor: (p: Planned) => PublishResult["outcome"]) =>
    planned.map((p): PublishResult => ({
      stream: p.stream,
      outcome: outcomeFor(p),
      watermark: p.watermark,
    }));
  // Attachments named by any stream's records, published or not yet: bytes can
  // arrive after the records that name them were published.
  const attachments: BlobDescriptor[] = [];
  for (const p of planned)
    if (!p.plan.deferred)
      attachments.push(
        ...(await listStreamBlobs(held, {
          connectionId,
          stream: p.stream,
          scope: streamScope(connection.connector, connection.ns, p.stream),
          generation: connection.generation,
        })),
      );
  if (included.length === 0) {
    // Nothing to publish. Record that every covered run was already saved by
    // what the log holds, move the watermarks, and compact.
    await commitIdle(held, connectionId, planned, log);
    return {
      kind: "done",
      results: settle((p) => (p.plan.deferred ? "deferred" : "noop")),
      attachments,
    };
  }

  const scope = logScope(connection.connector, connection.ns);
  // The log is folded into a snapshot when that is cheaper than replaying it
  // (or it is at the head's bound), and this segment carries the result.
  const compaction = await planCompaction(held, {
    connector: connection.connector,
    ns: connection.ns,
    generation: connection.generation,
    keyCheck,
    scope,
    log,
  });
  const base = compaction ? log.position : log.base;
  const refs = compaction ? [] : log.refs;
  const snapshot = compaction ? compaction.snapshot : log.snapshot;
  if (compactionRequired(refs.length, snapshot?.parts.length ?? 0)) {
    held.logger.warn(
      { connectionId, refs: refs.length, parts: snapshot?.parts.length ?? 0 },
      "stream sync: the log head is full even after compaction",
    );
    return all("deferred");
  }
  const position = log.position + 1;
  const observedAt = Math.max(
    ...included.map((p) => p.plan.newestRunObservedAt ?? 0),
    0,
  );
  const segment: Segment = {
    format: LOG_FORMAT,
    connector: connection.connector,
    ns: connection.ns,
    generation: connection.generation,
    keyCheck,
    position,
    observedAt: observedAt || held.now(),
    base,
    snapshot,
    refs,
    streams: included.map((p) => p.meta!),
    operations: included.flatMap((p) => p.operations),
  };
  const clear = encodeSegment(segment);
  const { dataHash, blobName } = await digestSegment(keccak, clear);
  // A segment that would not verify is never uploaded or posted.
  const verified = await verifySegment(keccak, clear, {
    dataHash,
    connector: connection.connector,
    ns: connection.ns,
    keyCheck,
    position,
  });
  if (verified.kind !== "ok")
    throw new Error(
      `publish: the log segment failed verification: ${verified.kind}`,
    );
  const cipher = await held.keys.encrypt(scope, clear);
  return {
    kind: "candidate",
    candidate: {
      basis: await basisOf(held, connectionId, planned, log),
      state: log,
      base,
      refs,
      snapshot,
      snapshotParts: compaction?.parts ?? [],
      position,
      generation: connection.generation,
      dataHash,
      blobName,
      cipher,
      clearBytes: clear.length,
      observedAt: segment.observedAt,
      planned,
      attachments,
      controlDataHash,
      prevHash: log.refs.at(-1)?.dataHash ?? null,
    },
  };
}

function opSize(op: LogOperation): number {
  return op.kind === "upsert"
    ? 160 + JSON.stringify(op.value).length
    : op.kind === "delete"
      ? 160
      : 100 + op.omitted.length * 70;
}

/** A stream that has not been published has its own scope for blobs only. */
async function establishControl(
  held: LocalSyncDeps,
  connectionId: string,
  connection: ConnectionRow,
  hashes: ControlHashes,
): Promise<"active" | "retry" | PublishResult["outcome"]> {
  const control = controlScope(connection.connector, connection.ns);
  let read = await held.registry.read(control);
  let state = classifyControl(read, hashes);
  if (state.kind === "absent") {
    if (connection.generation !== 1) return "deferred";
    const signature = await held.signer.signAddData({
      ownerAddress: held.ownerAddress,
      scope: control,
      dataHash: hashes.activeData,
      metadataHash: hashes.activeMetadata,
      expectedVersion: 1n,
    });
    await held.registry.post({
      ownerAddress: held.ownerAddress,
      scope: control,
      dataHash: hashes.activeData,
      metadataHash: hashes.activeMetadata,
      expectedVersion: "1",
      signature,
    });
    read = await held.registry.read(control);
    state = classifyControl(read, hashes);
  }
  if (state.kind === "deleted") {
    await purgeConnection(held, connectionId, {
      controlVersion: state.version,
    });
    return "purged";
  }
  if (state.kind !== "active") return "deferred";
  if (state.generation !== connection.generation) {
    await applyConnection(held, connectionId);
    return "deferred";
  }
  return "active";
}

/** The keys a replacing run dropped: held rows last observed before it. */
async function omittedBy(
  deps: LocalSyncDeps,
  connectionId: string,
  stream: string,
  replace: { o: number; r: string },
): Promise<string[]> {
  const rows = await deps.db.query<{ pk_hash: string }>(
    `SELECT pk_hash FROM records WHERE connection_id = ? AND stream = ?
        AND ${SEEN_BEFORE} ORDER BY pk_hash`,
    [connectionId, stream, ...seenBeforeParams(replace.o, replace.r)],
  );
  return rows.map((row) => row.pk_hash);
}

/** Changed keys since the watermark, oldest change first. */
async function changedKeys(
  deps: LocalSyncDeps,
  connectionId: string,
  stream: string,
  from: number,
  to: number,
): Promise<{ pk: string; seq: number }[]> {
  const rows = await deps.db.query<{ pk_hash: string; seq: number }>(
    `SELECT pk_hash, MAX(seq) AS seq FROM record_changes
      WHERE connection_id = ? AND stream = ? AND seq > ? AND seq <= ?
        AND origin IN ('local', 'import', 'refresh')
        AND NOT EXISTS (SELECT 1 FROM runs r JOIN run_streams rs ON rs.run_id=r.run_id
          WHERE r.connection_id=record_changes.connection_id AND rs.stream=record_changes.stream
            AND r.run_id=record_changes.stamp_r AND r.o=record_changes.stamp_o
            AND r.admitting = 0
            AND rs.decision IN ('refused','discarded'))
      GROUP BY pk_hash ORDER BY MAX(seq)`,
    [connectionId, stream, from, to],
  );
  return rows.map((row) => ({ pk: row.pk_hash, seq: row.seq }));
}

/**
 * The operations for these keys: a held row is an upsert at its stamp; a key
 * with no row and an explicit delete in the window is a delete at the stamp of
 * that delete. A key with no row and no explicit delete is nothing to say: a
 * replacing run's drop travels as its completion, and a refused run's rows
 * were never published.
 */
async function operationsFor(
  deps: LocalSyncDeps,
  connectionId: string,
  stream: string,
  keys: readonly string[],
  from: number,
  to: number,
): Promise<Map<string, LogOperation>> {
  const ops = new Map<string, LogOperation>();
  for (const group of chunked(keys, KEYS_PER_QUERY)) {
    const marks = group.map(() => "?").join(",");
    const rows = await deps.db.query<{
      pk_hash: string;
      stamp_o: number;
      stamp_r: string;
      first_o: number | null;
      body: string;
    }>(
      `SELECT pk_hash, stamp_o, stamp_r, first_o, body FROM records
        WHERE connection_id = ? AND stream = ? AND pk_hash IN (${marks})`,
      [connectionId, stream, ...group],
    );
    const held = new Set(rows.map((row) => row.pk_hash));
    for (const row of rows)
      ops.set(row.pk_hash, {
        kind: "upsert",
        stream,
        pkHash: row.pk_hash,
        stamp: { o: row.stamp_o, r: row.stamp_r },
        firstSeen: row.first_o,
        value: JSON.parse(row.body),
      });
    const gone = group.filter((pk) => !held.has(pk));
    if (gone.length === 0) continue;
    const goneMarks = gone.map(() => "?").join(",");
    const deletes = await deps.db.query<{
      pk_hash: string;
      stamp_o: number;
      stamp_r: string;
    }>(
      `SELECT pk_hash, stamp_o, stamp_r, MAX(seq) FROM record_changes
        WHERE connection_id = ? AND stream = ? AND seq > ? AND seq <= ?
          AND op = 'remove' AND explicit_delete = 1 AND pk_hash IN (${goneMarks})
        GROUP BY pk_hash`,
      [connectionId, stream, from, to, ...gone],
    );
    for (const row of deletes)
      ops.set(row.pk_hash, {
        kind: "delete",
        stream,
        pkHash: row.pk_hash,
        stamp: { o: row.stamp_o, r: row.stamp_r },
      });
  }
  return ops;
}

/** Upserts, then deletes, each by key: one order for every writer. */
function orderedOperations(ops: readonly LogOperation[]): LogOperation[] {
  return [...ops].sort(
    (a, b) =>
      (a.kind === "upsert" ? 0 : 1) - (b.kind === "upsert" ? 0 : 1) ||
      (a as { pkHash: string }).pkHash.localeCompare(
        (b as { pkHash: string }).pkHash,
      ),
  );
}

/**
 * The local state a candidate rests on, as one comparable key: the connection,
 * the log position, delete intents, and per stream its head, its retained
 * runs, the changes the round acknowledges, and the keys a replacement drops.
 * New upserts, deletes and runs above the acknowledged watermark are not in
 * it: they wait for the next round, and a delete above it is an operation of
 * the next segment, not a state the old one must match.
 */
async function basisOf(
  deps: LocalSyncDeps,
  connectionId: string,
  planned: readonly Planned[],
  log: LogState,
): Promise<string> {
  const [connection] = await deps.db.query(
    "SELECT generation, control_state, control_version FROM connections WHERE connection_id = ?",
    [connectionId],
  );
  const intents = await deps.db.query(
    "SELECT delete_id, intent FROM delete_intents",
  );
  const streams: unknown[] = [];
  for (const p of planned) {
    const [state] = await deps.db.query(
      `SELECT head_version, head_generation, head_data_hash, last_delete_version, publish_watermark
         FROM stream_state WHERE connection_id = ? AND stream = ?`,
      [connectionId, p.stream],
    );
    const runs = await deps.db.query(
      `SELECT r.run_id, r.state, r.generation, rs.decision, rs.replace
         FROM runs r JOIN run_streams rs ON rs.run_id = r.run_id
        WHERE r.connection_id = ? AND rs.stream = ? AND r.state = 'ended'
          AND rs.decision IN ('publish','noop','deferred','refused','discarded')
        ORDER BY r.run_id`,
      [connectionId, p.stream],
    );
    const covered = await deps.db.query(
      `SELECT COUNT(*) AS n, MAX(seq) AS newest FROM record_changes
        WHERE connection_id = ? AND stream = ? AND seq > ? AND seq <= ?`,
      [connectionId, p.stream, p.local.publish_watermark, p.ack],
    );
    const omitted = p.replace
      ? await omittedBy(deps, connectionId, p.stream, p.replace)
      : [];
    streams.push([p.stream, state, runs, covered, omitted]);
  }
  return JSON.stringify([connection, log, intents, streams]);
}

/** Nothing to write: run evidence for what the log already holds, then compact. */
async function commitIdle(
  deps: LocalSyncDeps,
  connectionId: string,
  planned: readonly Planned[],
  log: LogState,
): Promise<void> {
  const statements: SqlStatement[] = [];
  for (const p of planned) {
    if (p.plan.deferred || p.rest) continue;
    if (p.local.head_version > 0 && p.local.head_data_hash !== null)
      statements.push(
        ...(await runPublicationStatements(deps, connectionId, p.stream, {
          version: log.position,
          generation: p.local.head_generation ?? 1,
          dataHash: p.local.head_data_hash as `0x${string}`,
          watermark: p.ack,
          replaceBelow: undefined,
          runIds: p.runIds,
        })),
      );
    statements.push({
      sql: "UPDATE stream_state SET publish_watermark = ? WHERE connection_id = ? AND stream = ? AND publish_watermark < ?",
      params: [p.ack, connectionId, p.stream, p.ack],
    });
  }
  statements.push(...(await compaction(deps, connectionId, planned)));
  if (statements.length > 0)
    await deps.db.batch(withOrigin("refresh", statements));
}

async function compaction(
  deps: LocalSyncDeps,
  connectionId: string,
  planned: readonly Planned[],
): Promise<SqlStatement[]> {
  const [pending] = await deps.db.query<{ n: number }>(
    "SELECT COUNT(*) AS n FROM import_ledger WHERE connection_id = ? AND state = 'imported'",
    [connectionId],
  );
  if ((pending?.n ?? 0) > 0) return [];
  const lowest = Math.min(
    ...planned.map((p) =>
      p.plan.deferred || (p.rest && !p.included)
        ? p.local.publish_watermark
        : p.ack,
    ),
  );
  if (!Number.isFinite(lowest)) return [];
  return [
    {
      sql: "DELETE FROM record_changes WHERE connection_id = ? AND seq <= ?",
      params: [connectionId, lowest],
    },
  ];
}

async function commitRound(
  held: LocalSyncDeps,
  connectionId: string,
  candidate: Candidate,
): Promise<Committed> {
  const [connection] = await held.db.query<ConnectionRow>(
    "SELECT connector, ns, generation FROM connections WHERE connection_id = ?",
    [connectionId],
  );
  if (!connection || connection.generation !== candidate.generation)
    return { kind: "retry", conflict: false };
  const log = await readLogState(held, connectionId);
  if (
    (await basisOf(held, connectionId, candidate.planned, log)) !==
    candidate.basis
  )
    return { kind: "retry", conflict: false };
  const results = (outcome: PublishResult["outcome"]): Committed => ({
    kind: "done",
    more: false,
    results: candidate.planned.map((p): PublishResult => ({
      stream: p.stream,
      outcome: p.included ? outcome : "deferred",
      watermark: p.watermark,
    })),
  });
  if (await hasDeleteIntent(held, connection.connector))
    return results("deferred");

  const scope = logScope(connection.connector, connection.ns);
  const control = controlScope(connection.connector, connection.ns);
  const keyCheck = await deriveKeyCheck(held.keys.namespaceHmac);
  const hashes = await controlHashes(keccak, keyCheck);
  const metadataHash = metadataHashFor(
    scope,
    new Date(candidate.observedAt).toISOString(),
    candidate.cipher.length,
  );
  const signature = await held.signer.signAddData({
    ownerAddress: held.ownerAddress,
    scope,
    dataHash: candidate.dataHash,
    metadataHash,
    expectedVersion: BigInt(candidate.position),
  });
  const row = {
    scope,
    dataHash: candidate.dataHash,
    metadataHash,
    expectedVersion: String(candidate.position),
    signature,
    ...(candidate.prevHash !== null && {
      expectedHeadDataHash: candidate.prevHash,
    }),
  };
  const answer = await postBatchOnce(held.registry, {
    ownerAddress: held.ownerAddress,
    rows: [row],
    requires: [
      {
        scope: control,
        expectedVersion: String(connection.generation),
        notDeleted: true,
        expectedDataHash: hashes.activeData,
      },
    ],
  });
  if (answer.kind === "unsupported") return { kind: "unsupported" };
  if (answer.kind === "precondition_failed") {
    const verdict = answer.failure
      ? settleRequirementFailure(answer.failure, control)
      : null;
    if (verdict?.kind === "purge") {
      await purgeConnection(held, connectionId, {
        controlVersion: verdict.controlVersion,
      });
      return results("purged");
    }
    return results("deferred");
  }
  if (!(await lifetimeHolds(held, connectionId, connection.generation)))
    return results("deferred");
  const settlement = settleRow(answer.rows[0]!, {
    expectedVersion: row.expectedVersion,
    dataHash: row.dataHash,
  });
  if (settlement === "conflict") {
    // Another writer holds this position. Take its segments, then plan again.
    await applyConnection(held, connectionId);
    return { kind: "retry", conflict: true };
  }
  if (await hasDeleteIntent(held, connection.connector))
    return results("deferred");

  // The registry took the segment: record it, in one batch.
  const newRef: SegmentRef = {
    position: candidate.position,
    dataHash: candidate.dataHash,
    bytes: candidate.clearBytes,
  };
  const statements: SqlStatement[] = [];
  const touched = candidate.planned.filter((p) => p.included);
  for (const p of touched) {
    if (p.replace)
      statements.push(
        // Remember what the replace drops before it drops it (admit.ts), so a
        // run still collecting cannot bring those rows back.
        tombstoneOmissions(
          connectionId,
          p.stream,
          p.replace.o,
          p.replace.r,
          held.publishWhileCollecting === true,
        ),
        replaceDelete(connectionId, p.stream, p.replace.o, p.replace.r),
      );
  }
  for (const p of touched) {
    const meta = p.meta!;
    statements.push(
      {
        sql: `INSERT OR REPLACE INTO stream_versions (connection_id, stream, version, generation,
                head_blob, head_format, record_count, observed_at, complete, kind)
              SELECT ?, ?, MAX(s.head_version, s.last_delete_version) + 1, ?, ?, ?,
                     (SELECT COUNT(*) FROM records r WHERE r.connection_id = ? AND r.stream = ?),
                     ?, ?, 'published'
                FROM stream_state s WHERE s.connection_id = ? AND s.stream = ?`,
        params: [
          connectionId,
          p.stream,
          candidate.generation,
          candidate.blobName,
          5,
          connectionId,
          p.stream,
          candidate.observedAt,
          meta.complete ? 1 : 0,
          connectionId,
          p.stream,
        ],
      },
      {
        sql: `UPDATE stream_state SET primary_key = ?, profile_key = ?, profile_version = ?, complete = ?,
                head_version = MAX(head_version, last_delete_version) + 1,
                head_generation = ?, head_data_hash = ?, head_blob = ?,
                needs_full = CASE WHEN ? = 1 THEN 0 ELSE needs_full END
              WHERE connection_id = ? AND stream = ?`,
        params: [
          JSON.stringify(meta.primaryKey),
          meta.profile.key,
          meta.profile.version,
          meta.complete ? 1 : 0,
          candidate.generation,
          candidate.dataHash,
          candidate.blobName,
          meta.complete ? 1 : 0,
          connectionId,
          p.stream,
        ],
      },
    );
  }
  for (const p of candidate.planned) {
    if (p.plan.deferred) continue;
    if (!p.rest)
      statements.push(
        ...(await runPublicationStatements(held, connectionId, p.stream, {
          version: candidate.position,
          generation: candidate.generation,
          dataHash: candidate.dataHash,
          watermark: p.ack,
          replaceBelow: p.replace ?? undefined,
          runIds: p.runIds,
        })),
      );
    if (p.included || !p.rest)
      statements.push({
        sql: "UPDATE stream_state SET publish_watermark = ? WHERE connection_id = ? AND stream = ? AND publish_watermark < ?",
        params: [p.ack, connectionId, p.stream, p.ack],
      });
  }
  statements.push(
    writeLogState(connectionId, {
      position: candidate.position,
      base: candidate.base,
      refs: [...candidate.refs, newRef],
      snapshot: candidate.snapshot,
    }),
    ...(await compaction(held, connectionId, candidate.planned)),
  );
  await held.db.batch(withOrigin("refresh", statements));

  const more = candidate.planned.some((p) => p.rest);
  return {
    kind: "done",
    more,
    results: candidate.planned.map((p): PublishResult => ({
      stream: p.stream,
      outcome: p.included ? "published" : p.plan.deferred ? "deferred" : "noop",
      watermark: p.ack,
      ...(p.included && {
        publication: {
          connectionId,
          connector: connection.connector,
          ns: connection.ns,
          stream: p.stream,
          head: {
            version: candidate.position,
            generation: candidate.generation,
            dataHash: candidate.dataHash,
          },
          watermark: p.ack,
          runIds: p.runIds,
        },
      }),
    })),
  };
}
