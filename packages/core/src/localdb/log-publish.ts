// The writer of the stream-sync log (stream-sync/src/log.ts).
//
// One round publishes one batch: the changes of every stream that has work,
// as ONE immutable segment object (one PUT) and ONE registry commit that
// advances the connection's log position, so request count does not grow with
// stream count. It is the only way a connection publishes.
//
//   SNAPSHOT (slot)   Decide, for each stream, what its publish is: apply the
//     retained runs' plan (`planStream`), select the changes since the stream's
//     watermark, read the changed records, and, for a stream whose newest
//     replacing run still applies, list the keys that run dropped. Build the
//     segment, encode, hash, encrypt. Read nothing from the registry unless the
//     connection's control row is not yet known to be active here.
//   TRANSFER (no slot)  Upload the attachments, then the segment.
//   COMMIT (slot)     Re-read the basis. Post one row for the log scope at
//     version position+1 with a condition on the control row, in one
//     all-or-nothing request. A new connection's first save also carries the
//     control row's creation (version 1): the segment's PUT needs no control
//     row (objects are content addressed and authorize nothing until a commit
//     names them), so the creation waits for the commit and costs no round
//     trip of its own. A lost log row applies the winner and starts the round
//     over; a lost control row reads the control row; a failed control
//     condition purges or defers. On success one local batch: replace
//     deletes, each touched stream's local head, watermarks, run evidence, the
//     log position, and compaction of `record_changes`.
//
// A batch is bounded by the part target: a round takes the changes of streams
// in order until the target is reached and leaves the rest for the next round,
// except that a stream whose replacing run applies goes whole (its omission
// completion and its changes are one unit) when the whole fits one segment.
// A larger one goes in rounds, and only the round with its completion says
// the stream is complete. A completion larger than what a round has left goes
// in pieces, each naming a range of the dropped keys in hash order. A single
// record larger than the target goes alone, its body out of line.
//
// Runs it cannot place (refused, fenced, from another lifetime) are cleaned up
// and the round starts over; runs it cannot order yet (deferred) hold only
// their own stream.
//
// Compaction rides the batch's own commit (log-compact.ts): when the cost rule
// or the head's bound says so, the segment carries a snapshot pointer, a new
// `base`, and no refs at or below it.

import { sha256 } from "@noble/hashes/sha2";
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
  segmentRemoves,
  deletionKeyMatchesHash,
  firstDeletionKeyMismatch,
  keyFromRecordKey,
  logScope,
  streamScope,
  verifySegment,
  type ControlHashes,
  type KeyFieldType,
  type LogKey,
  type LogOmission,
  type LogOperation,
  type LogStreamMeta,
  type Segment,
  type SegmentRef,
  type SnapshotPointer,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  RegistryBatchRouteMissingError,
  RegistryRefusedError,
  type RegistryRequirementFailure,
  type SignedBatchRow,
} from "../stream-sync/ports.js";
import { StorageDeferredError } from "../stream-sync/storage-retry.js";
import { sameHead, type PlanHead } from "../stream-sync/publish-plan.js";
import { keccakOf } from "../stream-sync/crypto-port.js";
import { putBodiesOutOfLine } from "./log-bodies.js";
import { seedFromRecords } from "./log-seed.js";
import { applyConnection } from "./apply.js";
import { listStreamBlobs, uploadBlobs, type BlobDescriptor } from "./blobs.js";
import {
  batchBounds,
  checkBatchRoom,
  settleRequirementFailure,
  settleRow,
} from "./batch-commit.js";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";
import { WorkspaceOperationError } from "./workspace-failure.js";
import type { WorkspaceCanonicalRecord } from "./workspace-consumer.js";
import { tombstoneOmissions } from "./admit.js";
import { planCompaction } from "./log-compact.js";
import {
  logPublishPhases,
  openPhases,
  type PhaseClock,
} from "./log-publish-phases.js";
import { readLogState, writeLogState, type LogState } from "./log-apply.js";
import {
  openReplacementPlan,
  publishedOperationBytes,
  operationBytes,
  residentOperationBytes,
} from "./log-replacement.js";
import {
  replaceDelete,
  seenBeforeParams,
  SEEN_BEFORE,
  type KeyRange,
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
  retainedRuns,
  type ConnectionRow,
  type LocalStream,
  type PublishResult,
  type StreamPlan,
} from "./publish.js";
import { connectionLifetime, purgeConnection } from "./purge.js";
import {
  ELIGIBLE_CHANGE,
  PENDING_RUN,
  readPublicationWork,
  pendingChangeReasons,
  type PublicationWork,
} from "./publication-work.js";
import { readPublicationStatus } from "./run-receipts.js";
import { insideQueue } from "./slot.js";
import { unwriteRefusedRun } from "./unwrite.js";

/**
 * Compatibility transfer budget exported for existing host/test callers.
 * Replacement planning now reads one body with a bounded metadata cursor.
 */
export const PAGE_BYTES = 2 * 1024 * 1024;

const MAX_ATTEMPTS = 5;

type StreamRow = LocalStream & {
  stream: string;
  /**
   * The meta of the version this stream's head stands for: what the log last
   * said. A run's end writes the stream's own meta before its publish, so the
   * stream's columns are not it. NULL when the stream has no head.
   */
  published_complete: number | null;
  published_primary_key: string | null;
  published_profile_key: string | null;
  published_profile_version: string | null;
};

/**
 * The stream as the log last described it: the base a plan starts from. A
 * stream with no head was never described, so its own state is the base.
 */
function asPublished(row: StreamRow): LocalStream {
  if (row.head_version === 0) return row;
  if (row.published_primary_key === null || row.published_complete === null)
    throw new Error(
      `publish: stream ${row.stream} has head version ${row.head_version} and no meta for it`,
    );
  return {
    ...row,
    primary_key: row.published_primary_key,
    profile_key: row.published_profile_key,
    profile_version: row.published_profile_version,
    complete: row.published_complete,
  };
}

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
  /** The replace this round completes: its rows below the cutoff go. */
  readonly replace: { readonly o: number; readonly r: string } | null;
  /**
   * A replace whose rows this round carries but whose completion waits for a
   * later round. Its basis moves to the segment this round commits, which is
   * this device's own and so not a write the replace must yield to.
   */
  readonly replacing: { readonly o: number; readonly r: string } | null;
  /**
   * The keys of `replacing` that this round's piece of its completion names.
   * The commit drops them here as the last piece's commit drops the rest, so
   * the next round lists only the keys still to send.
   */
  readonly omitting: KeyRange | null;
  readonly workspace?: Awaited<ReturnType<typeof openReplacementPlan>>;
  readonly omitted: readonly LogOmission[];
  readonly bytes: number;
};

type Candidate = {
  readonly lifetime: object;
  readonly connector: string;
  readonly ns: string;
  readonly basis: string;
  readonly state: LogState;
  /** What the segment carries: after a compaction, `base` is the folded position and `refs` is empty. */
  readonly base: number;
  readonly refs: readonly SegmentRef[];
  readonly snapshot: SnapshotPointer | null;
  /**
   * Objects the segment names, to upload before it: snapshot parts and the
   * pieces of out-of-line bodies.
   */
  readonly objects: readonly {
    readonly name: string;
    readonly cipher: Uint8Array;
  }[];
  readonly position: number;
  readonly generation: number;
  readonly dataHash: `0x${string}`;
  readonly blobName: string;
  readonly cipher: Uint8Array;
  readonly clearBytes: number;
  /** Whether the segment removes a key (`segmentRemoves`): the fact its ref carries. */
  readonly removes: boolean;
  readonly observedAt: number;
  readonly planned: readonly Planned[];
  readonly attachments: readonly BlobDescriptor[];
  readonly controlDataHash: `0x${string}`;
  readonly prevHash: `0x${string}` | null;
  /** The first save of a new connection: the commit creates the control row. */
  readonly createControl: boolean;
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
  | { readonly kind: "retry"; readonly conflict: boolean };

/**
 * Publish a connection through the log. Every commit is a batch request:
 * throws `RegistryBatchRouteMissingError` when the registry serves none.
 */
export async function publishLog(
  deps: LocalSyncDeps,
  connectionId: string,
): Promise<readonly PublishResult[]> {
  if (!deps.registry.postBatch)
    throw new RegistryBatchRouteMissingError("this registry has no batch port");
  // One publish of a connection at a time. A publish releases the queue slot
  // while it uploads, and what it sends is chosen at its snapshot and leaves
  // the pending set only at its local commit. A second publish that took its
  // snapshot in between would choose the same changes: it would encode and
  // upload the same segment again and commit nothing. It waits for the first
  // instead, then publishes what is left, which is usually nothing; the
  // completion read covers the work pending when each caller arrived, even
  // if the preceding publish was the one that acknowledged it.
  const earlier = inFlight.get(deps.db)?.get(connectionId);
  const own = (async () => {
    // The earlier publish's own failure is its caller's; this one starts over.
    // Order the call's initial read after intake already queued by its caller.
    const work = await deps.queue.run(connectionId, "publish", () =>
      readPublicationWork(deps.db, connectionId),
    );
    if (earlier) await earlier.catch(() => null);
    const clock = openPhases(deps);
    try {
      await publishRounds(deps, connectionId, clock);
      return deps.queue.run(connectionId, "publish", () =>
        completedResults(insideQueue(deps, connectionId), connectionId, work),
      );
    } finally {
      logPublishPhases(deps, connectionId, clock);
    }
  })();
  const chain = inFlightOf(deps.db);
  chain.set(connectionId, own);
  try {
    return await own;
  } finally {
    if (chain.get(connectionId) === own) chain.delete(connectionId);
  }
}

/** Publishes in flight, by database and connection (see `publishLog`). */
const inFlight = new WeakMap<
  object,
  Map<string, Promise<readonly PublishResult[]>>
>();
function inFlightOf(
  db: object,
): Map<string, Promise<readonly PublishResult[]>> {
  let chain = inFlight.get(db);
  if (!chain) inFlight.set(db, (chain = new Map()));
  return chain;
}

/** Attempt outcomes describe blocked work, never the caller's completion. */
const blockedOrder = [
  "deferred",
  "backoff",
  "discarded",
  "purged",
  "refused",
] as const;
async function recordBlocked(
  deps: LocalSyncDeps,
  id: string,
  results: readonly PublishResult[],
) {
  for (const result of results) {
    const rank = blockedOrder.indexOf(
      result.outcome as (typeof blockedOrder)[number],
    );
    if (rank < 0) continue;
    // Each row records its latest attempt. Severity orders rows at completion,
    // never attempts over time.
    await deps.db.batch([
      {
        sql: `UPDATE record_changes SET publish_blocked_reason=?
          WHERE connection_id=? AND stream=?
            AND seq > (SELECT publish_watermark FROM stream_state WHERE connection_id=? AND stream=?)
            AND ${ELIGIBLE_CHANGE}`,
        params: [result.outcome, id, result.stream, id, result.stream],
      },
      {
        sql: `UPDATE run_streams SET publish_blocked_reason=? WHERE stream=?
          AND run_id IN (SELECT r.run_id FROM runs r JOIN run_streams rs ON rs.run_id=r.run_id
            WHERE r.connection_id=? AND rs.stream=? AND ${PENDING_RUN})`,
        params: [result.outcome, result.stream, id, result.stream],
      },
    ]);
  }
}

/** Completion is read after all work, independently of the order of attempts. */
async function completedResults(
  deps: LocalSyncDeps,
  id: string,
  work: readonly PublicationWork[],
): Promise<PublishResult[]> {
  const [connection] = await deps.db.query<
    ConnectionRow & { control_state: string }
  >(
    "SELECT connector, ns, generation, control_state FROM connections WHERE connection_id=?",
    [id],
  );
  const deleting = connection
    ? await hasDeleteIntent(deps, connection.connector)
    : false;
  const log = await readLogState(deps, id);
  const remaining = await readPublicationWork(deps.db, id);
  const results: PublishResult[] = [];
  for (const item of work) {
    const [state] = await deps.db.query<{
      publish_watermark: number;
      head_generation: number | null;
      head_data_hash: string | null;
    }>(
      "SELECT publish_watermark, head_generation, head_data_hash FROM stream_state WHERE connection_id=? AND stream=?",
      [id, item.stream],
    );
    const statuses = await Promise.all(
      item.runIds.map((runId) => readPublicationStatus(deps.db, runId)),
    );
    const streams = statuses.map((status) =>
      status.streams.find((s) => s.name === item.stream)!,
    );
    const changeReasons = await pendingChangeReasons(deps.db, id, item);
    const rest = remaining.find((w) => w.stream === item.stream);
    const pending =
      changeReasons.length > 0 || streams.some((s) => s.state === "pending");
    const reasons = new Set([
      ...changeReasons,
      ...item.runIds
        .filter((_, i) => streams[i]!.state === "pending")
        .map((runId) => rest?.runReasons.get(runId)),
    ]);
    const blocked =
      [...blockedOrder].reverse().find((reason) => reasons.has(reason)) ??
      "deferred";
    const superseded = streams.some(
      (s) => s.state === "superseded" && !s.reason?.startsWith("replaced_by:"),
    );
    const runIds = item.runIds.filter(
      (_, i) => streams[i]!.publication !== undefined,
    );
    const evidence = streams
      .flatMap((s) => (s.publication ? [s.publication] : []))
      .sort((a, b) => b.version - a.version)[0];
    const hadWork = item.hadChanges || item.runIds.length > 0;
    const lifetimeEnded =
      item.lifetime !== connectionLifetime(deps.db, id) ||
      connection?.generation !== item.generation;
    const outcome = lifetimeEnded
      ? "purged"
      : deleting
        ? "deferred"
        : connection?.control_state === "deleted"
          ? "purged"
          : pending
            ? blocked
            : superseded
              ? "discarded"
              : hadWork
                ? "published"
                : "noop";
    results.push({
      stream: item.stream,
      outcome,
      watermark: state?.publish_watermark ?? null,
      ...(outcome === "published" &&
        connection &&
        state?.head_data_hash && {
          publication: {
            connectionId: id,
            connector: connection.connector,
            ns: connection.ns,
            stream: item.stream,
            head: {
              version:
                evidence?.version ??
                log.refs.find((r) => r.dataHash === state.head_data_hash)
                  ?.position ??
                log.position,
              generation:
                evidence?.generation ??
                state.head_generation ??
                connection.generation,
              dataHash: evidence?.dataHash ?? state.head_data_hash,
            },
            watermark: evidence?.watermark ?? state.publish_watermark,
            runIds,
          },
        }),
    });
  }
  return results;
}

// Process-local lifecycle: uploading -> uploaded (commit unresolved) ->
// committed/refused. The uploaded state records whether a reply was ambiguous.
// A lifetime or basis change invalidates a candidate. An ambiguous commit must
// be reconciled before invalidation can release it; invalidated work never
// transfers or posts again. Only terminal, reconciled states leave the map.
type CandidateState =
  | { readonly kind: "uploading" }
  | { readonly kind: "uploaded"; readonly ambiguous: boolean }
  | { readonly kind: "committed" }
  | { readonly kind: "refused" }
  | { readonly kind: "invalidated"; readonly ambiguous: boolean };
type PendingCommit = { readonly candidate: Candidate; state: CandidateState };
type CandidateEvent =
  | "uploaded"
  | "ambiguous"
  | "committed"
  | "refused"
  | "invalidated"
  | "reconciled";
const pendingCommits = new WeakMap<object, Map<string, PendingCommit>>();
function pendingOf(db: object): Map<string, PendingCommit> {
  let pending = pendingCommits.get(db);
  if (!pending) pendingCommits.set(db, (pending = new Map()));
  return pending;
}
function isInvalidated(entry: PendingCommit): boolean {
  return entry.state.kind === "invalidated";
}
function hasAmbiguousCommit(entry: PendingCommit): boolean {
  return (
    (entry.state.kind === "uploaded" || entry.state.kind === "invalidated") &&
    entry.state.ambiguous
  );
}
function transition(entry: PendingCommit, event: CandidateEvent): void {
  const state = entry.state;
  if (event === "invalidated") {
    entry.state = { kind: "invalidated", ambiguous: hasAmbiguousCommit(entry) };
  } else if (event === "reconciled" && state.kind === "committed") {
    return;
  } else if (
    event === "reconciled" &&
    (state.kind === "uploaded" || state.kind === "invalidated")
  ) {
    entry.state = { kind: state.kind, ambiguous: false };
  } else if (event === "uploaded" && state.kind === "uploading") {
    entry.state = { kind: "uploaded", ambiguous: false };
  } else if (event === "ambiguous" && state.kind === "uploaded") {
    entry.state = { kind: "uploaded", ambiguous: true };
  } else if (
    event === "committed" &&
    (state.kind === "uploaded" || state.kind === "committed")
  ) {
    entry.state = { kind: "committed" };
  } else if (
    event === "refused" &&
    state.kind === "uploaded" &&
    !state.ambiguous
  ) {
    entry.state = { kind: "refused" };
  } else {
    throw new Error(
      `publish: invalid candidate transition ${state.kind} -> ${event}`,
    );
  }
}
async function releaseCandidate(
  pending: Map<string, PendingCommit>,
  id: string,
  entry: PendingCommit,
) {
  if (
    hasAmbiguousCommit(entry) ||
    entry.state.kind === "uploading" ||
    entry.state.kind === "uploaded"
  )
    throw new Error("publish: cannot release an unsettled candidate");
  // Unknown remote outcomes keep their preparation until recovery resolves them.
  if (entry.state.kind === "committed" || entry.state.kind === "refused")
    for (const p of entry.candidate.planned) await p.workspace?.dispose();
  pending.delete(id);
}
async function invalidateExpiredCandidate(
  held: LocalSyncDeps,
  id: string,
  entry: PendingCommit,
) {
  const [row] = await held.db.query<{
    generation: number;
    control_state: string;
  }>(
    "SELECT generation, control_state FROM connections WHERE connection_id = ?",
    [id],
  );
  if (
    entry.candidate.lifetime !== connectionLifetime(held.db, id) ||
    !row ||
    row.generation !== entry.candidate.generation ||
    // A first save's control row is created by its commit, so its connection
    // is still absent here; it is active once another path (an apply after a
    // lost reply) has seen the row. Either way the candidate stands.
    !(entry.candidate.createControl
      ? row.control_state === "absent" || row.control_state === "active"
      : row.control_state === "active") ||
    (await hasDeleteIntent(held, entry.candidate.connector))
  )
    transition(entry, "invalidated");
}

async function publishRounds(
  deps: LocalSyncDeps,
  connectionId: string,
  clock: PhaseClock,
): Promise<void> {
  const record = (list: readonly PublishResult[]) =>
    recordBlocked(deps, connectionId, list);
  let attempts = 0;
  const pending = pendingOf(deps.db);
  for (;;) {
    let retained = pending.get(connectionId);
    if (retained) {
      const entry = retained;
      const recovered = await deps.queue.run(
        connectionId,
        "publish",
        async () => {
          const held = insideQueue(deps, connectionId);
          await invalidateExpiredCandidate(held, connectionId, entry);
          if (hasAmbiguousCommit(entry) || entry.state.kind === "committed")
            return reconcileCandidate(held, connectionId, entry);
          if (
            !isInvalidated(entry) &&
            (await basisOf(
              held,
              connectionId,
              entry.candidate.planned,
              await readLogState(held, connectionId),
            )) !== entry.candidate.basis
          )
            transition(entry, "invalidated");
          return null;
        },
      );
      if (recovered) await record(recovered);
      if (
        entry.state.kind === "invalidated" ||
        entry.state.kind === "committed" ||
        entry.state.kind === "refused"
      ) {
        await releaseCandidate(pending, connectionId, entry);
        retained = undefined;
      }
    }
    const turn: Snapshot = retained
      ? { kind: "candidate", candidate: retained.candidate }
      : await clock.time("snapshot", () =>
          deps.queue.run(connectionId, "publish", async () => {
            const held = insideQueue(deps, connectionId);
            return snapshotRound(held, connectionId, clock);
          }),
        );
    if (turn.kind === "done") {
      // Bytes that arrived after their records were published still go up.
      if (turn.attachments && turn.attachments.length > 0) {
        const attachments = turn.attachments;
        await clock.time("attachments", () => uploadBlobs(deps, attachments));
      }
      await record(turn.results);
      break;
    }
    if (turn.kind === "retry") {
      if (++attempts >= MAX_ATTEMPTS) {
        await record(await backoff(deps, connectionId));
        break;
      }
      continue;
    }
    const { candidate } = turn;
    const transfer: PendingCommit = retained ?? {
      candidate,
      state: { kind: "uploading" },
    };
    pending.set(connectionId, transfer);
    // TRANSFER: no slot. Objects are content addressed and authorize nothing
    // until the registry commit, so nothing orders one PUT before another:
    // the attachments, the snapshot parts and the segment that names them go
    // at once and the commit waits for all of them. The commit's one
    // dependency is the objects it names.
    const scope = logScope(candidate.connector, candidate.ns);
    try {
      if (transfer.state.kind === "uploading") {
        await allTransferred([
          candidate.attachments.length > 0
            ? clock.time("attachments", () =>
                uploadBlobs(deps, candidate.attachments),
              )
            : undefined,
          clock.time("segment-put", () =>
            allTransferred([
              ...candidate.objects.map((object) =>
                putIfMissing(
                  deps,
                  `${scope}/${object.name}`,
                  object.cipher,
                  retained !== undefined || attempts > 0,
                ),
              ),
              putIfMissing(
                deps,
                `${scope}/${candidate.blobName}`,
                candidate.cipher,
                retained !== undefined || attempts > 0,
              ),
            ]),
          ),
        ]);
        transition(transfer, "uploaded");
      }
    } catch (error) {
      // Storage kept refusing past its retry budget. Nothing is wrong with the
      // data: nothing was committed, so the changes stay queued and the next
      // cycle sends them again.
      if (!(error instanceof StorageDeferredError)) throw error;
      deps.logger.info(
        { connectionId, error: error.message },
        "stream sync: storage unavailable, publish left in the queue",
      );
      await record(await backoff(deps, connectionId));
      break;
    }

    let committed: Committed;
    try {
      committed = await clock.time("commit", () =>
        deps.queue.run(connectionId, "publish", () =>
          commitRound(
            insideQueue(deps, connectionId),
            connectionId,
            transfer,
            clock,
          ),
        ),
      );
    } catch (error) {
      if (
        (error instanceof RegistryRefusedError ||
          error instanceof RegistryBatchRouteMissingError) &&
        transfer.state.kind === "uploaded" &&
        !hasAmbiguousCommit(transfer)
      ) {
        transition(transfer, "refused");
        await releaseCandidate(pending, connectionId, transfer);
      }
      throw error;
    }
    await releaseCandidate(pending, connectionId, transfer);
    if (committed.kind === "retry") {
      if (++attempts >= MAX_ATTEMPTS) {
        await record(await backoff(deps, connectionId));
        break;
      }
      continue;
    }
    await record(committed.results);
    attempts = 0;
    if (!committed.more) break;
  }
}

/**
 * Probe retries only. Storage must publish complete objects atomically:
 * existence proves the whole immutable object is available.
 */
async function putIfMissing(
  deps: LocalSyncDeps,
  key: string,
  bytes: Uint8Array,
  checkExisting: boolean,
) {
  if (!checkExisting || !(await deps.blobs.exists(key)))
    await deps.blobs.put(key, bytes);
}

// A failed transfer must not leave another PUT running into the next retry.
async function allTransferred(
  transfers: readonly (Promise<unknown> | undefined)[],
) {
  const results = await Promise.allSettled(transfers);
  const failed = results.find((r) => r.status === "rejected");
  if (failed) throw failed.reason;
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

/**
 * What this process already warned about, by database and connection: a held
 * stream's warned state, so one held state warns once however many publish
 * passes meet it.
 */
const heldWarnings = new WeakMap<object, Map<string, Map<string, string>>>();
function warnedHolds(db: object, connectionId: string): Map<string, string> {
  let byConnection = heldWarnings.get(db);
  if (!byConnection) heldWarnings.set(db, (byConnection = new Map()));
  let streams = byConnection.get(connectionId);
  if (!streams) byConnection.set(connectionId, (streams = new Map()));
  return streams;
}

async function snapshotRound(
  held: LocalSyncDeps,
  connectionId: string,
  clock: PhaseClock,
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
    `SELECT s.stream, s.primary_key, s.profile_key, s.profile_version, s.complete,
            s.floor_version, s.floor_o, s.floor_r, s.last_delete_version,
            s.head_version, s.head_generation, s.head_data_hash, s.publish_watermark,
            v.complete AS published_complete, v.primary_key AS published_primary_key,
            v.profile_key AS published_profile_key,
            v.profile_version AS published_profile_version
       FROM stream_state s
       LEFT JOIN stream_versions v
         ON v.connection_id = s.connection_id AND v.stream = s.stream
        AND v.version = s.head_version
      WHERE s.connection_id = ? ORDER BY s.stream`,
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
  const hashes = await controlHashes(keccakOf(held.streamCrypto), keyCheck);

  // Control. A connection this device already holds as active is confirmed by
  // the commit's own condition; only an unknown one is read here. A first
  // save creates the row with its commit.
  const controlDataHash = hashes.activeData;
  let createControl = false;
  if (connection.control_state !== "active") {
    const settled = await clock.time("control", () =>
      establishControl(held, connectionId, connection, hashes),
    );
    if (settled === "create") createControl = true;
    else if (settled !== "active") return all(settled);
  }
  if (
    await discardForeignLifetimeRuns(held, connectionId, connection.generation)
  ) {
    await applyConnection(held, connectionId);
    return { kind: "retry" };
  }
  await held.db.batch([
    ...(createControl ? [] : [markControlActive(connectionId, connection)]),
    {
      sql: "UPDATE runs SET generation=? WHERE connection_id=? AND generation IS NULL AND state='ended'",
      params: [connection.generation, connectionId],
    },
  ]);

  const planStart = clock.now();
  const log = await readLogState(held, connectionId);
  // A connection with no log yet starts it with everything this device holds
  // (a device that applied a log first seeded when it did, `applyLog`).
  const seeded =
    log.position === 0
      ? await seedFromRecords(held, connectionId)
      : new Set<string>();
  const planned: Planned[] = [];
  const roundObservedAt = held.now();
  let handedOff = false;
  try {
    const target = held.partTargetBytes ?? DEFAULT_PART_TARGET_BYTES;
    let budget = 0;
    let first = true;
    // Streams this pass holds back, and streams it did not examine for it.
    const heldNow = new Set<string>();
    const unexamined = new Set<string>();
    eachStream: for (const row of streams) {
      const { stream } = row;
      if (await discardFencedRuns(held, connectionId, stream)) {
        await applyConnection(held, connectionId);
        return { kind: "retry" };
      }
      if (connection.generation !== 1)
        await excludeSeedsIfAny(held, connectionId, stream);
      // The plan's base is what the log last said, not what the run's end wrote.
      const published = asPublished(row);
      const plan = await planStream(
        held,
        connectionId,
        connection,
        stream,
        published,
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
        replacing: null,
        omitting: null,
        omitted: [],
        bytes: 0,
      };
      if (plan.deferred) {
        unexamined.add(stream);
        planned.push({ ...base, ack: row.publish_watermark });
        continue;
      }
      // The stream's local head stands for the log's last segment that touched
      // it (see `applySegmentOperations`): a replacing run applies only if no
      // segment touched the stream since the run began.
      const replace = plan.replaceBelow ?? null;
      const workspace = await openReplacementPlan(held, {
        connection: connectionId,
        generation: connection.generation,
        keyCheck,
        expectedHead: log.refs.at(-1)?.dataHash ?? "null",
        creatingControl: createControl,
        stream,
        from: row.publish_watermark,
        to: watermark,
        primaryKey: plan.finalHead?.primaryKey ?? JSON.parse(row.primary_key),
        cutoff: replace,
        target,
      });
      let failed = false;
      try {
        const hasChanges = await workspace.hasChanges();
        // A stream with no head yet (a first collection that publishes while it
        // collects) is described by its local state.
        const head: PlanHead | null =
          plan.finalHead ??
          (hasChanges
            ? {
                generation: row.head_generation ?? connection.generation,
                primaryKey: JSON.parse(row.primary_key),
                profile: {
                  key: row.profile_key ?? connection.connector,
                  version: row.profile_version ?? row.floor_version ?? "0",
                },
                // A seeded stream is what this device holds, head and all: its
                // completeness is its own. Other changes with no run to describe
                // them belong to a first collection that is still filling.
                complete: seeded.has(stream) && row.complete === 1,
              }
            : null);
        const metaChanged =
          head !== null &&
          (row.head_version === 0 ||
            !sameHead(head, {
              generation: row.head_generation ?? head.generation,
              primaryKey: JSON.parse(published.primary_key),
              profile: {
                key: published.profile_key ?? connection.connector,
                version: published.profile_version ?? "0",
              },
              complete: published.complete === 1,
            }));
        const metaPublishes =
          metaChanged && plan.steps.some((s) => s.decision.kind === "publish");
        const hasWork = hasChanges || replace !== null || metaPublishes;
        if (!hasWork || head === null) {
          planned.push({ ...base, runIds: base.runIds });
          continue;
        }
        // Changes go in the order they were made, until the segment reaches the
        // part target, measured on the operations themselves. The first thing in
        // a segment always goes, however large, so a round always progresses.
        //
        // A replacing stream whose rows and completion fit one segment goes whole
        // (a reader sees the replace at once), or waits for the next round if
        // this segment is full. One larger than a segment goes like any other
        // changes, over as many rounds as it needs. Its completion (the keys it
        // dropped) goes in the round that takes its last rows, or alone in the
        // next. A completion larger than what is left of the segment goes in
        // pieces over as many rounds as it needs: each is a completion at the
        // run's cutoff for the next keys in hash order, an omission per key like
        // any other. Only the round with the last piece says the stream is
        // complete: an earlier round says it is not, so a reader never takes a
        // replace that is half published for a complete stream. Every operation
        // merges per key by stamp, so rounds from other writers in between
        // interleave as they would with any other changes.
        const metaFor = (complete: boolean): LogStreamMeta => ({
          stream,
          primaryKey: head.primaryKey,
          profile: head.profile as LogStreamMeta["profile"],
          complete,
        });
        const envelopeSizes: (number | undefined)[] = [];
        const envelopeSize = (complete: boolean, alone = false) => {
          const key = (complete ? 1 : 0) + (alone ? 2 : 0);
          if (envelopeSizes[key] !== undefined) return envelopeSizes[key]!;
          const size = encodeSegment({
            format: LOG_FORMAT,
            connector: connection.connector,
            ns: connection.ns,
            generation: connection.generation,
            keyCheck,
            position: log.position + 1,
            observedAt:
              Math.max(
                plan.newestRunObservedAt ?? 0,
                ...(alone
                  ? []
                  : planned
                      .filter((p) => p.included)
                      .map((p) => p.plan.newestRunObservedAt ?? 0)),
              ) || roundObservedAt,
            base: log.base,
            snapshot: log.snapshot,
            refs: log.refs,
            streams: [
              ...(alone
                ? []
                : planned.filter((p) => p.included).map((p) => p.meta!)),
              metaFor(complete),
            ],
            operations: [],
          }).length;
          envelopeSizes[key] = size;
          return size;
        };
        const room = (size: number, complete = false) =>
          first ||
          envelopeSize(complete) +
            budget +
            (budget > 0 && size > 0 ? 1 : 0) +
            size <=
            target;
        const sizeOf = (op: LogOperation) => opSize(op, target);
        let selectedCount = 0;
        let selectedSeq = row.publish_watermark;
        const taken: LogOperation[] = [];
        let bytes = 0;
        let rest = false;
        let whole = false;
        // A stream with a change the log cannot say stops here: nothing of it is
        // published or acknowledged this round (`plan.deferred`, as for a stream
        // that waits on its runs), so no change is lost without a trace.
        const wasFirst = first;
        const stop = (untyped: readonly string[]) => {
          first = wasFirst;
          heldNow.add(stream);
          // One warning per held state, not per pass: a cycle publishes more than
          // once and a held stream is met again on every poll until its keys are
          // known. The state is the set of changes held; a different set warns.
          const state = [...untyped].sort().join(",");
          const warned = warnedHolds(held.db, connectionId);
          if (warned.get(stream) !== state) {
            warned.set(stream, state);
            held.logger.warn(
              { connectionId, stream, pkHashes: untyped.slice(0, 5) },
              `stream sync: the log holds back stream "${stream}": an explicit delete made before typed keys were kept cannot be written to it, and the stream's declared key types do not give its key back`,
            );
          }
          planned.push({
            ...base,
            plan: { ...plan, deferred: true },
            ack: row.publish_watermark,
          });
        };
        // Count the exact operation wire encoding, one body at a time. The
        // second pass re-reads the frozen key relation and retains only this part.
        const omittedCount = replace ? await workspace.omissionCount() : 0;
        const emptyCompletion = replace
          ? { kind: "complete" as const, stream, cutoff: replace, omitted: [] }
          : null;
        const wireCompletionBase = emptyCompletion
          ? operationBytes(emptyCompletion)
          : 0;
        const residentCompletionBase = emptyCompletion
          ? residentOperationBytes(emptyCompletion)
          : 0;
        const completionBase = Math.max(
          wireCompletionBase,
          residentCompletionBase,
        );
        const omissionCost = (omission: LogOmission) => {
          const single = {
            kind: "complete" as const,
            stream,
            cutoff: replace!,
            omitted: [omission],
          };
          return Math.max(
            operationBytes(single) - wireCompletionBase,
            residentOperationBytes(single) - residentCompletionBase,
          );
        };
        if (replace !== null) {
          const unknown = await firstUntypedDeletion(
            held,
            connectionId,
            stream,
            row.publish_watermark,
            watermark,
            workspace.admitKey,
          );
          if (unknown !== null) {
            stop([unknown]);
            continue eachStream;
          }
          let size = completionBase;
          let fullyCounted = true;
          let count = 0;
          for await (const omission of workspace.omissions()) {
            size += omissionCost(omission) + (count++ > 0 ? 1 : 0);
            if (envelopeSize(head.complete, true) + size > target) {
              fullyCounted = false;
              break;
            }
          }
          if (fullyCounted)
            for await (const group of workspace.changes()) {
              await workspace.admitKey(group.recordBytes);
              const { op, untyped } = await operationForKey(
                held,
                connectionId,
                stream,
                group.pk,
                row.publish_watermark,
                watermark,
                group.record,
              );
              if (untyped !== null) {
                stop([untyped]);
                continue eachStream;
              }
              if (op) size += sizeOf(op) + 1;
              if (envelopeSize(head.complete, true) + size > target) {
                fullyCounted = false;
                break;
              }
            }
          if (
            fullyCounted &&
            envelopeSize(head.complete, true) + size <= target
          ) {
            if (!room(size, head.complete)) {
              planned.push({ ...base, ack: row.publish_watermark, rest: true });
              continue;
            }
            whole = true;
          }
        }
        for await (const group of workspace.changes()) {
          await workspace.admitKey(group.recordBytes);
          const { op, untyped } = await operationForKey(
            held,
            connectionId,
            stream,
            group.pk,
            row.publish_watermark,
            watermark,
            group.record,
          );
          if (untyped !== null) {
            stop([untyped]);
            continue eachStream;
          }
          const size = op ? sizeOf(op) + (taken.length > 0 ? 1 : 0) : 0;
          if (!whole && !room(bytes + size)) {
            rest = true;
            break;
          }
          selectedCount += 1;
          selectedSeq = group.seq;
          if (op) {
            taken.push(op);
            first = false;
          }
          bytes += size;
        }
        if (selectedCount === 0 && hasChanges) {
          planned.push({ ...base, ack: row.publish_watermark, rest: true });
          continue;
        }
        // Rows of the stream wait for a later round; its completion waits with them.
        const rowsRest = rest;
        let completes = whole;
        const piece: LogOmission[] = [];
        if (replace !== null && (whole || !rowsRest)) {
          let used = completionBase + (taken.length > 0 ? 1 : 0);
          for await (const omission of workspace.omissions()) {
            const size = omissionCost(omission) + (piece.length > 0 ? 1 : 0);
            if (
              !whole &&
              !room(bytes + used + size) &&
              !(first && piece.length === 0)
            ) {
              rest = true;
              break;
            }
            piece.push(omission);
            first = false;
            used += size;
          }
          completes = piece.length === omittedCount;
          if (completes || piece.length > 0) bytes += used;
          else if (omittedCount > 0) rest = true;
        }
        // A replace whose completion waits, with no rows or piece of its
        // completion in this round, waits whole.
        if (
          replace !== null &&
          !completes &&
          taken.length === 0 &&
          piece.length === 0
        ) {
          planned.push({ ...base, ack: row.publish_watermark, rest: true });
          continue;
        }
        // Changes that carry no operation are nothing to publish: the rows a
        // replacing run dropped are deleted locally in the commit that publishes
        // its completion, and those deletions are changes above that commit's
        // watermark. Counted as work they would cost a segment that says nothing.
        if (!completes && !rest && taken.length === 0 && !metaPublishes) {
          planned.push({ ...base });
          continue;
        }
        budget += bytes + (budget > 0 && bytes > 0 ? 1 : 0);
        first = false;
        const ack = rowsRest ? selectedSeq : watermark;
        await workspace.prepare(ack, piece, completes);
        planned.push({
          ...base,
          included: true,
          workspace,
          rest,
          ack,
          operations: [
            ...orderedOperations(taken),
            ...(replace && (completes || piece.length > 0)
              ? [
                  {
                    kind: "complete" as const,
                    stream,
                    cutoff: { o: replace.o, r: replace.r },
                    omitted: piece,
                  },
                ]
              : []),
          ],
          meta: {
            stream,
            primaryKey: head.primaryKey,
            profile: head.profile as LogStreamMeta["profile"],
            complete: replace !== null && !completes ? false : head.complete,
          },
          replace: completes ? replace : null,
          replacing: replace !== null && !completes ? replace : null,
          omitting:
            piece.length > 0
              ? { from: piece[0]!.pkHash, to: piece.at(-1)!.pkHash }
              : null,
          omitted: piece,
          bytes,
        });
      } catch (error) {
        failed = true;
        if (error instanceof WorkspaceOperationError) throw error;
        await workspace.failure(error);
      } finally {
        await workspace.release(!failed);
        if (!failed && planned.at(-1)?.workspace !== workspace)
          await workspace.dispose();
      }
    }

    // A stream that is no longer held warns again if it is held again.
    const warned = warnedHolds(held.db, connectionId);
    for (const stream of [...warned.keys()])
      if (!heldNow.has(stream) && !unexamined.has(stream))
        warned.delete(stream);
    const included = planned.filter((p) => p.included);
    const settle = (outcomeFor: (p: Planned) => PublishResult["outcome"]) =>
      planned.map((p): PublishResult => ({
        stream: p.stream,
        outcome: outcomeFor(p),
        watermark: p.watermark,
      }));
    // Attachments named by any stream's records, published or not yet: bytes can
    // arrive after the records that name them were published.
    clock.record("plan", planStart);
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
      // Nothing to publish. A new connection's control row is still created, as
      // a request of its own. Record that every covered run was already saved
      // by what the log holds, move the watermarks, and compact.
      if (createControl) {
        const created = await clock.time("control", () =>
          commitControl(held, connectionId, connection, hashes),
        );
        if (created === "retry") return { kind: "retry" };
        if (created !== "active") return all(created);
      }
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
      observedAt: observedAt || roundObservedAt,
      base,
      snapshot,
      refs,
      streams: included.map((p) => p.meta!),
      operations: included.flatMap((p) => p.operations),
    };
    // A deletion's key is the one its hash covers, or the segment is not written.
    const mismatch = await firstDeletionKeyMismatch(
      async (bytes) => sha256(bytes),
      segment.streams,
      segment.operations,
    );
    if (mismatch)
      throw new Error(
        `publish: a deletion's key does not match its hash (${mismatch.stream}/${mismatch.pkHash})`,
      );
    const encodeStart = clock.now();
    // A body larger than one object goes out of line (stream-sync `log.ts`).
    const outOfLine = await putBodiesOutOfLine(
      held,
      scope,
      segment.operations,
      target,
    );
    const clear = encodeSegment({ ...segment, operations: outOfLine.ops });
    const { dataHash, blobName } = await digestSegment(
      keccakOf(held.streamCrypto),
      clear,
    );
    // A segment that would not verify is never uploaded or posted.
    const verified = await verifySegment(keccakOf(held.streamCrypto), clear, {
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
    clock.record("encode", encodeStart);
    const basis = await basisOf(held, connectionId, planned, log);
    handedOff = true;
    return {
      kind: "candidate",
      candidate: {
        lifetime: connectionLifetime(held.db, connectionId),
        connector: connection.connector,
        ns: connection.ns,
        basis,
        state: log,
        base,
        refs,
        snapshot,
        objects: [...(compaction?.objects ?? []), ...outOfLine.pieces],
        position,
        generation: connection.generation,
        dataHash,
        blobName,
        cipher,
        clearBytes: clear.length,
        removes: segmentRemoves(segment.operations),
        observedAt: segment.observedAt,
        planned: planned.map((p) => ({ ...p, operations: [] })),
        attachments,
        controlDataHash,
        createControl,
        prevHash: log.refs.at(-1)?.dataHash ?? null,
      },
    };
  } finally {
    if (!handedOff) for (const p of planned) await p.workspace?.dispose();
  }
}

/**
 * Charge the exact output bytes and the resident body, whichever is larger.
 * A small reference cannot admit several large decoded bodies into one part.
 */
function opSize(op: LogOperation, target: number): number {
  return Math.max(
    residentOperationBytes(op),
    operationBytes(op),
    publishedOperationBytes(op, target),
  );
}

/**
 * Whether the connection's control row is active here, for a connection this
 * device does not already hold as active.
 *
 * A connection this device has only ever seen absent, at its first generation,
 * is the first save of a new connection: `create`, with no read. The commit
 * creates the row in its own request, as a compare-and-set at version 1, and
 * the request's control condition is judged on what it commits. A row another
 * device wrote makes the creation lose, and the row is then read and
 * classified as for any other connection (`readControl`).
 */
async function establishControl(
  held: LocalSyncDeps,
  connectionId: string,
  connection: ConnectionRow & { control_state: string },
  hashes: ControlHashes,
): Promise<"active" | "create" | PublishResult["outcome"]> {
  if (connection.control_state === "absent" && connection.generation === 1)
    return "create";
  return readControl(held, connectionId, connection, hashes);
}

/** Read the control row and say what it means for this connection. */
async function readControl(
  held: LocalSyncDeps,
  connectionId: string,
  connection: ConnectionRow & { control_state: string },
  hashes: ControlHashes,
): Promise<"active" | "create" | PublishResult["outcome"]> {
  const control = controlScope(connection.connector, connection.ns);
  const state = classifyControl(await held.registry.read(control), hashes);
  // Absence creates the row only for a connection this device never saved. A
  // connection this device deleted is absent from the registry too (a delete
  // of a never-saved connection fences nothing), and only an explicit connect
  // starts it again: creating its row here would undo the delete.
  if (state.kind === "absent")
    return connection.control_state === "absent" && connection.generation === 1
      ? "create"
      : "deferred";
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

function markControlActive(
  connectionId: string,
  connection: ConnectionRow,
): SqlStatement {
  return {
    sql: "UPDATE connections SET control_state='active',control_version=? WHERE connection_id=?",
    params: [connection.generation, connectionId],
  };
}

/** The control row of a new connection: active, version 1. */
async function controlCreation(
  held: LocalSyncDeps,
  control: string,
  hashes: ControlHashes,
): Promise<SignedBatchRow> {
  return {
    scope: control,
    dataHash: hashes.activeData,
    metadataHash: hashes.activeMetadata,
    expectedVersion: "1",
    signature: await held.signer.signAddData({
      ownerAddress: held.ownerAddress,
      scope: control,
      dataHash: hashes.activeData,
      metadataHash: hashes.activeMetadata,
      expectedVersion: 1n,
    }),
  };
}

/**
 * The condition every commit carries: the control row is this connection's
 * lifetime, active. Judged on what the request commits, so it also holds a
 * control row the same request creates, and refuses a stored one (a replay)
 * that a delete has since tombstoned.
 */
function controlCondition(
  control: string,
  connection: ConnectionRow,
  hashes: ControlHashes,
) {
  return {
    scope: control,
    expectedVersion: String(connection.generation),
    notDeleted: true,
    expectedDataHash: hashes.activeData,
  };
}

/** What a failed control condition means for the connection. */
async function controlFailed(
  held: LocalSyncDeps,
  connectionId: string,
  control: string,
  failure: RegistryRequirementFailure | null,
): Promise<"purged" | "deferred"> {
  const verdict = failure ? settleRequirementFailure(failure, control) : null;
  if (verdict?.kind !== "purge") return "deferred";
  await purgeConnection(held, connectionId, {
    controlVersion: verdict.controlVersion,
  });
  return "purged";
}

/**
 * Create a new connection's control row in a request of its own: the first
 * save of a connection with nothing to publish yet.
 */
async function commitControl(
  held: LocalSyncDeps,
  connectionId: string,
  connection: ConnectionRow & { control_state: string },
  hashes: ControlHashes,
): Promise<"active" | "retry" | PublishResult["outcome"]> {
  const control = controlScope(connection.connector, connection.ns);
  const answer = await postBatchOnce(held.registry, {
    ownerAddress: held.ownerAddress,
    rows: [await controlCreation(held, control, hashes)],
    requires: [controlCondition(control, connection, hashes)],
  });
  if (answer.kind === "precondition_failed")
    return controlFailed(held, connectionId, control, answer.failure);
  const state =
    answer.kind === "committed"
      ? "active"
      : await readControl(held, connectionId, connection, hashes);
  if (state === "create") return "retry";
  if (state === "active")
    await held.db.batch([markControlActive(connectionId, connection)]);
  return state;
}

/** A bounded digest of the same sorted omission identities used by the
 * publication basis. No all-key comparison array survives transfer. */
async function omittedDigest(
  deps: LocalSyncDeps,
  connectionId: string,
  stream: string,
  replace: { o: number; r: string },
  keys?: KeyRange,
): Promise<string> {
  const digest = sha256.create();
  let after = "";
  for (;;) {
    const [row] = await deps.db.query<{ pk_hash: string }>(
      `SELECT pk_hash FROM records WHERE connection_id=? AND stream=? AND ${SEEN_BEFORE}
       AND pk_hash>? ${keys ? "AND pk_hash>=? AND pk_hash<=?" : ""} ORDER BY pk_hash LIMIT 1`,
      [
        connectionId,
        stream,
        ...seenBeforeParams(replace.o, replace.r),
        after,
        ...(keys ? [keys.from, keys.to] : []),
      ],
    );
    if (!row) break;
    digest.update(new TextEncoder().encode(JSON.stringify(row.pk_hash)));
    after = row.pk_hash;
  }
  return Array.from(digest.digest(), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

async function hasChangedKey(
  deps: Pick<LocalSyncDeps, "db">,
  connectionId: string,
  stream: string,
  from: number,
  to: number,
): Promise<boolean> {
  return (
    (
      await deps.db.query(
        `SELECT seq FROM record_changes WHERE connection_id=? AND stream=? AND seq>? AND seq<=? AND ${ELIGIBLE_CHANGE} LIMIT 1`,
        [connectionId, stream, from, to],
      )
    ).length > 0
  );
}

/**
 * Local publication debt, independent of publishRounds' aggregate receipt.
 * Read under the connection queue using the same changed-key and retained-run
 * eligibility queries as snapshotRound/planStream. Pending runs also cover a
 * metadata-only completion or an omission round after its records were sent.
 */
export async function hasPendingLogPublication(
  deps: Pick<LocalSyncDeps, "db" | "queue">,
  connectionId: string,
): Promise<boolean> {
  return deps.queue.run(connectionId, "publish", async () => {
    const streams = await deps.db.query<{
      stream: string;
      publish_watermark: number;
    }>(
      "SELECT stream, publish_watermark FROM stream_state WHERE connection_id=?",
      [connectionId],
    );
    const [last] = await deps.db.query<{ seq: number | null }>(
      "SELECT MAX(seq) AS seq FROM record_changes WHERE connection_id=?",
      [connectionId],
    );
    for (const row of streams) {
      if ((await retainedRuns(deps, connectionId, row.stream)).length > 0)
        return true;
      if (
        await hasChangedKey(
          deps,
          connectionId,
          row.stream,
          row.publish_watermark,
          last?.seq ?? row.publish_watermark,
        )
      )
        return true;
    }
    return false;
  });
}

/** A covered replace used to validate every deletion before it could emit
 * its first body. Keep that holdback while byte counting can stop early. */
async function firstUntypedDeletion(
  deps: LocalSyncDeps,
  connectionId: string,
  stream: string,
  from: number,
  to: number,
  admit: (bytes: number) => Promise<void>,
): Promise<string | null> {
  let after = "";
  for (;;) {
    const [candidate] = await deps.db.query<{
      pk_hash: string;
      seq: number;
      n: number;
    }>(
      `SELECT candidate.pk_hash,candidate.seq,LENGTH(CAST(candidate.record_key AS BLOB)) AS n FROM record_changes candidate
     WHERE candidate.connection_id=? AND candidate.stream=? AND candidate.seq>? AND candidate.seq<=? AND candidate.pk_hash>?
       AND candidate.op='remove' AND candidate.explicit_delete=1 AND candidate.pk_values IS NULL
       AND EXISTS(SELECT 1 FROM record_changes WHERE connection_id=candidate.connection_id AND stream=candidate.stream AND pk_hash=candidate.pk_hash AND seq>? AND seq<=? AND ${ELIGIBLE_CHANGE})
       AND NOT EXISTS(SELECT 1 FROM records r WHERE r.connection_id=candidate.connection_id AND r.stream=candidate.stream AND r.pk_hash=candidate.pk_hash)
       AND NOT EXISTS(SELECT 1 FROM record_changes later WHERE later.connection_id=candidate.connection_id AND later.stream=candidate.stream AND later.pk_hash=candidate.pk_hash AND later.seq>candidate.seq AND later.seq<=? AND later.op='remove' AND (later.explicit_delete=1 OR later.pk_values IS NOT NULL))
     ORDER BY candidate.pk_hash LIMIT 1`,
      [connectionId, stream, from, to, after, from, to, to],
    );
    if (!candidate) return null;
    await admit(candidate.n);
    const [row] = await deps.db.query<{ pk_hash: string; record_key: string }>(
      "SELECT pk_hash,record_key FROM record_changes WHERE seq=?",
      [candidate.seq],
    );
    if ((await declaredKey(deps, connectionId, stream, row!)) === null)
      return candidate.pk_hash;
    after = candidate.pk_hash;
  }
}

/**
 * The operation for one key: a held row is an upsert at its stamp; a key
 * with no row and an explicit delete in the window is a delete at the stamp of
 * that delete. A key with no row and no explicit delete is nothing to say: a
 * replacing run's drop travels as its completion, and a refused run's rows
 * were never published.
 */
async function operationForKey(
  deps: LocalSyncDeps,
  connectionId: string,
  stream: string,
  keyHash: string,
  from: number,
  to: number,
  cached?: WorkspaceCanonicalRecord | null,
): Promise<{ op: LogOperation | null; untyped: string | null }> {
  const row =
    cached !== undefined
      ? cached
      : (
          await deps.db.query<{
            pk_hash: string;
            stamp_o: number;
            stamp_r: string;
            stamp_n: number;
            first_o: number | null;
            body: string;
          }>(
            "SELECT pk_hash,stamp_o,stamp_r,stamp_n,first_o,body FROM records WHERE connection_id=? AND stream=? AND pk_hash=?",
            [connectionId, stream, keyHash],
          )
        )[0];
  if (row)
    return {
      op: {
        kind: "upsert",
        stream,
        pkHash: row.pk_hash,
        stamp: { o: row.stamp_o, r: row.stamp_r },
        ...(row.stamp_n > 0 ? { ordinal: row.stamp_n } : {}),
        firstSeen: row.first_o,
        value: JSON.parse(row.body),
      },
      untyped: null,
    };
  const [deletion] = await deps.db.query<{
    pk_hash: string;
    pk_values: string | null;
    record_key: string;
    stamp_o: number;
    stamp_r: string;
    explicit_delete: number;
  }>(
    `SELECT pk_hash,pk_values,record_key,stamp_o,stamp_r,explicit_delete FROM record_changes
      WHERE connection_id=? AND stream=? AND pk_hash=? AND seq>? AND seq<=?
        AND op='remove' AND (explicit_delete=1 OR pk_values IS NOT NULL) ORDER BY seq DESC LIMIT 1`,
    [connectionId, stream, keyHash, from, to],
  );
  if (!deletion) return { op: null, untyped: null };
  if (deletion.explicit_delete === 0)
    return {
      op: {
        kind: "complete",
        stream,
        cutoff: { o: deletion.stamp_o, r: deletion.stamp_r },
        omitted: [
          { pkHash: keyHash, key: JSON.parse(deletion.pk_values!) as LogKey },
        ],
      },
      untyped: null,
    };
  const key =
    deletion.pk_values !== null
      ? (JSON.parse(deletion.pk_values) as LogKey)
      : await declaredKey(deps, connectionId, stream, deletion);
  return key === null
    ? { op: null, untyped: keyHash }
    : {
        op: {
          kind: "delete",
          stream,
          pkHash: keyHash,
          key,
          stamp: { o: deletion.stamp_o, r: deletion.stamp_r },
        },
        untyped: null,
      };
}

/**
 * The typed key of a delete made before typed keys were kept: its record key
 * read with the types the stream's schema declares for its key fields, and
 * accepted only if it hashes to the delete's hash. `null` when the schema does
 * not determine it (no declared types yet, a union, or data that disagrees
 * with the schema).
 */
async function declaredKey(
  deps: LocalSyncDeps,
  connectionId: string,
  stream: string,
  row: { pk_hash: string; record_key: string },
): Promise<LogKey | null> {
  const [state] = await deps.db.query<{
    primary_key: string;
    key_types: string | null;
  }>(
    "SELECT primary_key, key_types FROM stream_state WHERE connection_id = ? AND stream = ?",
    [connectionId, stream],
  );
  if (!state || state.key_types === null) return null;
  const primaryKey = JSON.parse(state.primary_key) as string[];
  const key = keyFromRecordKey(
    primaryKey,
    JSON.parse(state.key_types) as (KeyFieldType | null)[],
    row.record_key,
  );
  return key !== null &&
    (await deletionKeyMatchesHash(
      async (bytes) => sha256(bytes),
      primaryKey,
      key,
      row.pk_hash,
    ))
    ? (key as LogKey)
    : null;
}

/** Upserts, then deletes, each by key: one order for every writer. */
function orderedOperations(ops: readonly LogOperation[]): LogOperation[] {
  const pkOf = (op: LogOperation) =>
    op.kind === "complete" ? (op.omitted[0]?.pkHash ?? "") : op.pkHash;
  return [...ops].sort(
    (a, b) =>
      (a.kind === "upsert" ? 0 : 1) - (b.kind === "upsert" ? 0 : 1) ||
      pkOf(a).localeCompare(pkOf(b)),
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
      ? await omittedDigest(deps, connectionId, p.stream, p.replace)
      : p.replacing && p.omitting
        ? await omittedDigest(
            deps,
            connectionId,
            p.stream,
            p.replacing,
            p.omitting,
          )
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
    statements.push(
      {
        sql: "UPDATE stream_state SET publish_watermark = ? WHERE connection_id = ? AND stream = ? AND publish_watermark < ?",
        params: [p.ack, connectionId, p.stream, p.ack],
      },
      {
        sql: "UPDATE record_changes SET publish_blocked_reason=NULL WHERE connection_id=? AND stream=? AND seq <= ?",
        params: [connectionId, p.stream, p.ack],
      },
    );
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
  entry: PendingCommit,
  clock: PhaseClock,
): Promise<Committed> {
  const candidate = entry.candidate;
  await invalidateExpiredCandidate(held, connectionId, entry);
  if (entry.state.kind === "invalidated")
    return { kind: "retry", conflict: false };
  const [connection] = await held.db.query<
    ConnectionRow & { control_state: string }
  >(
    "SELECT connector, ns, generation, control_state FROM connections WHERE connection_id = ?",
    [connectionId],
  );
  if (!connection || connection.generation !== candidate.generation) {
    transition(entry, "invalidated");
    return { kind: "retry", conflict: false };
  }
  const log = await readLogState(held, connectionId);
  if (
    (await basisOf(held, connectionId, candidate.planned, log)) !==
    candidate.basis
  ) {
    transition(entry, "invalidated");
    return { kind: "retry", conflict: false };
  }
  const results = (outcome: PublishResult["outcome"]): Committed => ({
    kind: "done",
    more: false,
    results: candidate.planned.map((p): PublishResult => ({
      stream: p.stream,
      outcome: p.included ? outcome : "deferred",
      watermark: p.watermark,
    })),
  });
  if (await hasDeleteIntent(held, connection.connector)) {
    transition(entry, "invalidated");
    return results("deferred");
  }

  const scope = logScope(connection.connector, connection.ns);
  const control = controlScope(connection.connector, connection.ns);
  const keyCheck = await deriveKeyCheck(held.keys.namespaceHmac);
  const hashes = await controlHashes(keccakOf(held.streamCrypto), keyCheck);
  const metadataHash = await metadataHashFor(
    scope,
    new Date(candidate.observedAt).toISOString(),
    candidate.cipher.length,
    held.streamCrypto,
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
    // A reset can have no refs while retaining an older registry position.
    // Only position 1 creates the log row for the first time.
    ...(candidate.position === 1
      ? { expectedHeadAbsent: true }
      : candidate.prevHash !== null
        ? { expectedHeadDataHash: candidate.prevHash }
        : {}),
  };
  // A first save creates the control row in the same request: one commit.
  const creation = candidate.createControl
    ? await controlCreation(held, control, hashes)
    : null;
  const request = {
    ownerAddress: held.ownerAddress,
    rows: creation ? [creation, row] : [row],
    requires: [controlCondition(control, connection, hashes)],
  };
  // These rows commit together or not at all, so a policy with no room for
  // them fails the save. A policy not yet known comes with the gateway's
  // refusal of the request.
  checkBatchRoom(batchBounds(held.registry), request);
  let answer;
  try {
    answer = await clock.time("registry-commit", () =>
      postBatchOnce(held.registry, request, () =>
        transition(entry, "ambiguous"),
      ).catch((error: unknown) => {
        if (error instanceof RegistryRefusedError)
          checkBatchRoom(batchBounds(held.registry), request);
        throw error;
      }),
    );
  } catch (error) {
    // Nothing was written: an earlier send that may have landed is settled
    // first, then the caller refuses the candidate.
    if (error instanceof RegistryBatchRouteMissingError)
      await reconcileBeforeRefusal(held, connectionId, entry);
    throw error;
  }
  if (answer.kind === "precondition_failed") {
    await reconcileBeforeRefusal(held, connectionId, entry);
    if (entry.state.kind === "uploaded") transition(entry, "refused");
    return results(
      await controlFailed(held, connectionId, control, answer.failure),
    );
  }
  if (!(await lifetimeHolds(held, connectionId, connection.generation))) {
    await reconcileBeforeRefusal(held, connectionId, entry);
    transition(entry, "invalidated");
    return results("deferred");
  }
  if (answer.kind === "refused") {
    // Nothing was written. The row that lost says why.
    const [created, logged] = creation
      ? answer.rows
      : [undefined, answer.rows[0]!];
    if (created?.kind === "conflict") {
      // Another device's row holds the control scope: read it.
      const state = await readControl(held, connectionId, connection, hashes);
      await reconcileBeforeRefusal(held, connectionId, entry);
      transition(entry, "invalidated");
      if (state === "active") {
        await held.db.batch([markControlActive(connectionId, connection)]);
        return { kind: "retry", conflict: false };
      }
      if (state === "create") return { kind: "retry", conflict: false };
      return results(state);
    }
    const settlement = settleRow(logged!, {
      expectedVersion: row.expectedVersion,
      dataHash: row.dataHash,
    });
    if (settlement === "conflict") {
      // Another writer holds this position. Take its segments, then plan again.
      await applyConnection(held, connectionId);
      transition(entry, "reconciled");
      transition(entry, "invalidated");
      return { kind: "retry", conflict: true };
    }
    // A copy of this very row landed earlier, with the whole request that
    // held it: published.
    if (settlement !== "committed") {
      await reconcileBeforeRefusal(held, connectionId, entry);
      transition(entry, "invalidated");
      return { kind: "retry", conflict: false };
    }
  }
  transition(entry, "committed");
  if (await hasDeleteIntent(held, connection.connector)) {
    transition(entry, "invalidated");
    return results("deferred");
  }

  // The registry took the segment: record it, in one batch.
  const newRef: SegmentRef = {
    position: candidate.position,
    dataHash: candidate.dataHash,
    bytes: candidate.clearBytes,
    removes: candidate.removes,
  };
  const statements: SqlStatement[] = candidate.createControl
    ? [markControlActive(connectionId, connection)]
    : [];
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
    else if (p.replacing && p.omitting)
      statements.push(
        tombstoneOmissions(
          connectionId,
          p.stream,
          p.replacing.o,
          p.replacing.r,
          held.publishWhileCollecting === true,
          p.omitting,
        ),
        replaceDelete(
          connectionId,
          p.stream,
          p.replacing.o,
          p.replacing.r,
          p.omitting,
        ),
      );
  }
  for (const p of touched) {
    const meta = p.meta!;
    statements.push(
      {
        sql: `INSERT OR REPLACE INTO stream_versions (connection_id, stream, version, generation,
                head_blob, head_format, record_count, observed_at, complete, kind,
                primary_key, profile_key, profile_version)
              SELECT ?, ?, MAX(s.head_version, s.last_delete_version) + 1, ?, ?, ?,
                     (SELECT COUNT(*) FROM records r WHERE r.connection_id = ? AND r.stream = ?),
                     ?, ?, 'published', ?, ?, ?
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
          JSON.stringify(meta.primaryKey),
          meta.profile.key,
          meta.profile.version,
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
  statements.push(
    ...(await candidateAcknowledgements(held, connectionId, candidate)),
  );
  statements.push(
    writeLogState(connectionId, {
      position: candidate.position,
      base: candidate.base,
      refs: [...candidate.refs, newRef],
      snapshot: candidate.snapshot,
    }),
    ...(await compaction(held, connectionId, candidate.planned)),
  );
  await clock.time("local-commit", () =>
    held.db.batch(withOrigin("refresh", statements)),
  );

  for (const p of touched)
    await p.workspace?.published(p.omitted, p.replace !== null);

  const more = candidate.planned.some((p) => p.rest);
  return {
    kind: "done",
    more,
    results: publishedResults(connectionId, candidate),
  };
}

function publishedResults(
  connectionId: string,
  candidate: Candidate,
): PublishResult[] {
  return candidate.planned.map((p): PublishResult => ({
    stream: p.stream,
    outcome: p.included ? "published" : p.plan.deferred ? "deferred" : "noop",
    watermark: p.ack,
    ...(p.included && {
      publication: {
        connectionId,
        connector: candidate.connector,
        ns: candidate.ns,
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
  }));
}

async function candidateAcknowledgements(
  held: LocalSyncDeps,
  connectionId: string,
  candidate: Candidate,
): Promise<SqlStatement[]> {
  const statements: SqlStatement[] = [];
  const touched = candidate.planned.filter((p) => p.included);
  // A replace still under way read the stream at its basis; the segment this
  // round committed is this device's own, so the basis moves to it (after the
  // head columns above have).
  for (const p of touched)
    if (p.replacing)
      statements.push({
        sql: `UPDATE run_streams SET
                basis_version = (SELECT head_version FROM stream_state WHERE connection_id = ? AND stream = ?),
                basis_data_hash = ?, basis_generation = ?
               WHERE run_id = ? AND stream = ? AND replace = 1
                 AND (SELECT head_data_hash FROM stream_state WHERE connection_id = ? AND stream = ?) = ?`,
        params: [
          connectionId,
          p.stream,
          candidate.dataHash,
          candidate.generation,
          p.replacing.r,
          p.stream,
          connectionId,
          p.stream,
          candidate.dataHash,
        ],
      });
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
      statements.push(
        {
          sql: "UPDATE stream_state SET publish_watermark = ? WHERE connection_id = ? AND stream = ? AND publish_watermark < ?",
          params: [p.ack, connectionId, p.stream, p.ack],
        },
        {
          sql: "UPDATE record_changes SET publish_blocked_reason=NULL WHERE connection_id=? AND stream=? AND seq <= ?",
          params: [connectionId, p.stream, p.ack],
        },
      );
  }

  return statements;
}

async function reconcileBeforeRefusal(
  held: LocalSyncDeps,
  connectionId: string,
  entry: PendingCommit,
) {
  if (!hasAmbiguousCommit(entry)) return;
  await reconcileCandidate(held, connectionId, entry);
}

async function reconcileCandidate(
  held: LocalSyncDeps,
  connectionId: string,
  entry: PendingCommit,
): Promise<readonly PublishResult[] | null> {
  const candidate = entry.candidate;
  const scope = logScope(candidate.connector, candidate.ns);
  const read = await held.registry.read(scope);
  if (isInvalidated(entry)) {
    transition(entry, "reconciled");
    return null;
  }
  // Apply the registry's history before looking at the local basis. Applying
  // preserves newer local rows; acknowledgement covers only this candidate's
  // runs and watermark, never the collector that ended while its reply was lost.
  await applyConnection(held, connectionId, [{ scope, read }]);
  await invalidateExpiredCandidate(held, connectionId, entry);
  if (isInvalidated(entry)) {
    transition(entry, "reconciled");
    return null;
  }
  const log = await readLogState(held, connectionId);
  const own =
    read.found &&
    read.version >= candidate.position &&
    log.refs.some(
      (r) =>
        r.position === candidate.position && r.dataHash === candidate.dataHash,
    );
  if (!own) {
    transition(entry, "reconciled");
    transition(entry, "invalidated");
    return null;
  }
  transition(entry, "committed");
  await held.db.batch(
    withOrigin("refresh", [
      ...(await candidateAcknowledgements(held, connectionId, candidate)),
      ...(await compaction(held, connectionId, candidate.planned)),
    ]),
  );
  return publishedResults(connectionId, candidate);
}
