import { holdMemory } from "./transfer-memory.js";
import { listStreamBlobs, uploadBlobs, type BlobDescriptor } from "./blobs.js";
// PS-2 P09 publish: the publish side of local sync.
//
// Per connection, after apply. Per stream with work, in three phases. Only
// the first and the last hold the connection's queue slot; the middle one
// holds none, so a run's begin never waits for the upload. The slot is not
// network-free: the snapshot still reads the registry and prior head blobs,
// and the commit still reads, signs and posts the CAS under it.
//
//   SNAPSHOT (slot)  1. Snapshot W = max(seq) in record_changes and the
//      changes with seq > publish_watermark and seq <= W.
//      2. Registry: a newer registry head is applied (same slot turn) and
//      the stream restarts at step 1; a deleted control row purges the
//      connection and stops.
//      3. Re-plan the retained ended runs against the registry head. A run
//      accepted at end but now refused is un-written in one batch and
//      apply runs at once; a deferred run defers the stream.
//      Freeze what the next phase needs: the rows of each changed prefix,
//      copied by SQL into the attempt's rows of `publish_spool` (on disk, in
//      the same database; under replace, leaving out rows below the run's
//      stamp), the attachments to upload, and the basis the snapshot rests
//      on (control, stream state, head parts, delete intents, retained runs,
//      W, and what readBasis lists).
//   TRANSFER (no slot)  4. Read the spooled rows page by page, encode,
//      upload every new part and attachment, build the head and upload it.
//      Objects are content addressed and authorize nothing until the registry
//      CAS, so they need no mutual exclusion. The spool is a copy no write to
//      `records` reaches, so continuous collection cannot invalidate a
//      transfer; only the commit's revalidation can. Each page is a plain read
//      (no slot, no transaction across a network await) of at most a few
//      MiB of bodies, so memory is a page and the part in progress. A spool
//      that lost rows discards the candidate before its head exists.
//      Attachment bytes are read by exact id and checked against it. The
//      attempt's spool rows are deleted when the attempt ends, however it
//      ends; `openLocalDb` deletes any a crash left.
//   COMMIT (slot)  5. Re-read the basis and the registry rows. A change in
//      what readBasis compares discards the candidate and re-snapshots (up
//      to MAX_INVALIDATIONS re-snapshots, then the work stays pending for the
//      next cycle); nothing merges. Otherwise head,
//      then registry CAS from head_version: the same data hash skips the CAS;
//      a conflict applies the winner and re-plans, at most 5 tries, then back
//      off. On success one batch: replace deletes (origin refresh), head
//      identity, publish_watermark = the SNAPSHOT's W (never a fresh max, so a
//      run that ended during the transfer stays pending), head_parts,
//      stream_versions, compaction of record_changes at or below the
//      connection's lowest watermark (kept while an import read-back is
//      pending).
//
// Seeds (import rows with stamp (0, "seed")) publish only into generation
// 1; otherwise they are purged and the ledger records excluded(seed_skipped).
//
// Every stream of one connection runs together. Each
// stream's turns take the slot one at a time, so the control row is settled
// by whichever snapshot runs first and every other stream sees it active; the
// transfers overlap. Each stream's own state (stream_state row, spool attempt,
// watermark) is its own; the connection's state (control, apply) is only
// touched in a slot turn, and a change to it shows in the other streams'
// readBasis. A purge sets a latch in its turn: streams still running stop at
// their next turn or upload and report "purged"; no stream starts after it.
//
// Queue: this module takes the connection's "publish" slot itself, for the
// snapshot and the commit. The caller must not hold it. applyConnection and
// purgeConnection, called inside a turn, run inline in that turn.

import { keccak_256 } from "@noble/hashes/sha3";
import {
  HEAD_FORMAT,
  classifyControl,
  classifyStreamRow,
  controlHashes,
  controlScope,
  deriveKeyCheck,
  digestHead,
  encodeHead,
  headBlobName,
  streamScope,
  toHex,
  utf8,
  verifyHead,
  type ControlHashes,
  type ControlRead,
  type Head,
  type HeadPart,
  type Keccak256,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  planStreamStep,
  type PlanHead,
  type PlanRun,
  type StepDecision,
} from "../stream-sync/publish-plan.js";
import { applyConnection } from "./apply.js";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";
import {
  FrozenRowsChanged,
  dropSpool,
  freezePrefixRows,
  newSpoolAttempt,
  PARTS_IN_FLIGHT,
  partTargetOf,
  startFrozenParts,
  type EncodedPart,
  type FrozenPrefix,
  type HeadExtras,
} from "./encode.js";
import { planChangedPrefixes } from "./part-layout.js";
import {
  StorageDeferredError,
  type SendWindowStats,
} from "../stream-sync/storage-retry.js";
import {
  meteredBlobs,
  newPublishMeter,
  publishTimings,
  timed,
  type PublishMeter,
} from "./publish-meter.js";
import { replaceDelete, withOrigin } from "./merge.js";
import {
  endsEarlierLifetime,
  hydrateLifetimeBoundary,
  olderLifetimeFence,
} from "./lifetime-boundary.js";
import { purgeConnection } from "./purge.js";
import { checkRunFence } from "./fence.js";
import { replaceMayApply } from "./replace.js";
import { openRegistryView, type RegistryView } from "./registry-view.js";
import { insideQueue } from "./slot.js";
import { recallHead, rememberHead, rememberOwnHead } from "./verified-heads.js";
import { newUploadWave, type UploadWave } from "./upload-wave.js";
import { unwriteRefusedRun } from "./unwrite.js";

/** Confirmed publication of one stream in a connector namespace. */
export interface PublicationReceipt {
  readonly connectionId: string;
  readonly connector: string;
  readonly ns: string;
  readonly stream: string;
  readonly head: {
    readonly version: number;
    readonly generation: number;
    readonly dataHash: string;
  };
  /** Local record-change sequence included, scoped to this database. */
  readonly watermark: number;
  /** Accepted ended runs included in this stream's publication plan. */
  readonly runIds: readonly string[];
}

export interface PublishResult {
  readonly publication?: PublicationReceipt;
  readonly stream: string;
  readonly outcome:
    | "published"
    | "noop"
    | "deferred"
    | "refused"
    | "discarded"
    | "purged"
    | "backoff";
  readonly watermark: number | null; // max(seq) read in step 1; new publish_watermark on success
}

/**
 * All streams of one connection start at once. Their transfers (the uploads)
 * overlap; their snapshot and commit turns still take the connection's slot one
 * at a time. No stream count bounds the work: the blob store's send governor
 * paces every request and bounds the encoded bytes held in memory.
 */
export interface PublishOptions {
  readonly headExtras?: (stream: string) => Promise<HeadExtras | undefined>;
}

export async function publishConnection(
  deps: LocalSyncDeps,
  connectionId: string,
  options?: PublishOptions,
): Promise<readonly PublishResult[]> {
  const opened = await deps.queue.run(connectionId, "publish", async () => {
    const held = insideQueue(deps, connectionId);
    const [connection] = await held.db.query<ConnectionRow>(
      `SELECT connector, ns, generation FROM connections WHERE connection_id = ?`,
      [connectionId],
    );
    if (!connection) {
      throw new Error(`publish: unknown connection ${connectionId}`);
    }
    const keyCheck = await deriveKeyCheck(held.keys.namespaceHmac);
    const hashes = await controlHashes(keccak, keyCheck);
    const streams = await held.db.query<{ stream: string }>(
      `SELECT stream FROM stream_state WHERE connection_id = ? ORDER BY stream`,
      [connectionId],
    );
    if (
      (
        await held.db.query("SELECT 1 FROM delete_intents WHERE connector=?", [
          connection.connector,
        ])
      ).length
    )
      return {
        results: streams.map(({ stream }): PublishResult => ({
          stream,
          outcome: "deferred",
          watermark: null,
        })),
      };
    if (streams.length === 0) {
      const state = classifyControl(
        await held.registry.read(
          controlScope(connection.connector, connection.ns),
        ),
        hashes,
      );
      if (state.kind === "deleted")
        await purgeConnection(held, connectionId, {
          controlVersion: state.version,
        });
    }
    return { connection, keyCheck, hashes, streams };
  });
  if (opened.results) return opened.results;
  const { connection, keyCheck, hashes, streams } = opened;
  const latch: PurgeLatch = { purged: false };
  const view = openRegistryView(deps, connection, streams.length);
  const sendWindow = deps.blobs.governor?.window();
  const published = await publishEach(
    streams.map(({ stream }) => stream),
    latch,
    (stream) =>
      publishStream(
        deps,
        connectionId,
        connection,
        stream,
        keyCheck,
        hashes,
        latch,
        view,
        options,
      ),
  ).finally(() => logSendGate(deps, connectionId, sendWindow));
  // A deleted control row purges the whole connection. Every stream that
  // started has a result, "purged" included: with streams running together,
  // a stream after the purged one may already have published, and leaving it
  // out would hide a real publication. A stream missing from the results never
  // started.
  return published;
}

/**
 * Set, in the slot turn that purged the connection, so that the next turn of
 * any stream of the connection sees it. Streams of one publish share one.
 */
type PurgeLatch = { purged: boolean };

/** A stream stopped because another stream's turn purged the connection. */
class ConnectionPurged extends Error {
  constructor() {
    super("publish: the connection was purged");
  }
}

function stopIfPurged(latch: PurgeLatch): void {
  if (latch.purged) throw new ConnectionPurged();
}

/**
 * Run `publish` for every stream at once. Returns the results of the streams
 * that ran, in stream order whatever order they finished in. Every stream is
 * waited for, so nothing runs on after this returns; a stream that starts
 * after the connection was purged or another stream failed stops at its next
 * turn or upload. The failure of the earliest stream is thrown.
 */
async function publishEach(
  streams: readonly string[],
  latch: PurgeLatch,
  publish: (stream: string) => Promise<PublishResult>,
): Promise<PublishResult[]> {
  const results: (PublishResult | undefined)[] = streams.map(() => undefined);
  const failures = new Map<number, unknown>();
  await Promise.all(
    streams.map(async (stream, at) => {
      try {
        results[at] = await publish(stream);
      } catch (error) {
        failures.set(at, error);
      }
    }),
  );
  if (failures.size > 0) throw failures.get(Math.min(...failures.keys()));
  return results.filter((r): r is PublishResult => r !== undefined);
}

/** One line per publish that sent requests: what the send governor did. */
function logSendGate(
  deps: LocalSyncDeps,
  connectionId: string,
  window: { end(): SendWindowStats } | undefined,
): void {
  const stats = window?.end();
  if (!stats || stats.requests === 0) return;
  deps.logger.info(
    {
      connectionId,
      gateWindow: stats.window,
      ...(stats.quotaPerSec === undefined
        ? {}
        : {
            quotaPerSec: Object.fromEntries(
              Object.entries(stats.quotaPerSec).map(([kind, rate]) => [
                kind,
                Math.round(rate * 100) / 100,
              ]),
            ),
          }),
      requests: stats.requests,
      throttles: stats.throttles,
      retryAfterWaitMs: Math.round(stats.retryAfterWaitMs),
      peakBytesInFlight: stats.peakBytesInFlight,
    },
    "stream sync: publish send gate",
  );
}

const keccak: Keccak256 = async (data) => keccak_256(data);

/** metadataHash for a head: keccak over the UTF-8 JSON of the envelope facts. */
function metadataHashFor(
  scope: string,
  collectedAt: string,
  sizeBytes: number,
): `0x${string}` {
  return `0x${toHex(keccak_256(utf8(JSON.stringify({ scope, collectedAt, sizeBytes }))))}`;
}

type ConnectionRow = {
  connector: string;
  ns: string;
  generation: number;
};

type LocalStream = {
  primary_key: string;
  profile_key: string | null;
  profile_version: string | null;
  complete: number;
  floor_version: string | null;
  floor_o: number | null;
  floor_r: string | null;
  last_delete_version: number;
  head_version: number;
  head_generation: number | null;
  head_data_hash: string | null;
  publish_watermark: number;
};

type RetainedRun = {
  run_id: string;
  o: number;
  generation: number | null;
  artifact_version: string;
  primary_key: string | null;
  profile_key: string | null;
  profile_version: string | null;
  full_read: number;
  foreign_checkpoint: number;
  seed: "none" | "merged" | "unresolved";
  decision: string;
  replace: number;
  basis_version: number | null;
  basis_generation: number | null;
  basis_data_hash: string | null;
  row_count: number;
};

type ChangeRow = { pk_hash: string };

const MAX_ATTEMPTS = 5;
/**
 * Re-snapshots allowed after a candidate was discarded (a changed basis, or a
 * spool that lost rows) before the work waits for the next cycle. A cycle
 * builds at most MAX_INVALIDATIONS + 1 candidates for a stream. A write that
 * only re-stamps rows is not a reason to discard: the transfer sends its copy.
 */
const MAX_INVALIDATIONS = 3;

/** What one stream's publish carries from one loop pass to the next. */
type StreamRun = {
  sawRefusal: boolean;
  appliedVersion: number | null;
  attempts: number;
  invalidations: number;
  watermark: number | null;
  /**
   * The attempt whose rows are in `publish_spool`, and the prefixes it froze;
   * see `endSpool`.
   */
  spool: {
    readonly attempt: string;
    readonly prefixes: readonly string[];
  } | null;
  /** Counts for the one log line the stream's publish ends with. */
  readonly meter: PublishMeter;
};

type StreamContext = {
  readonly connectionId: string;
  readonly connection: ConnectionRow;
  readonly stream: string;
  readonly scope: string;
  readonly keyCheck: string;
  readonly hashes: ControlHashes;
  readonly latch: PurgeLatch;
  /** What the publish already read from the registry; see registry-view.ts. */
  readonly view: RegistryView;
  readonly options: PublishOptions | undefined;
};

/**
 * Everything a transfer and a commit need, frozen under the slot. Nothing
 * here is read again from local state; `basis` is how the commit learns the
 * local state it rests on has moved.
 */
type Candidate = {
  readonly basis: string;
  /** The change watermark W of the snapshot; the commit acknowledges this. */
  readonly watermark: number;
  readonly localWatermark: number;
  readonly registryVersion: number;
  readonly registryDataHash: string | null;
  readonly baseParts: readonly HeadPart[];
  readonly changedPrefixes: readonly string[];
  readonly frozen: readonly FrozenPrefix[];
  /** The spool rows of `frozen`; the transfer reads them, nothing else does. */
  readonly attempt: string;
  readonly blobs: readonly BlobDescriptor[];
  readonly headGeneration: number;
  /** The head but for its parts, which the transfer produces. */
  readonly head: Omit<Head, "parts" | "recordCount">;
  readonly replaceBelow: { o: number; r: string } | undefined;
  readonly runIds: readonly string[];
  readonly sawRefusal: boolean;
};

type Prepared = {
  readonly parts: readonly HeadPart[];
  readonly recordCount: number;
  readonly dataHash: `0x${string}`;
  readonly blobName: string;
  /** `null` when the head equals the registry head: nothing to publish. */
  readonly encryptedLength: number | null;
  /**
   * The head this device encoded, as the reader would parse it: the result of
   * `verifyHead` on the exact bytes that were hashed and uploaded. `null` when
   * `encryptedLength` is `null`: that head is the registry's own, and the
   * snapshot that planned over it already verified and remembered it.
   */
  readonly verifiedHead: Head | null;
};

type Snapshot =
  | { readonly kind: "done"; readonly result: PublishResult }
  | { readonly kind: "retry" }
  | {
      readonly kind: "blobs";
      readonly blobs: readonly BlobDescriptor[];
      readonly result: PublishResult;
      /** Held until the attachments are up; see `confirmNoWork`. */
      readonly evidence: RunEvidence | null;
    }
  | { readonly kind: "candidate"; readonly candidate: Candidate };

type Committed =
  | { readonly kind: "done"; readonly result: PublishResult }
  | { readonly kind: "retry" }
  | { readonly kind: "invalidated" };

async function publishStream(
  deps: LocalSyncDeps,
  connectionId: string,
  connection: ConnectionRow,
  stream: string,
  keyCheck: string,
  hashes: ControlHashes,
  latch: PurgeLatch,
  view: RegistryView,
  options: PublishOptions | undefined,
): Promise<PublishResult> {
  const run: StreamRun = {
    sawRefusal: false,
    appliedVersion: null,
    attempts: 0,
    invalidations: 0,
    watermark: null,
    spool: null,
    meter: newPublishMeter(),
  };
  const startedAt = deps.now();
  let outcome: PublishResult["outcome"] | "failed" = "failed";
  try {
    const result = await publishAttempts(
      deps,
      run,
      connectionId,
      connection,
      stream,
      keyCheck,
      hashes,
      latch,
      view,
      options,
    ).catch((error: unknown): PublishResult => {
      if (error instanceof ConnectionPurged)
        return { stream, outcome: "purged", watermark: run.watermark };
      // Storage kept refusing past the retry budget. Nothing is wrong with
      // the data: the stream stays in the durable queue (its watermark is not
      // advanced) and the next cycle sends it again.
      if (error instanceof StorageDeferredError) {
        deps.logger.info(
          { connectionId, stream, error: error.message },
          "stream sync: storage unavailable, publish left in the queue",
        );
        return { stream, outcome: "backoff", watermark: run.watermark };
      }
      throw error;
    });
    outcome = result.outcome;
    return result;
  } finally {
    // Commit, discard and failure all end here.
    await endSpool(deps, run);
    logPublishTimings(
      deps,
      connectionId,
      stream,
      outcome,
      run.meter,
      startedAt,
    );
  }
}

/**
 * One info line per stream publish that did work, so a journey reads where the
 * time went. A stream with nothing to do (a quiet poll) logs nothing: it would
 * add a line per stream every cycle.
 */
function logPublishTimings(
  deps: LocalSyncDeps,
  connectionId: string,
  stream: string,
  outcome: PublishResult["outcome"] | "failed",
  meter: PublishMeter,
  startedAt: number,
): void {
  const idle =
    (outcome === "noop" || outcome === "deferred") &&
    meter.blobGets === 0 &&
    meter.blobPuts === 0;
  if (idle) return;
  deps.logger.info(
    {
      connectionId,
      stream,
      outcome,
      ...publishTimings(meter, deps.now() - startedAt),
    },
    "stream sync: stream publish timings",
  );
}

/**
 * Drop the spool rows of the attempt in `run`, if it spooled any. A failed
 * drop leaves rows that the next start deletes; it must not hide the
 * attempt's result.
 */
async function endSpool(deps: LocalSyncDeps, run: StreamRun): Promise<void> {
  const { spool } = run;
  if (spool === null) return;
  run.spool = null;
  await dropSpool(deps, spool.attempt, spool.prefixes).catch((error: unknown) =>
    deps.logger.warn(
      { error: String(error) },
      "publish: spool rows not dropped",
    ),
  );
}

async function publishAttempts(
  deps: LocalSyncDeps,
  run: StreamRun,
  connectionId: string,
  connection: ConnectionRow,
  stream: string,
  keyCheck: string,
  hashes: ControlHashes,
  latch: PurgeLatch,
  view: RegistryView,
  options: PublishOptions | undefined,
): Promise<PublishResult> {
  const context: StreamContext = {
    connectionId,
    connection,
    stream,
    scope: streamScope(connection.connector, connection.ns, stream),
    keyCheck,
    hashes,
    latch,
    view,
    options,
  };
  // Another stream may have purged the connection while this one waited for
  // the turn or was transferring: the turn does nothing then.
  const slot = <T>(work: (held: LocalSyncDeps) => Promise<T>) =>
    deps.queue.run(connectionId, "publish", () => {
      stopIfPurged(latch);
      return work(insideQueue(deps, connectionId));
    });
  while (run.attempts < MAX_ATTEMPTS) {
    stopIfPurged(latch);
    if (run.invalidations > MAX_INVALIDATIONS) {
      // Local state kept moving under every candidate. Nothing was published
      // and nothing was acknowledged: the work is still pending next cycle.
      return { stream, outcome: "backoff", watermark: run.watermark };
    }
    // The last attempt's copy is of no use now: it was discarded or ended.
    await endSpool(deps, run);
    const snapshot = await timed(
      deps,
      (ms) => (run.meter.planMs += ms),
      () => slot((held) => snapshotStream(held, context, run)),
    );
    if (snapshot.kind === "done") return snapshot.result;
    if (snapshot.kind === "retry") continue;
    if (snapshot.kind === "blobs") {
      await uploadBlobs(deps, snapshot.blobs, run.meter, () =>
        stopIfPurged(latch),
      );
      // The attachments took time outside the slot: the control row and the
      // stream row are read again before the stream is called done.
      const { evidence, result } = snapshot;
      const ended = await slot((held) =>
        confirmNoWork(held, context, evidence),
      );
      return ended
        ? { stream, outcome: ended, watermark: result.watermark }
        : result;
    }
    const { candidate } = snapshot;
    stopIfPurged(latch);
    let prepared: Prepared;
    try {
      prepared = await timed(
        deps,
        (ms) => (run.meter.transferMs += ms),
        () => transferCandidate(deps, context, candidate, run.meter),
      );
    } catch (error) {
      if (error instanceof ConnectionPurged) throw error;
      // A transfer that lost its input because local state moved (a purge
      // took the spooled rows or an attachment) is a stale candidate, not a
      // failure.
      if (error instanceof FrozenRowsChanged) {
        run.invalidations++;
        continue;
      }
      if ((await readBasis(deps, context, candidate)) === candidate.basis)
        throw error;
      run.invalidations++;
      continue;
    }
    const committed = await slot((held) =>
      commitCandidate(held, context, candidate, prepared, run),
    );
    if (committed.kind === "done") return committed.result;
    if (committed.kind === "invalidated") run.invalidations++;
    // A lost CAS applied the winner: the next snapshot of this stream reads
    // the registry. Streams start together, so none takes a first snapshot
    // after this; the call keeps a listing from outliving the conflict.
    if (committed.kind === "retry") view.invalidate();
  }
  return { stream, outcome: "backoff", watermark: run.watermark };
}

/**
 * SNAPSHOT, in the slot. Steps 1-3 of the file comment, then everything the
 * transfer needs, read once. Returns a result when the stream ends here.
 */
async function snapshotStream(
  deps: LocalSyncDeps,
  context: StreamContext,
  run: StreamRun,
): Promise<Snapshot> {
  const { connectionId, connection, stream, scope, keyCheck, hashes } = context;
  const control = controlScope(connection.connector, connection.ns);
  const done = (result: PublishResult): Snapshot => ({ kind: "done", result });
  // An apply changes local state from the registry: a listing taken before it
  // is not a starting point for any stream's first snapshot after it.
  const applyRegistry = async () => {
    context.view.invalidate();
    await applyConnection(deps, connectionId);
  };
  const deferred = (): Snapshot =>
    done({ stream, outcome: "deferred", watermark: run.watermark });

  // Step 1: snapshot W and the changes since the last publish.
  let [local] = await deps.db.query<LocalStream>(
    `SELECT primary_key, profile_key, profile_version, complete,
            floor_version, floor_o, floor_r, last_delete_version,
            head_version, head_generation, head_data_hash, publish_watermark
       FROM stream_state WHERE connection_id = ? AND stream = ?`,
    [connectionId, stream],
  );
  if (!local) {
    throw new Error(`publish: missing local stream state for ${stream}`);
  }
  const [wRow] = await deps.db.query<{ w: number | null }>(
    `SELECT MAX(seq) AS w FROM record_changes WHERE connection_id = ? AND stream = ?`,
    [connectionId, stream],
  );
  const watermark = wRow?.w ?? local.publish_watermark;
  run.watermark = watermark;
  const changes: ChangeRow[] = await deps.db.query<ChangeRow>(
    `SELECT pk_hash FROM record_changes
      WHERE connection_id = ? AND stream = ?
        AND seq > ? AND seq <= ?
        AND origin IN ('local', 'import', 'refresh')
        AND NOT EXISTS (SELECT 1 FROM runs r JOIN run_streams rs ON rs.run_id=r.run_id
          WHERE r.connection_id=record_changes.connection_id AND rs.stream=record_changes.stream
            AND r.run_id=record_changes.stamp_r AND r.o=record_changes.stamp_o
            AND rs.decision IN ('refused','discarded'))`,
    [connectionId, stream, local.publish_watermark, watermark],
  );

  // Step 2: registry. A deleted control row purges and stops; a foreign
  // control row, or one whose generation moved, defers the stream.
  // The hints of this stream's first snapshot; a snapshot that repeats reads
  // the registry. A control hint is only an active row of this generation:
  // absent would create the row and deleted would purge, so those are read.
  const hints = await context.view.firstSnapshot(scope);
  const hintedState = hints.control && classifyControl(hints.control, hashes);
  const hintedControl =
    hintedState?.kind === "active" &&
    hintedState.generation === connection.generation;
  let controlRead = hintedControl
    ? hints.control!
    : await deps.registry.read(control);
  let controlState = classifyControl(controlRead, hashes);
  if (controlState.kind === "absent") {
    if (connection.generation !== 1) return deferred();
    const signature = await deps.signer.signAddData({
      ownerAddress: deps.ownerAddress,
      scope: control,
      dataHash: hashes.activeData,
      metadataHash: hashes.activeMetadata,
      expectedVersion: 1n,
    });
    await deps.registry.post({
      ownerAddress: deps.ownerAddress,
      scope: control,
      dataHash: hashes.activeData,
      metadataHash: hashes.activeMetadata,
      expectedVersion: "1",
      signature,
    });
    controlRead = await deps.registry.read(control);
    controlState = classifyControl(controlRead, hashes);
  }
  if (controlState.kind === "deleted") {
    await purgeConnection(deps, connectionId, {
      controlVersion: controlState.version,
    });
    context.latch.purged = true;
    return done({ stream, outcome: "purged", watermark });
  }
  if (controlState.kind === "foreign" || controlState.kind === "absent") {
    deps.logger.warn(
      {},
      "publish: control unavailable for publishing; deferring stream",
    );
    return deferred();
  }
  if (controlState.generation !== connection.generation) {
    await applyRegistry();
    return deferred();
  }
  // A run that began before this control generation never joins it: it is
  // discarded here, before the binding below could give it the generation.
  if (
    await discardForeignLifetimeRuns(
      deps,
      connectionId,
      controlState.generation,
    )
  ) {
    await applyRegistry();
    return { kind: "retry" };
  }
  await deps.db.batch([
    {
      sql: "UPDATE connections SET control_state='active',control_version=? WHERE connection_id=?",
      params: [controlState.generation, connectionId],
    },
    // C.0: an offline fresh run binds when the registry first answers. Only a
    // run that has ended and passed the lifetime check above: a run still
    // collecting keeps its lifetime (none) until it ends, so a collector that
    // began before another writer moved the lifetime is never handed the new
    // one. End then discards it if the lifetime moved past 1.
    {
      sql: "UPDATE runs SET generation=? WHERE connection_id=? AND generation IS NULL AND state='ended'",
      params: [controlState.generation, connectionId],
    },
  ]);

  // A stream row from the listing is a hint (see `hintedRow` below); a repeat
  // snapshot reads it.
  const hintedRow = hints.stream !== undefined;
  const streamRead = hints.stream ?? (await deps.registry.read(scope));
  const streamRow = classifyStreamRow(streamRead, hashes);
  // Hints are older than this turn. Anything a snapshot does besides building
  // a candidate (the commit has its own live checks and a CAS) acts on the
  // registry as it is now, so it reads again first: the stream row, THEN the
  // control row. That order matters: a stream row outlives the deletion of its
  // connection until cleanup, so a row read alone proves nothing, and a
  // control read made before the row read can predate a deletion the row
  // read then misses. A deleted control row purges; one that moved defers; a
  // stream row that is no longer the hinted one repeats the snapshot, which
  // reads live (a hint serves a first snapshot only).
  const confirmHints = async (): Promise<Snapshot | null> => {
    if (!hintedRow && !hintedControl) return null;
    if (hintedRow && !sameRow(await deps.registry.read(scope), streamRead))
      return { kind: "retry" };
    const checked = await checkControl(deps, context);
    return checked ? done({ stream, outcome: checked, watermark }) : null;
  };
  // `registryHead` is the content base: the verified head of THIS lifetime.
  // `registryVersion` and `registryDataHash` are the compare-and-set basis and
  // describe the registry row whatever lifetime its head is from.
  let registryHead: Head | null = null;
  let registryVersion = 0;
  let registryDataHash: string | null = null;
  if (streamRead.found) {
    registryVersion = streamRead.version;
    registryDataHash = streamRead.dataHash;
  }
  if (streamRow === "present" && streamRead.found) {
    const verified = await readRegistryHead(
      deps,
      scope,
      streamRead.dataHash,
      connection,
      stream,
      keyCheck,
    );
    // A head of a later lifetime than this connection knows: it is not ours
    // to replace. Wait for this connection to catch up.
    if (verified.generation > connection.generation) return deferred();
    if (verified.generation === connection.generation) {
      registryHead = verified;
    } else {
      // No content base. Keep the delete fence of that lifetime: record it
      // locally (see lifetime-boundary.ts) and carry it into the new head.
      const fence = olderLifetimeFence(
        scope,
        streamRead,
        verified,
        connection.generation,
      );
      const provenEarlier = endsEarlierLifetime(
        scope,
        streamRead,
        connection.generation,
      );
      await hydrateLifetimeBoundary(deps, {
        connectionId,
        stream,
        generation: connection.generation,
        fence,
        provenEarlier,
        primaryKey: verified.primaryKey,
      });
      // No proof this delete ended an earlier lifetime: it may be the delete
      // of this one, awaiting its control tombstone. Do not write over it.
      if (!provenEarlier) return deferred();
      local = {
        ...local,
        last_delete_version: Math.max(local.last_delete_version, fence),
      };
    }
  }

  // A registry row newer than the local head is applied (same slot turn)
  // and the stream restarts at step 1. Apply once per version: if the head
  // still lags after apply, proceed with the registry head.
  if (streamRead.found && registryVersion > local.head_version) {
    if (run.appliedVersion !== registryVersion) {
      await applyRegistry();
      run.appliedVersion = registryVersion;
      return { kind: "retry" };
    }
  }

  if (await discardFencedRuns(deps, connectionId, stream)) {
    await applyRegistry();
    return { kind: "retry" };
  }
  if (connection.generation !== 1)
    await excludeSeedsIfAny(deps, connectionId, stream);

  // Step 3: re-plan the retained ended runs against the registry head.
  const plan = await planStream(
    deps,
    connectionId,
    connection,
    stream,
    local,
    registryHead,
    registryVersion,
    // No content base: a replacing run replaces nothing, as with an absent row.
    registryHead ? registryDataHash : null,
  );
  if (plan.deferred) return deferred();
  if (plan.refused) {
    const stale = await confirmHints();
    if (stale) return stale;
    run.sawRefusal = true;
    await unwriteRefusedRun(deps, {
      connectionId,
      stream,
      runId: plan.refused.runId,
      reason: plan.refused.reason,
    });
    await applyRegistry();
    return { kind: "retry" };
  }

  const headGeneration = plan.finalHead?.generation ?? connection.generation;
  const blobs = await listStreamBlobs(deps, {
    connectionId,
    stream,
    scope,
    generation: headGeneration,
  });
  const hasWork =
    changes.length > 0 ||
    plan.replaceBelow !== undefined ||
    plan.steps.some((step) => step.decision.kind === "publish");
  if (!hasWork) {
    const stale = await confirmHints();
    if (stale) return stale;
    const result: PublishResult = {
      stream,
      outcome: run.sawRefusal ? "refused" : "noop",
      watermark,
    };
    // No change to publish: the registry head, read in this slot turn, already
    // holds what the plan produces, so a pending run it covers is saved by it.
    const evidence: RunEvidence | null =
      registryHead && registryDataHash !== null
        ? {
            version: registryVersion,
            generation: registryHead.generation,
            dataHash: registryDataHash as `0x${string}`,
            watermark: local.publish_watermark,
            replaceBelow: undefined,
            runIds: plan.steps.map((step) => step.runId),
          }
        : null;
    if (blobs.length > 0) return { kind: "blobs", blobs, result, evidence };
    if (evidence) await saveRunEvidence(deps, connectionId, stream, evidence);
    return done(result);
  }

  // Seeds publish only into generation 1; otherwise they are purged
  // and the ledger records excluded(seed_skipped).
  if (headGeneration !== 1) {
    await excludeSeedsIfAny(deps, connectionId, stream);
  }

  // Step 4 input: the changed prefixes, planned by the spec's bucket planner
  // so parts are sized by the byte target (see part-layout.ts).
  const rewriteAll = Boolean(
    registryHead && (registryHead.format !== HEAD_FORMAT || plan.replaceBelow),
  );
  const changedPrefixes = await planChangedPrefixes(deps, {
    connectionId,
    stream,
    changedKeys: changes.map((change) => change.pk_hash),
    baseParts: registryHead?.parts ?? [],
    targetBytes: partTargetOf(deps),
    rewriteAll,
  });
  // Read the caller's head extras, the rows to encode and the clock now: the
  // transfer reads none of them again.
  await context.options?.headExtras?.(stream);
  const attempt = newSpoolAttempt();
  // Recorded before the freeze, so a freeze that fails part-way is still dropped.
  if (changedPrefixes.length > 0)
    run.spool = { attempt, prefixes: changedPrefixes };
  const frozen =
    changedPrefixes.length === 0
      ? []
      : await freezePrefixRows(deps, {
          connectionId,
          stream,
          attempt,
          changedPrefixes,
          replaceBelow: plan.replaceBelow,
        });
  const observedAt =
    plan.newestRunObservedAt ?? registryHead?.observedAt ?? deps.now();
  const head: Omit<Head, "parts" | "recordCount"> = {
    complete: plan.finalHead?.complete ?? registryHead?.complete ?? false,
    connector: connection.connector,
    format: HEAD_FORMAT,
    generation: headGeneration,
    keyCheck,
    lastDeleteVersion: Math.max(
      // Includes an earlier lifetime's fence, hydrated above.
      local.last_delete_version,
      streamRow === "tombstoned" ? registryVersion : 0,
    ),
    ns: connection.ns,
    observedAt,
    primaryKey:
      plan.finalHead?.primaryKey ??
      registryHead?.primaryKey ??
      JSON.parse(local.primary_key),
    profile: plan.finalHead?.profile ??
      registryHead?.profile ?? {
        key: local.profile_key ?? connection.connector,
        version: local.profile_version ?? local.floor_version ?? "0",
      },
    stream,
  };
  const runIds = plan.steps.map((step) => step.runId);
  const basis = await readBasis(deps, context, {
    watermark,
    localWatermark: local.publish_watermark,
    runIds,
  });
  return {
    kind: "candidate",
    candidate: {
      basis,
      watermark,
      localWatermark: local.publish_watermark,
      registryVersion,
      registryDataHash,
      baseParts: registryHead?.parts ?? [],
      changedPrefixes,
      frozen,
      attempt,
      blobs,
      headGeneration,
      head,
      replaceBelow: plan.replaceBelow,
      runIds,
      sawRefusal: run.sawRefusal,
    },
  };
}

/**
 * TRANSFER, outside the slot. Attachments, parts and the head, each a
 * content-addressed object. It reads the attempt's spooled rows (page by page)
 * and attachment bytes by exact id, so it cannot encode rows the snapshot did
 * not freeze, and no write to `records` can invalidate it. A spool that lost
 * rows throws FrozenRowsChanged.
 *
 * The uploads are not ordered among themselves: nothing points at any of them
 * until the registry CAS, and the head names its parts by hash, which are
 * known once they are encoded. Each upload starts when it is ready and the
 * transfer returns once all of them are stored, so the commit (the registry
 * write) never runs before the stream's last file is in storage. The storage
 * client's limits decide how many go on the wire at once.
 */
async function transferCandidate(
  deps: LocalSyncDeps,
  context: StreamContext,
  candidate: Candidate,
  meter: PublishMeter,
): Promise<Prepared> {
  const wave = newUploadWave(PARTS_IN_FLIGHT);
  try {
    const prepared = await transferOnWave(
      deps,
      context,
      candidate,
      meter,
      wave,
    );
    await wave.drain();
    return prepared;
  } catch (error) {
    // Nothing of this transfer runs on after it returns, nor reports unseen.
    await wave.settle();
    throw error;
  }
}

async function transferOnWave(
  deps: LocalSyncDeps,
  context: StreamContext,
  candidate: Candidate,
  meter: PublishMeter,
  wave: UploadWave,
): Promise<Prepared> {
  const { scope, latch } = context;
  // A stream with no registry row has nothing in storage to find: a probe
  // could only answer "no". An upload of a stored name keeps or replaces the
  // object with another encryption of the same clear bytes, so skipping a
  // probe can repeat an upload and never drop one. Where a row exists (a
  // resume, a refresh) files may well be stored, and a probe saves the upload.
  // The rule is "no registry row", never "this device uploaded it before":
  // storage can delete or overwrite objects.
  const probe = candidate.registryVersion > 0;
  if (candidate.blobs.length > 0) {
    await wave.start(() =>
      uploadBlobs(
        deps,
        candidate.blobs,
        meter,
        () => stopIfPurged(latch),
        probe,
      ),
    );
  }
  const encoded = await startFrozenParts(deps, {
    attempt: candidate.attempt,
    scope,
    generation: candidate.headGeneration,
    frozen: candidate.frozen,
    wave,
    probe,
    meter,
    // A purge by another stream ends this transfer before its next upload.
    beforeUpload: () => stopIfPurged(latch),
  });
  const parts = mergedParts(
    candidate.baseParts,
    encoded,
    candidate.changedPrefixes,
  );
  const recordCount = parts.reduce((sum, part) => sum + part.count, 0);
  const blobs = meteredBlobs(deps, meter);
  // The head is built, verified and encrypted in memory and stays there until
  // its upload settles. It is held as one part's worth, like a part, from
  // before it is built, so heads of many streams cannot pile up under a slow
  // store. The upload task owns the reservation once it starts.
  const release = await holdMemory(blobs, partTargetOf(deps));
  let handedOver = false;
  try {
    const headBytes = encodeHead({ ...candidate.head, parts, recordCount });
    const { dataHash, blobName } = await digestHead(keccak, headBytes);
    // The same data hash as the registry head: nothing to upload or post.
    if (
      candidate.registryDataHash !== null &&
      dataHash.toLowerCase() === candidate.registryDataHash.toLowerCase()
    ) {
      return {
        parts,
        recordCount,
        dataHash,
        blobName,
        encryptedLength: null,
        verifiedHead: null,
      };
    }
    // The reader's own check, on the bytes about to be uploaded: a head that
    // would not verify is never uploaded, posted or remembered.
    const verified = await verifyHead(keccak, headBytes, {
      dataHash,
      connector: context.connection.connector,
      ns: context.connection.ns,
      stream: context.stream,
      keyCheck: context.keyCheck,
    });
    if (verified.kind !== "ok") {
      throw new Error(
        `publish: the head built for ${context.stream} failed verification: ${verified.kind}`,
      );
    }
    const encrypted = await deps.keys.encrypt(scope, headBytes);
    stopIfPurged(latch);
    // Started with the parts still going: the head names them by hash.
    wave.startAlongside(async () => {
      try {
        if (!probe || !(await blobs.exists(`${scope}/${blobName}`))) {
          // A sibling may have purged the connection while the probe was out.
          stopIfPurged(latch);
          await blobs.put(`${scope}/${blobName}`, encrypted, () =>
            stopIfPurged(latch),
          );
        }
      } finally {
        release();
      }
    });
    handedOver = true;
    return {
      parts,
      recordCount,
      dataHash,
      blobName,
      encryptedLength: encrypted.length,
      verifiedHead: verified.head,
    };
  } finally {
    if (!handedOver) release();
  }
}

/** Write run evidence on its own: the no-work path has no head to commit. */
async function saveRunEvidence(
  deps: LocalSyncDeps,
  connectionId: string,
  stream: string,
  evidence: RunEvidence,
): Promise<void> {
  const statements = await runPublicationStatements(
    deps,
    connectionId,
    stream,
    evidence,
  );
  if (statements.length > 0) await deps.db.batch(statements);
}

/**
 * The no-work path with attachments to upload: the snapshot's slot turn is
 * over by the time they are up, so the stream row is read again, then the
 * control row, in a slot turn. A connection deleted meanwhile purges and one
 * that moved defers, never "noop". Evidence is written only if the stream row
 * is still the one the plan matched; a head that moved leaves the runs pending
 * for the next cycle.
 */
async function confirmNoWork(
  deps: LocalSyncDeps,
  context: StreamContext,
  evidence: RunEvidence | null,
): Promise<"purged" | "deferred" | null> {
  // The row first, the control row second: see `confirmHints`.
  const read =
    evidence === null ? null : await deps.registry.read(context.scope);
  const checked = await checkControl(deps, context);
  if (checked) return checked;
  if (
    evidence === null ||
    read === null ||
    !read.found ||
    read.version !== evidence.version ||
    read.dataHash.toLowerCase() !== evidence.dataHash.toLowerCase()
  ) {
    return null;
  }
  await saveRunEvidence(deps, context.connectionId, context.stream, evidence);
  return null;
}

/** Whether two reads of a stream's row are the same row version and content. */
function sameRow(a: ControlRead, b: ControlRead): boolean {
  if (!a.found || !b.found) return a.found === b.found;
  return (
    a.version === b.version &&
    a.dataHash.toLowerCase() === b.dataHash.toLowerCase()
  );
}

/**
 * COMMIT, in the slot. The candidate stands only if what readBasis compares
 * is unchanged and the registry row is the one it was built over; the
 * registry CAS stays the remote fence.
 */
async function commitCandidate(
  deps: LocalSyncDeps,
  context: StreamContext,
  candidate: Candidate,
  prepared: Prepared,
  run: StreamRun,
): Promise<Committed> {
  const { connectionId, connection, stream, scope } = context;
  const { watermark } = candidate;
  const done = (result: PublishResult): Committed => ({ kind: "done", result });
  // Local state: what readBasis compares (control, stream state, head parts,
  // delete intents, selected runs, the covered change log, removals and
  // foreign writes above W) is the snapshot's. Later begins change none.
  if ((await readBasis(deps, context, candidate)) !== candidate.basis) {
    return { kind: "invalidated" };
  }
  // The registry row is not re-read here. A CAS follows (below) and is the
  // fence: a stale expectedVersion answers 409, the winner is applied, the
  // stream re-plans and is never marked published. The no-op path sends no
  // CAS and re-reads the row itself.
  const { dataHash: headHash, blobName } = prepared;
  const commit = (version: number, isNewVersion: boolean) =>
    commitBatch(deps, connectionId, stream, {
      version,
      generation: candidate.headGeneration,
      dataHash: headHash,
      blobName,
      recordCount: prepared.recordCount,
      observedAt: candidate.head.observedAt,
      complete: candidate.head.complete,
      parts: prepared.parts,
      watermark,
      lastDeleteVersion: candidate.head.lastDeleteVersion ?? 0,
      replaceBelow: candidate.replaceBelow,
      primaryKey: candidate.head.primaryKey,
      profile: candidate.head.profile,
      isNewVersion,
      runIds: candidate.runIds,
    });

  // Step 5: if the new head's data hash equals the registry head's, skip the
  // CAS and record the local state (watermark advances, the head is already
  // published).
  if (prepared.encryptedLength === null) {
    // No CAS follows, so this read is the only fence: the registry row is
    // still the one the candidate was built over.
    const read = await deps.registry.read(scope);
    const version = read.found ? read.version : 0;
    const dataHash = read.found ? read.dataHash.toLowerCase() : null;
    if (
      version !== candidate.registryVersion ||
      dataHash !== (candidate.registryDataHash?.toLowerCase() ?? null)
    ) {
      return { kind: "invalidated" };
    }
    const checked = await checkControl(deps, context);
    if (checked) return done({ stream, outcome: checked, watermark });
    await commit(candidate.registryVersion, false);
    return done({
      stream,
      outcome: candidate.sawRefusal ? "refused" : "noop",
      watermark,
      ...(watermark > candidate.localWatermark && {
        publication: {
          connectionId,
          connector: connection.connector,
          ns: connection.ns,
          stream,
          head: {
            version: candidate.registryVersion,
            generation: candidate.headGeneration,
            dataHash: headHash,
          },
          watermark,
          runIds: candidate.runIds,
        },
      }),
    });
  }

  const newVersion = candidate.registryVersion + 1;
  const metadataHash = metadataHashFor(
    scope,
    new Date(candidate.head.observedAt).toISOString(),
    prepared.encryptedLength,
  );
  const addRegisterMs = (ms: number) => (run.meter.headRegisterMs += ms);
  const signature = await timed(deps, addRegisterMs, () =>
    deps.signer.signAddData({
      ownerAddress: deps.ownerAddress,
      scope,
      dataHash: headHash,
      metadataHash,
      expectedVersion: BigInt(newVersion),
    }),
  );
  const beforePost = await checkControl(deps, context);
  if (beforePost) return done({ stream, outcome: beforePost, watermark });
  run.attempts++;
  const posted = await timed(deps, addRegisterMs, () =>
    deps.registry.post({
      ownerAddress: deps.ownerAddress,
      scope,
      dataHash: headHash,
      metadataHash,
      expectedVersion: String(newVersion),
      signature,
    }),
  );
  if (posted.kind === "conflict") {
    // Apply the winner and re-plan. On the last try, back off without
    // applying again: the winner will be applied on the next cycle.
    if (run.attempts === MAX_ATTEMPTS) {
      return done({ stream, outcome: "backoff", watermark });
    }
    await applyConnection(deps, connectionId);
    return { kind: "retry" };
  }

  const afterPost = await checkControl(deps, context);
  if (afterPost) return done({ stream, outcome: afterPost, watermark });
  await commit(newVersion, true);
  // The next snapshot of this stream meets this head at the registry. This
  // device built, verified and committed it, so it need not download it.
  if (prepared.verifiedHead) {
    rememberOwnHead(
      deps,
      scope,
      headHash,
      context.keyCheck,
      prepared.verifiedHead,
    );
  }
  return done({
    stream,
    outcome: "published",
    watermark,
    publication: {
      connectionId,
      connector: connection.connector,
      ns: connection.ns,
      stream,
      head: {
        version: newVersion,
        generation: candidate.headGeneration,
        dataHash: headHash,
      },
      watermark,
      runIds: candidate.runIds,
    },
  });
}

/**
 * The local state a candidate rests on, as one comparable key. It compares the
 * connection's control, the stream's head fields and parts, the connection's
 * delete intents, the selected runs, the changes at or below W, and what
 * happened above W that could make the frozen rows wrong (below). It is not
 * every input: stream floor and profile fields, and runs that ended after the
 * snapshot, are left out on purpose.
 *
 * A candidate survives a run that begins or ends after the snapshot and the
 * rows it upserts (origin `local` or `import`, sequence above W): they stay
 * queued above W, compaction never passes W, and a later publish carries them.
 * A removal above W is different: a remote head that still shows the row
 * would outlive the local delete. So every removal above W (a PDPP record
 * delete is origin `local`, `explicit_delete`) and every write of another
 * origin (a purge, a refresh) is in the key. Reads only; no transaction is
 * held.
 */
async function readBasis(
  deps: LocalSyncDeps,
  context: StreamContext,
  snapshot: {
    readonly watermark: number;
    readonly localWatermark: number;
    readonly runIds: readonly string[];
  },
): Promise<string> {
  const { connectionId, connection, stream } = context;
  const [connectionRow] = await deps.db.query(
    `SELECT generation, control_state, control_version FROM connections WHERE connection_id = ?`,
    [connectionId],
  );
  const [streamRow] = await deps.db.query(
    `SELECT head_version, head_generation, head_data_hash, head_blob,
            last_delete_version, publish_watermark
       FROM stream_state WHERE connection_id = ? AND stream = ?`,
    [connectionId, stream],
  );
  const headParts = await deps.db.query(
    `SELECT prefix, seq, part_hash, bytes, count FROM head_parts
      WHERE connection_id = ? AND stream = ? ORDER BY prefix, seq`,
    [connectionId, stream],
  );
  const intents = await deps.db.query(
    `SELECT delete_id, intent FROM delete_intents WHERE connector = ?`,
    [connection.connector],
  );
  const runs: unknown[] = [];
  for (const runId of snapshot.runIds) {
    runs.push(
      await deps.db.query(
        `SELECT r.run_id, r.state, r.generation, rs.decision, rs.replace,
                (SELECT COUNT(*) FROM run_rows rr
                  WHERE rr.run_id = r.run_id AND rr.stream = rs.stream) AS row_count
           FROM runs r JOIN run_streams rs ON rs.run_id = r.run_id
          WHERE r.run_id = ? AND rs.stream = ?`,
        [runId, stream],
      ),
    );
  }
  const covered = await deps.db.query(
    `SELECT COUNT(*) AS n, MAX(seq) AS newest FROM record_changes
      WHERE connection_id = ? AND stream = ? AND seq > ? AND seq <= ?`,
    [connectionId, stream, snapshot.localWatermark, snapshot.watermark],
  );
  const foreign = await deps.db.query(
    `SELECT COUNT(*) AS n FROM record_changes
      WHERE connection_id = ? AND stream = ? AND seq > ?
        AND (origin NOT IN ('local', 'import')
             OR op = 'remove' OR explicit_delete = 1)`,
    [connectionId, stream, snapshot.watermark],
  );
  return JSON.stringify([
    connectionRow ?? null,
    streamRow ?? null,
    headParts,
    intents,
    runs,
    covered,
    foreign,
  ]);
}

async function checkControl(
  deps: LocalSyncDeps,
  context: StreamContext,
): Promise<"purged" | "deferred" | null> {
  const { connectionId: id, connection, hashes } = context;
  if (
    (
      await deps.db.query("SELECT 1 FROM delete_intents WHERE connector=?", [
        connection.connector,
      ])
    ).length
  )
    return "deferred";
  const state = classifyControl(
    await deps.registry.read(controlScope(connection.connector, connection.ns)),
    hashes,
  );
  if (state.kind === "deleted") {
    await purgeConnection(deps, id, { controlVersion: state.version });
    context.latch.purged = true;
    return "purged";
  }
  if (state.kind !== "active" || state.generation !== connection.generation)
    return "deferred";
  return null;
}

/** The ended runs whose decision still awaits publication, oldest first. */
async function retainedRuns(
  deps: LocalSyncDeps,
  connectionId: string,
  stream: string,
): Promise<RetainedRun[]> {
  return deps.db.query<RetainedRun>(
    `SELECT r.run_id, r.o, r.generation, r.artifact_version,
            rs.primary_key, rs.profile_key, rs.profile_version,
            rs.full_read, rs.foreign_checkpoint, rs.seed, rs.decision,
            rs.replace, rs.basis_version, rs.basis_generation, rs.basis_data_hash,
            (SELECT COUNT(*) FROM run_rows rr
              WHERE rr.run_id = r.run_id AND rr.stream = rs.stream) AS row_count
       FROM runs r JOIN run_streams rs ON rs.run_id = r.run_id
      WHERE r.connection_id = ? AND rs.stream = ? AND r.state = 'ended'
        AND rs.decision IN ('publish', 'noop', 'deferred')
      ORDER BY r.o, r.run_id`,
    [connectionId, stream],
  );
}

/**
 * A run belongs to the connection lifetime it began in. A run that began
 * before the current control generation (it has no generation of its own, or
 * its begin basis is another control version) must never publish into the
 * current one: its rows may be rows another writer deleted. Such runs are
 * discarded with `lifetime_changed` and the connection recollects.
 *
 * Without this the "bind unbound runs" step of the snapshot hands a run that
 * ended before a delete+reconnect the NEW generation, and the next cycle
 * publishes the deleted rows back.
 */
export async function discardForeignLifetimeRuns(
  deps: LocalSyncDeps,
  connectionId: string,
  currentGeneration: number,
): Promise<boolean> {
  const runs = await deps.db.query<{
    run_id: string;
    o: number;
    stream: string;
    generation: number | null;
    begin_control_version: number | null;
  }>(
    `SELECT r.run_id, r.o, rs.stream, r.generation, r.begin_control_version
       FROM runs r JOIN run_streams rs ON rs.run_id = r.run_id
      WHERE r.connection_id = ? AND r.state = 'ended'
        AND rs.decision IN ('publish', 'noop', 'deferred')`,
    [connectionId],
  );
  const foreign = runs.filter(
    (run) =>
      (run.generation === null && currentGeneration > 1) ||
      (run.begin_control_version !== null &&
        run.begin_control_version > 0 &&
        run.begin_control_version !== currentGeneration),
  );
  if (foreign.length === 0) return false;
  const statements: SqlStatement[] = [];
  for (const run of foreign) {
    statements.push(
      {
        sql: "DELETE FROM records WHERE connection_id=? AND stream=? AND stamp_o=? AND stamp_r=?",
        params: [connectionId, run.stream, run.o, run.run_id],
      },
      {
        sql: "UPDATE run_streams SET decision='discarded',reason='lifetime_changed',replace=0,publication_state='superseded',publication_reason='lifetime_changed' WHERE run_id=? AND stream=?",
        params: [run.run_id, run.stream],
      },
      {
        sql: "DELETE FROM run_rows WHERE run_id=? AND stream=?",
        params: [run.run_id, run.stream],
      },
    );
  }
  for (const stream of new Set(foreign.map((run) => run.stream))) {
    statements.push({
      sql: "DELETE FROM head_parts WHERE connection_id=? AND stream=?",
      params: [connectionId, stream],
    });
  }
  // The discarded rows were collected against a lifetime that ended: the next
  // run collects in full instead of resuming from their checkpoint.
  statements.push({
    sql: "UPDATE connections SET checkpoint = NULL WHERE connection_id = ?",
    params: [connectionId],
  });
  await deps.db.batch(withOrigin("purge", statements));
  return true;
}

async function discardFencedRuns(
  deps: LocalSyncDeps,
  id: string,
  stream: string,
): Promise<boolean> {
  const runs = await deps.db.query<{ run_id: string; o: number }>(
    `SELECT r.run_id,r.o FROM runs r JOIN run_streams rs ON rs.run_id=r.run_id
    WHERE r.connection_id=? AND rs.stream=? AND r.state='ended' AND rs.decision IN ('publish','noop','deferred')`,
    [id, stream],
  );
  const statements: SqlStatement[] = [];
  for (const run of runs) {
    const trip = (await checkRunFence(deps, run.run_id, "publish")).find(
      (t) => t.stream === stream,
    );
    if (!trip) continue;
    statements.push(
      {
        sql: "DELETE FROM records WHERE connection_id=? AND stream=? AND stamp_o=? AND stamp_r=?",
        params: [id, stream, run.o, run.run_id],
      },
      {
        sql: "UPDATE run_streams SET decision='discarded',reason=?,replace=0,publication_state='superseded',publication_reason=? WHERE run_id=? AND stream=?",
        params: [trip.trip, trip.trip, run.run_id, stream],
      },
      {
        sql: "DELETE FROM run_rows WHERE run_id=? AND stream=?",
        params: [run.run_id, stream],
      },
    );
  }
  if (statements.length === 0) return false;
  statements.push({
    sql: "DELETE FROM head_parts WHERE connection_id=? AND stream=?",
    params: [id, stream],
  });
  await deps.db.batch(withOrigin("purge", statements));
  return true;
}

async function readRegistryHead(
  deps: LocalSyncDeps,
  scope: string,
  dataHash: string,
  connection: ConnectionRow,
  stream: string,
  keyCheck: string,
): Promise<Head> {
  const remembered = recallHead(deps, scope, dataHash, keyCheck);
  if (remembered) return remembered;
  const blobName = headBlobName(dataHash);
  const cipher = await deps.blobs.get(`${scope}/${blobName}`);
  if (cipher === null) {
    throw new Error(
      `publish: registry head blob ${blobName} is missing for ${stream}`,
    );
  }
  const clear = await deps.keys.decrypt(scope, cipher);
  const verified = await verifyHead(keccak, clear, {
    dataHash,
    connector: connection.connector,
    ns: connection.ns,
    stream,
    keyCheck,
  });
  if (verified.kind !== "ok") {
    throw new Error(
      `publish: registry head for ${stream} failed verification: ${verified.kind}`,
    );
  }
  rememberHead(deps, scope, dataHash, keyCheck, verified.head);
  return verified.head;
}

type StreamPlan = {
  readonly steps: readonly { runId: string; decision: StepDecision }[];
  readonly finalHead: PlanHead | null;
  readonly deferred: boolean;
  readonly refused: {
    runId: string;
    reason: "connector_update_required" | "out_of_order";
  } | null;
  readonly replaceBelow: { o: number; r: string } | undefined;
  readonly newestRunObservedAt: number | null;
};

async function planStream(
  deps: LocalSyncDeps,
  connectionId: string,
  connection: ConnectionRow,
  stream: string,
  local: LocalStream,
  registryHead: Head | null,
  registryVersion: number,
  registryDataHash: string | null,
): Promise<StreamPlan> {
  const runs = await retainedRuns(deps, connectionId, stream);

  const newest = runs.length > 0 ? runs[runs.length - 1] : undefined;
  const baseHead: PlanHead | null = registryHead
    ? {
        generation: registryHead.generation,
        primaryKey: registryHead.primaryKey,
        profile: registryHead.profile,
        complete: registryHead.complete,
      }
    : local.head_version > 0 || local.floor_o !== null
      ? {
          generation:
            local.head_generation ??
            newest?.generation ??
            connection.generation,
          primaryKey: JSON.parse(local.primary_key),
          profile: {
            key: local.profile_key ?? connection.connector,
            version:
              local.profile_version ??
              local.floor_version ??
              newest?.artifact_version ??
              "0",
          },
          complete: local.complete === 1,
        }
      : null;

  // The floor at publish carries the version floor but no committed stamp:
  // commit order was enforced at end (a late run was refused there and
  // never entered the retained set), so the retained runs are already
  // accepted and ordered.
  let state = {
    head: baseHead,
    floor: { version: local.floor_version, committed: null },
  };
  const steps: { runId: string; decision: StepDecision }[] = [];
  let replaceBelow: { o: number; r: string } | undefined;
  for (const run of runs) {
    const planRun: PlanRun = {
      runId: run.run_id,
      observedAt: run.o,
      generation: run.generation,
      primaryKey: JSON.parse(
        run.primary_key ?? local.primary_key,
      ) as readonly string[],
      profile: {
        key: run.profile_key ?? connection.connector,
        version: run.profile_version ?? run.artifact_version,
      },
      full: run.full_read === 1,
      foreignCheckpoint: run.foreign_checkpoint === 1,
      empty: run.row_count === 0,
      seed: run.seed,
    };
    const decision = planStreamStep(state, planRun);
    if (decision.kind === "refused") {
      return {
        steps,
        finalHead: state.head,
        deferred: false,
        refused: { runId: run.run_id, reason: decision.reason },
        replaceBelow: undefined,
        newestRunObservedAt: newest?.o ?? null,
      };
    }
    if (decision.kind === "deferred") {
      return {
        steps,
        finalHead: state.head,
        deferred: true,
        refused: null,
        replaceBelow: undefined,
        newestRunObservedAt: newest?.o ?? null,
      };
    }
    steps.push({ runId: run.run_id, decision });
    if (decision.kind === "publish" && decision.replacesBase)
      replaceBelow = { o: run.o, r: run.run_id };
    state = {
      head: decision.head,
      floor: { version: decision.floor, committed: null },
    };
  }

  // Replace (H): the newest retained replacing run whose basis matches the
  // registry head's identity. The basis was recorded at begin and is never
  // refreshed; a predicted head has no identity, so replace defers.
  for (let i = runs.length - 1; i >= 0; i--) {
    const run = runs[i];
    if (run.replace !== 1) continue;
    const applies = replaceMayApply(
      {
        basisVersion: run.basis_version,
        basisDataHash: run.basis_data_hash,
        basisKnown: run.basis_generation !== null,
      },
      registryDataHash === null
        ? null
        : { version: registryVersion, dataHash: registryDataHash },
    );
    if (
      applies &&
      (!replaceBelow ||
        run.o > replaceBelow.o ||
        (run.o === replaceBelow.o && run.run_id > replaceBelow.r))
    ) {
      replaceBelow = { o: run.o, r: run.run_id };
      break;
    }
  }

  return {
    steps,
    finalHead: state.head,
    deferred: false,
    refused: null,
    replaceBelow,
    newestRunObservedAt: newest?.o ?? null,
  };
}

/** Purge seed rows for a stream whose head generation is not 1. */
async function excludeSeedsIfAny(
  deps: LocalSyncDeps,
  connectionId: string,
  stream: string,
): Promise<void> {
  const [row] = await deps.db.query<{ n: number }>(
    `SELECT COUNT(*) AS n FROM records
      WHERE connection_id = ? AND stream = ? AND stamp_o = 0 AND stamp_r = 'seed'`,
    [connectionId, stream],
  );
  if ((row?.n ?? 0) === 0) return;
  await deps.db.batch(
    withOrigin("purge", [
      {
        sql: `DELETE FROM records
               WHERE connection_id = ? AND stream = ? AND stamp_o = 0 AND stamp_r = 'seed'`,
        params: [connectionId, stream],
      },
      {
        sql: `UPDATE run_streams SET seed='none' WHERE stream=? AND seed='merged'
          AND run_id IN (SELECT run_id FROM runs WHERE connection_id=?)`,
        params: [stream, connectionId],
      },
      {
        sql: `UPDATE import_ledger SET state = 'excluded', reason = 'seed_skipped', at = ?
               WHERE connection_id = ? AND stream = ? AND state = 'imported'`,
        params: [deps.now(), connectionId, stream],
      },
    ]),
  );
}

/**
 * The new head's parts: the base head's parts for prefixes not re-encoded,
 * the freshly encoded parts for the changed prefixes, grouped by prefix
 * and ordered by prefix.
 */
function mergedParts(
  baseParts: readonly HeadPart[],
  encoded: readonly EncodedPart[],
  changedPrefixes: readonly string[],
): HeadPart[] {
  const changed = [...changedPrefixes];
  const groups = new Map<string, HeadPart[]>();
  const push = (prefix: string, part: HeadPart) => {
    const group = groups.get(prefix);
    if (group) group.push(part);
    else groups.set(prefix, [part]);
  };
  for (const part of baseParts) {
    // A base part goes when it overlaps a changed prefix (see
    // `selectChangedBuckets`: then every prefix it overlaps is changed).
    if (
      !changed.some(
        (prefix) =>
          prefix.startsWith(part.prefix) || part.prefix.startsWith(prefix),
      )
    ) {
      push(part.prefix, part);
    }
  }
  for (const part of encoded) {
    push(part.prefix, {
      prefix: part.prefix,
      bytes: part.bytes,
      count: part.count,
      hash: part.partHash,
    });
  }
  return [...groups.keys()].sort().flatMap((prefix) => groups.get(prefix)!);
}

type CommitInput = {
  version: number;
  generation: number;
  dataHash: `0x${string}`;
  blobName: string;
  recordCount: number;
  observedAt: number;
  complete: boolean;
  parts: readonly HeadPart[];
  watermark: number | null;
  lastDeleteVersion: number;
  replaceBelow: { o: number; r: string } | undefined;
  primaryKey: readonly string[];
  profile: Head["profile"];
  isNewVersion: boolean;
  /** The plan's accepted runs for this stream: the runs this publication covers. */
  runIds: readonly string[];
};

/** What a publication confirmed, and the runs it covered. */
type RunEvidence = Pick<
  CommitInput,
  | "version"
  | "generation"
  | "dataHash"
  | "watermark"
  | "replaceBelow"
  | "runIds"
>;

const RUN_ID_CHUNK = 400;

/**
 * Durable run-to-publication evidence, written in the same batch as the head.
 * Only runs still `pending` move to `published`, so a later publication never
 * rewrites older evidence and runs from before this column stay `unknown`.
 * The ids are the plan's: a run that ended after planning is not covered.
 * The watermark is stored as evidence only; it is a local change sequence and
 * is never compared with a run's `o`.
 */
async function runPublicationStatements(
  deps: LocalSyncDeps,
  connectionId: string,
  stream: string,
  input: RunEvidence,
): Promise<SqlStatement[]> {
  const planned = new Set(input.runIds);
  const pending = (
    await deps.db.query<{ run_id: string }>(
      `SELECT rs.run_id FROM run_streams rs JOIN runs r ON r.run_id = rs.run_id
        WHERE r.connection_id = ? AND rs.stream = ? AND rs.publication_state = 'pending'`,
      [connectionId, stream],
    )
  )
    .map((row) => row.run_id)
    .filter((runId) => planned.has(runId));
  const statements: SqlStatement[] = [];
  for (let i = 0; i < pending.length; i += RUN_ID_CHUNK) {
    const chunk = pending.slice(i, i + RUN_ID_CHUNK);
    statements.push({
      sql: `UPDATE run_streams SET publication_state = 'published',
              published_generation = ?, published_version = ?, published_data_hash = ?,
              published_watermark = ?, publication_reason = NULL
            WHERE stream = ? AND publication_state = 'pending'
              AND run_id IN (${chunk.map(() => "?").join(",")})`,
      params: [
        input.generation,
        input.version,
        input.dataHash,
        input.watermark ?? 0,
        stream,
        ...chunk,
      ],
    });
  }
  if (input.replaceBelow) {
    // The replacement dropped older rows: older runs were saved, then replaced.
    const { o, r } = input.replaceBelow;
    statements.push({
      sql: `UPDATE run_streams SET publication_state = 'superseded', publication_reason = ?
            WHERE stream = ? AND publication_state = 'published'
              AND run_id IN (SELECT run_id FROM runs
                              WHERE connection_id = ? AND (o < ? OR (o = ? AND run_id < ?)))`,
      params: [`replaced_by:${r}`, stream, connectionId, o, o, r],
    });
  }
  return statements;
}

/**
 * The one batch after a successful CAS (or a skipped CAS): replace deletes
 * (origin refresh), head identity, publish_watermark = W, head_parts, a
 * stream_versions row for a new version, and compaction of record_changes
 * at or below the connection's lowest watermark — skipped entirely while
 * an import read-back is pending (an imported ledger row for the
 * connection).
 */
async function commitBatch(
  deps: LocalSyncDeps,
  connectionId: string,
  stream: string,
  input: CommitInput,
): Promise<void> {
  const statements: SqlStatement[] = [];
  if (input.replaceBelow) {
    statements.push(
      replaceDelete(
        connectionId,
        stream,
        input.replaceBelow.o,
        input.replaceBelow.r,
      ),
    );
  }
  statements.push({
    sql: `UPDATE stream_state SET head_version = ?, head_generation = ?,
            head_data_hash = ?, head_blob = ?, publish_watermark = ?,
            last_delete_version = ?, primary_key = ?, profile_key = ?, profile_version = ?, complete = ?,
            needs_full = CASE WHEN ? = 1 THEN 0 WHEN ? > 0 THEN 1 ELSE needs_full END
          WHERE connection_id = ? AND stream = ?`,
    params: [
      input.version,
      input.generation,
      input.dataHash,
      input.blobName,
      input.watermark ?? 0,
      input.lastDeleteVersion,
      JSON.stringify(input.primaryKey),
      input.profile.key,
      input.profile.version,
      input.complete ? 1 : 0,
      input.complete ? 1 : 0,
      input.lastDeleteVersion,
      connectionId,
      stream,
    ],
  });
  statements.push(
    ...(await runPublicationStatements(deps, connectionId, stream, input)),
  );
  statements.push({
    sql: `DELETE FROM head_parts WHERE connection_id = ? AND stream = ?`,
    params: [connectionId, stream],
  });
  const seqByPrefix = new Map<string, number>();
  for (const part of input.parts) {
    const seq = seqByPrefix.get(part.prefix) ?? 0;
    seqByPrefix.set(part.prefix, seq + 1);
    statements.push({
      sql: `INSERT INTO head_parts (connection_id, stream, prefix, seq, part_hash, bytes, count)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
      params: [
        connectionId,
        stream,
        part.prefix,
        seq,
        part.hash,
        part.bytes,
        part.count,
      ],
    });
  }
  if (input.isNewVersion) {
    statements.push({
      sql: `INSERT INTO stream_versions (connection_id, stream, version, generation,
              head_blob, head_format, record_count, observed_at, complete, kind)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'published')`,
      params: [
        connectionId,
        stream,
        input.version,
        input.generation,
        input.blobName,
        HEAD_FORMAT,
        input.recordCount,
        input.observedAt,
        input.complete ? 1 : 0,
      ],
    });
  }
  const [pendingImport] = await deps.db.query<{ n: number }>(
    `SELECT COUNT(*) AS n FROM import_ledger
      WHERE connection_id = ? AND state = 'imported'`,
    [connectionId],
  );
  if ((pendingImport?.n ?? 0) === 0) {
    // The connection's lowest watermark after this stream's update: the
    // new watermark for this stream, the current watermark of the others.
    const [others] = await deps.db.query<{ m: number | null }>(
      `SELECT MIN(publish_watermark) AS m FROM stream_state
        WHERE connection_id = ? AND stream != ?`,
      [connectionId, stream],
    );
    const lowest = Math.min(
      input.watermark ?? 0,
      others?.m ?? Number.POSITIVE_INFINITY,
    );
    statements.push({
      sql: `DELETE FROM record_changes WHERE connection_id = ? AND seq <= ?`,
      params: [connectionId, lowest],
    });
  }
  await deps.db.batch(withOrigin("refresh", statements));
}
