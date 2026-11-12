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
//      Freeze what the next phase needs: for each changed prefix a count and
//      a digest of its rows' identities (never the bodies; under replace,
//      leaving out rows below the run's stamp), the attachments to upload,
//      and the basis the snapshot rests on (control, stream state, head
//      parts, delete intents, retained runs, W, and what readBasis lists).
//   TRANSFER (no slot)  4. Read the changed prefixes page by page, encode,
//      upload every new part and attachment, build the head and upload it.
//      Objects are content addressed and authorize nothing until the registry
//      CAS, so they need no mutual exclusion. Each page is a plain read (no
//      slot, no transaction across a network await), so memory is a page and
//      the part in progress. A prefix whose rows no longer match the frozen
//      digest discards the candidate before its head exists. Attachment
//      bytes are read by exact id and checked against it.
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
  freezePrefixRows,
  uploadFrozenParts,
  type EncodedPart,
  type FrozenPrefix,
  type HeadExtras,
} from "./encode.js";
import { replaceDelete, withOrigin } from "./merge.js";
import { purgeConnection } from "./purge.js";
import { checkRunFence } from "./fence.js";
import { replaceMayApply } from "./replace.js";
import { insideQueue } from "./slot.js";
import { unwriteRefusedRun } from "./unwrite.js";

/**
 * Verified registry heads by (scope, data hash). A head blob is named by its
 * data hash and never changes, so a head verified once need not be downloaded
 * again. Without this every cycle downloaded one head blob per stream of every
 * connection, quiet or not; the storage service rejects a burst of reads, and
 * a cycle that has real work to publish then fails before it posts anything.
 */
const verifiedHeads = new WeakMap<object, Map<string, Head>>();
const MAX_VERIFIED_HEADS = 512;

function headCache(deps: LocalSyncDeps): Map<string, Head> {
  let cache = verifiedHeads.get(deps.blobs);
  if (!cache) {
    cache = new Map();
    verifiedHeads.set(deps.blobs, cache);
  }
  return cache;
}

function rememberHead(
  deps: LocalSyncDeps,
  scope: string,
  dataHash: string,
  keyCheck: string,
  head: Head,
): void {
  const cache = headCache(deps);
  const key = `${scope}|${dataHash.toLowerCase()}|${keyCheck}`;
  cache.delete(key);
  cache.set(key, head);
  if (cache.size > MAX_VERIFIED_HEADS) {
    cache.delete(cache.keys().next().value!);
  }
}

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
  const results: PublishResult[] = [];
  for (const { stream } of streams) {
    const result = await publishStream(
      deps,
      connectionId,
      connection,
      stream,
      keyCheck,
      hashes,
      options,
    );
    results.push(result);
    // A deleted control row purges the whole connection and stops.
    if (result.outcome === "purged") break;
  }
  return results;
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
 * Re-snapshots allowed after a candidate was discarded (changed basis or
 * changed rows) before the work waits for the next cycle. A cycle builds at
 * most MAX_INVALIDATIONS + 1 candidates for a stream.
 */
const MAX_INVALIDATIONS = 3;

/** What one stream's publish carries from one loop pass to the next. */
type StreamRun = {
  sawRefusal: boolean;
  appliedVersion: number | null;
  attempts: number;
  invalidations: number;
  watermark: number | null;
};

type StreamContext = {
  readonly connectionId: string;
  readonly connection: ConnectionRow;
  readonly stream: string;
  readonly scope: string;
  readonly keyCheck: string;
  readonly hashes: ControlHashes;
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
  options: PublishOptions | undefined,
): Promise<PublishResult> {
  const context: StreamContext = {
    connectionId,
    connection,
    stream,
    scope: streamScope(connection.connector, connection.ns, stream),
    keyCheck,
    hashes,
    options,
  };
  const run: StreamRun = {
    sawRefusal: false,
    appliedVersion: null,
    attempts: 0,
    invalidations: 0,
    watermark: null,
  };
  const slot = <T>(work: (held: LocalSyncDeps) => Promise<T>) =>
    deps.queue.run(connectionId, "publish", () =>
      work(insideQueue(deps, connectionId)),
    );
  while (run.attempts < MAX_ATTEMPTS) {
    if (run.invalidations > MAX_INVALIDATIONS) {
      // Local state kept moving under every candidate. Nothing was published
      // and nothing was acknowledged: the work is still pending next cycle.
      return { stream, outcome: "backoff", watermark: run.watermark };
    }
    const snapshot = await slot((held) => snapshotStream(held, context, run));
    if (snapshot.kind === "done") return snapshot.result;
    if (snapshot.kind === "retry") continue;
    if (snapshot.kind === "blobs") {
      await uploadBlobs(deps, snapshot.blobs);
      const { evidence } = snapshot;
      if (evidence) {
        await slot((held) => confirmNoWork(held, context, evidence));
      }
      return snapshot.result;
    }
    const { candidate } = snapshot;
    let prepared: Prepared;
    try {
      prepared = await transferCandidate(deps, context, candidate);
    } catch (error) {
      // A transfer that lost its input because local state moved (rows that
      // changed, a delete that purged an attachment) is a stale candidate,
      // not a failure.
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
  const deferred = (): Snapshot =>
    done({ stream, outcome: "deferred", watermark: run.watermark });

  // Step 1: snapshot W and the changes since the last publish.
  const [local] = await deps.db.query<LocalStream>(
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
  let controlRead = await deps.registry.read(control);
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
    await applyConnection(deps, connectionId);
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
    await applyConnection(deps, connectionId);
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

  const streamRead = await deps.registry.read(scope);
  const streamRow = classifyStreamRow(streamRead, hashes);
  let registryHead: Head | null = null;
  let registryVersion = 0;
  let registryDataHash: string | null = null;
  if (streamRead.found) {
    registryVersion = streamRead.version;
    registryDataHash = streamRead.dataHash;
  }
  if (streamRow === "present" && streamRead.found) {
    registryHead = await readRegistryHead(
      deps,
      scope,
      streamRead.dataHash,
      connection,
      stream,
      keyCheck,
    );
  }

  if (registryHead && registryHead.generation !== connection.generation)
    return deferred();

  // A registry row newer than the local head is applied (same slot turn)
  // and the stream restarts at step 1. Apply once per version: if the head
  // still lags after apply, proceed with the registry head.
  if (streamRead.found && registryVersion > local.head_version) {
    if (run.appliedVersion !== registryVersion) {
      await applyConnection(deps, connectionId);
      run.appliedVersion = registryVersion;
      return { kind: "retry" };
    }
  }

  if (await discardFencedRuns(deps, connectionId, stream)) {
    await applyConnection(deps, connectionId);
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
    registryDataHash,
  );
  if (plan.deferred) return deferred();
  if (plan.refused) {
    run.sawRefusal = true;
    await unwriteRefusedRun(deps, {
      connectionId,
      stream,
      runId: plan.refused.runId,
      reason: plan.refused.reason,
    });
    await applyConnection(deps, connectionId);
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

  // Step 4 input: the changed prefixes. The head's partition is respected:
  // a changed record re-encodes the base prefix holding it, or its own
  // 16-bit prefix when no base prefix covers it.
  let changedPrefixes = changedPrefixesFor(
    changes,
    registryHead?.parts ?? null,
  );
  if (
    registryHead &&
    (registryHead.format !== HEAD_FORMAT || plan.replaceBelow)
  ) {
    changedPrefixes = [
      ...new Set([
        ...changedPrefixes,
        ...registryHead.parts.map((p) => p.prefix),
      ]),
    ].sort();
  }
  // Read the caller's head extras, the rows to encode and the clock now: the
  // transfer reads none of them again.
  await context.options?.headExtras?.(stream);
  const frozen =
    changedPrefixes.length === 0
      ? []
      : await freezePrefixRows(deps, {
          connectionId,
          stream,
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
 * TRANSFER, outside the slot. Attachments, parts, then the head, each a
 * content-addressed object. It reads the changed prefixes' rows (page by page,
 * checked against the frozen digest) and attachment bytes by exact id, so it
 * cannot encode rows the snapshot did not freeze: a difference throws
 * FrozenRowsChanged.
 */
async function transferCandidate(
  deps: LocalSyncDeps,
  context: StreamContext,
  candidate: Candidate,
): Promise<Prepared> {
  const { scope } = context;
  await uploadBlobs(deps, candidate.blobs);
  const encoded = await uploadFrozenParts(deps, {
    connectionId: context.connectionId,
    stream: context.stream,
    replaceBelow: candidate.replaceBelow,
    scope,
    generation: candidate.headGeneration,
    frozen: candidate.frozen,
  });
  const parts = mergedParts(
    candidate.baseParts,
    encoded,
    candidate.changedPrefixes,
  );
  const recordCount = parts.reduce((sum, part) => sum + part.count, 0);
  const headBytes = encodeHead({ ...candidate.head, parts, recordCount });
  const { dataHash, blobName } = await digestHead(keccak, headBytes);
  // The same data hash as the registry head: nothing to upload or post.
  if (
    candidate.registryDataHash !== null &&
    dataHash.toLowerCase() === candidate.registryDataHash.toLowerCase()
  ) {
    return { parts, recordCount, dataHash, blobName, encryptedLength: null };
  }
  const encrypted = await deps.keys.encrypt(scope, headBytes);
  if ((await deps.blobs.get(`${scope}/${blobName}`)) === null) {
    await deps.blobs.put(`${scope}/${blobName}`, encrypted);
  }
  return {
    parts,
    recordCount,
    dataHash,
    blobName,
    encryptedLength: encrypted.length,
  };
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
 * over by the time they are up, so the registry row is read again, in a slot
 * turn. Evidence is written only if it is still the row the plan matched; a
 * head that moved leaves the runs pending for the next cycle.
 */
async function confirmNoWork(
  deps: LocalSyncDeps,
  context: StreamContext,
  evidence: RunEvidence,
): Promise<void> {
  const read = await deps.registry.read(context.scope);
  if (
    !read.found ||
    read.version !== evidence.version ||
    read.dataHash.toLowerCase() !== evidence.dataHash.toLowerCase()
  ) {
    return;
  }
  await saveRunEvidence(deps, context.connectionId, context.stream, evidence);
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
  const { connectionId, connection, stream, scope, hashes } = context;
  const { watermark } = candidate;
  const done = (result: PublishResult): Committed => ({ kind: "done", result });
  // Local state: what readBasis compares (control, stream state, head parts,
  // delete intents, selected runs, the covered change log, removals and
  // foreign writes above W) is the snapshot's. Later begins change none.
  if ((await readBasis(deps, context, candidate)) !== candidate.basis) {
    return { kind: "invalidated" };
  }
  // Registry: the stream row is the one the candidate was built over.
  const read = await deps.registry.read(scope);
  const version = read.found ? read.version : 0;
  const dataHash = read.found ? read.dataHash.toLowerCase() : null;
  if (
    version !== candidate.registryVersion ||
    dataHash !== (candidate.registryDataHash?.toLowerCase() ?? null)
  ) {
    return { kind: "invalidated" };
  }
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
    const checked = await checkControl(deps, connectionId, connection, hashes);
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
  const signature = await deps.signer.signAddData({
    ownerAddress: deps.ownerAddress,
    scope,
    dataHash: headHash,
    metadataHash,
    expectedVersion: BigInt(newVersion),
  });
  const beforePost = await checkControl(deps, connectionId, connection, hashes);
  if (beforePost) return done({ stream, outcome: beforePost, watermark });
  run.attempts++;
  const posted = await deps.registry.post({
    ownerAddress: deps.ownerAddress,
    scope,
    dataHash: headHash,
    metadataHash,
    expectedVersion: String(newVersion),
    signature,
  });
  if (posted.kind === "conflict") {
    // Apply the winner and re-plan. On the last try, back off without
    // applying again: the winner will be applied on the next cycle.
    if (run.attempts === MAX_ATTEMPTS) {
      return done({ stream, outcome: "backoff", watermark });
    }
    await applyConnection(deps, connectionId);
    return { kind: "retry" };
  }

  const afterPost = await checkControl(deps, connectionId, connection, hashes);
  if (afterPost) return done({ stream, outcome: afterPost, watermark });
  await commit(newVersion, true);
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
  id: string,
  connection: ConnectionRow,
  hashes: ControlHashes,
): Promise<"purged" | "deferred" | null> {
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
  const remembered = headCache(deps).get(
    `${scope}|${dataHash.toLowerCase()}|${keyCheck}`,
  );
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

/** The first `bits` bits of a hex string, as a bit string. */
function prefixBits(hex: string, bits: number): string {
  if (bits === 0) return "";
  const needed = Math.ceil(bits / 4);
  const value = BigInt(`0x${hex.slice(0, needed)}`);
  return value
    .toString(2)
    .padStart(needed * 4, "0")
    .slice(0, bits);
}

function covers(prefix: string, pkHash: string): boolean {
  return prefixBits(pkHash, prefix.length) === prefix;
}

/**
 * The prefixes to encode for the changed records, aligned to the base
 * head's partition: a changed record re-encodes the base prefix holding
 * it, or its own 16-bit prefix when no base prefix covers it. With no
 * base head, every changed record's own 16-bit prefix.
 */
function changedPrefixesFor(
  changes: readonly ChangeRow[],
  baseParts: readonly HeadPart[] | null,
): string[] {
  const prefixes = new Set<string>();
  const basePrefixes = baseParts?.map((part) => part.prefix) ?? [];
  for (const { pk_hash } of changes) {
    const holding = basePrefixes.find((prefix) => covers(prefix, pk_hash));
    prefixes.add(holding ?? prefixBits(pk_hash, 16));
  }
  return [...prefixes].sort();
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
  const changed = new Set(changedPrefixes);
  const groups = new Map<string, HeadPart[]>();
  const push = (prefix: string, part: HeadPart) => {
    const group = groups.get(prefix);
    if (group) group.push(part);
    else groups.set(prefix, [part]);
  };
  for (const part of baseParts) {
    if (!changed.has(part.prefix)) push(part.prefix, part);
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
