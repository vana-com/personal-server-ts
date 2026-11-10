import { uploadStreamBlobs } from "./blobs.js";
// PS-2 P09 publish: the publish side of local sync.
//
// Per connection, in the connection queue (held by the caller, cycle.ts),
// after apply. Per stream with work:
//   1. Snapshot W = max(seq) in record_changes and the changes with
//      seq > publish_watermark and seq <= W.
//   2. Registry: a newer registry head is applied (same queue turn) and
//      the stream restarts at step 1; a deleted control row purges the
//      connection and stops.
//   3. Re-plan the retained ended runs against the registry head. A run
//      accepted at end but now refused is un-written in one batch and
//      apply runs at once; a deferred run defers the stream.
//   4. Encode the changed prefixes (the head's partition is respected:
//      a changed record re-encodes the base prefix that holds it, or its
//      own 16-bit prefix when no base prefix covers it), under replace
//      leaving out rows below the run's stamp.
//   5. Head, then registry CAS from head_version: the same data hash
//      skips the CAS; a conflict applies the winner and re-plans, at most
//      5 tries, then back off. On success one batch: replace deletes
//      (origin refresh), head identity, publish_watermark = W, head_parts,
//      stream_versions, compaction of record_changes at or below the
//      connection's lowest watermark (kept while an import read-back is
//      pending).
//
// Seeds (import rows with stamp (0, "seed")) publish only into generation
// 1; otherwise they are purged and the ledger records excluded(seed_skipped).
//
// This module does not take the connection queue: the caller holds one
// "publish" queue turn for the connection. applyConnection and
// purgeConnection take the queue with the deps they receive.

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
import { encodePrefixes, type EncodedPart, type HeadExtras } from "./encode.js";
import { replaceDelete, withOrigin } from "./merge.js";
import { purgeConnection } from "./purge.js";
import { checkRunFence } from "./fence.js";
import { replaceMayApply } from "./replace.js";
import { unwriteRefusedRun } from "./unwrite.js";

export interface PublishResult {
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

export async function publishConnection(
  deps: LocalSyncDeps,
  connectionId: string,
  options?: {
    readonly headExtras?: (stream: string) => Promise<HeadExtras | undefined>;
  },
): Promise<readonly PublishResult[]> {
  const [connection] = await deps.db.query<{
    connector: string;
    ns: string;
    generation: number;
  }>(
    `SELECT connector, ns, generation FROM connections WHERE connection_id = ?`,
    [connectionId],
  );
  if (!connection) {
    throw new Error(`publish: unknown connection ${connectionId}`);
  }
  const keyCheck = await deriveKeyCheck(deps.keys.namespaceHmac);
  const hashes = await controlHashes(keccak, keyCheck);
  const streams = await deps.db.query<{ stream: string }>(
    `SELECT stream FROM stream_state WHERE connection_id = ? ORDER BY stream`,
    [connectionId],
  );
  if (
    (
      await deps.db.query("SELECT 1 FROM delete_intents WHERE connector=?", [
        connection.connector,
      ])
    ).length
  )
    return streams.map(({ stream }) => ({
      stream,
      outcome: "deferred",
      watermark: null,
    }));
  if (streams.length === 0) {
    const state = classifyControl(
      await deps.registry.read(
        controlScope(connection.connector, connection.ns),
      ),
      hashes,
    );
    if (state.kind === "deleted")
      await purgeConnection(deps, connectionId, {
        controlVersion: state.version,
      });
  }
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

async function publishStream(
  deps: LocalSyncDeps,
  connectionId: string,
  connection: ConnectionRow,
  stream: string,
  keyCheck: string,
  hashes: ControlHashes,
  options:
    | {
        readonly headExtras?: (
          stream: string,
        ) => Promise<HeadExtras | undefined>;
      }
    | undefined,
): Promise<PublishResult> {
  const scope = streamScope(connection.connector, connection.ns, stream);
  const control = controlScope(connection.connector, connection.ns);
  let sawRefusal = false;
  let appliedVersion: number | null = null;
  let watermark: number | null = null;

  let attempts = 0;
  while (attempts < MAX_ATTEMPTS) {
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
    watermark = wRow?.w ?? local.publish_watermark;
    const changes: ChangeRow[] =
      watermark === null
        ? []
        : await deps.db.query<ChangeRow>(
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
      if (connection.generation !== 1)
        return { stream, outcome: "deferred", watermark };
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
      return { stream, outcome: "purged", watermark };
    }
    if (controlState.kind === "foreign" || controlState.kind === "absent") {
      deps.logger.warn(
        {},
        "publish: control unavailable for publishing; deferring stream",
      );
      return { stream, outcome: "deferred", watermark };
    }
    if (controlState.generation !== connection.generation) {
      await applyConnection(deps, connectionId);
      return { stream, outcome: "deferred", watermark };
    }
    await deps.db.batch([
      {
        sql: "UPDATE connections SET control_state='active',control_version=? WHERE connection_id=?",
        params: [controlState.generation, connectionId],
      },
      // C.0: an offline fresh run binds when the registry first answers.
      {
        sql: "UPDATE runs SET generation=? WHERE connection_id=? AND generation IS NULL",
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
      return { stream, outcome: "deferred", watermark };

    // A registry row newer than the local head is applied (same queue
    // turn) and the stream restarts at step 1. Apply once per version:
    // if the head still lags after apply, proceed with the registry head.
    if (streamRead.found && registryVersion > local.head_version) {
      if (appliedVersion !== registryVersion) {
        await applyConnection(deps, connectionId);
        appliedVersion = registryVersion;
        continue;
      }
    }

    if (await discardFencedRuns(deps, connectionId, stream)) {
      await applyConnection(deps, connectionId);
      continue;
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
    if (plan.deferred) {
      return { stream, outcome: "deferred", watermark };
    }
    if (plan.refused) {
      sawRefusal = true;
      await unwriteRefusedRun(deps, {
        connectionId,
        stream,
        runId: plan.refused.runId,
        reason: plan.refused.reason,
      });
      await applyConnection(deps, connectionId);
      continue;
    }

    const hasWork =
      changes.length > 0 ||
      plan.replaceBelow !== undefined ||
      plan.steps.some((step) => step.decision.kind === "publish");
    if (!hasWork) {
      return { stream, outcome: sawRefusal ? "refused" : "noop", watermark };
    }

    const headGeneration = plan.finalHead?.generation ?? connection.generation;
    // Seeds publish only into generation 1; otherwise they are purged
    // and the ledger records excluded(seed_skipped).
    if (headGeneration !== 1) {
      await excludeSeedsIfAny(deps, connectionId, stream);
    }

    // Step 4: encode the changed prefixes. The head's partition is
    // respected: a changed record re-encodes the base prefix holding it,
    // or its own 16-bit prefix when no base prefix covers it.
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
    await uploadStreamBlobs(deps, {
      connectionId,
      stream,
      scope,
      generation: headGeneration,
    });
    const headExtras = await options?.headExtras?.(stream);
    const encoded =
      changedPrefixes.length === 0
        ? []
        : await encodePrefixes(deps, {
            connectionId,
            stream,
            scope,
            generation: headGeneration,
            changedPrefixes,
            upToSeq: watermark ?? 0,
            replaceBelow: plan.replaceBelow,
            headExtras,
          });

    const parts = mergedParts(
      registryHead?.parts ?? [],
      encoded,
      changedPrefixes,
    );
    const recordCount = parts.reduce((sum, part) => sum + part.count, 0);
    const observedAt =
      plan.newestRunObservedAt ?? registryHead?.observedAt ?? deps.now();
    const head: Head = {
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
      parts,
      primaryKey:
        plan.finalHead?.primaryKey ??
        registryHead?.primaryKey ??
        JSON.parse(local.primary_key),
      profile: plan.finalHead?.profile ??
        registryHead?.profile ?? {
          key: local.profile_key ?? connection.connector,
          version: local.profile_version ?? local.floor_version ?? "0",
        },
      recordCount,
      stream,
    };
    const headBytes = encodeHead(head);
    const { dataHash, blobName } = await digestHead(keccak, headBytes);

    // Step 5: if the new head's data hash equals the registry head's,
    // skip the CAS and record the local state (watermark advances, the
    // head is already published).
    if (
      registryDataHash !== null &&
      dataHash.toLowerCase() === registryDataHash.toLowerCase()
    ) {
      const checked = await checkControl(
        deps,
        connectionId,
        connection,
        hashes,
      );
      if (checked) return { stream, outcome: checked, watermark };
      await commitBatch(deps, connectionId, stream, {
        version: registryVersion,
        generation: headGeneration,
        dataHash,
        blobName,
        recordCount,
        observedAt,
        complete: head.complete,
        parts,
        watermark,
        lastDeleteVersion: head.lastDeleteVersion ?? 0,
        replaceBelow: plan.replaceBelow,
        primaryKey: head.primaryKey,
        profile: head.profile,
        isNewVersion: false,
      });
      return { stream, outcome: sawRefusal ? "refused" : "noop", watermark };
    }

    const encrypted = await deps.keys.encrypt(scope, headBytes);
    if ((await deps.blobs.get(`${scope}/${blobName}`)) === null) {
      await deps.blobs.put(`${scope}/${blobName}`, encrypted);
    }
    const newVersion = registryVersion + 1;
    const metadataHash = metadataHashFor(
      scope,
      new Date(observedAt).toISOString(),
      encrypted.length,
    );
    const signature = await deps.signer.signAddData({
      ownerAddress: deps.ownerAddress,
      scope,
      dataHash,
      metadataHash,
      expectedVersion: BigInt(newVersion),
    });
    const beforePost = await checkControl(
      deps,
      connectionId,
      connection,
      hashes,
    );
    if (beforePost) return { stream, outcome: beforePost, watermark };
    attempts++;
    const posted = await deps.registry.post({
      ownerAddress: deps.ownerAddress,
      scope,
      dataHash,
      metadataHash,
      expectedVersion: String(newVersion),
      signature,
    });
    if (posted.kind === "conflict") {
      // Apply the winner and re-plan. On the last try, back off without
      // applying again: the winner will be applied on the next cycle.
      if (attempts === MAX_ATTEMPTS) {
        return { stream, outcome: "backoff", watermark };
      }
      await applyConnection(deps, connectionId);
      continue;
    }

    const afterPost = await checkControl(
      deps,
      connectionId,
      connection,
      hashes,
    );
    if (afterPost) return { stream, outcome: afterPost, watermark };
    await commitBatch(deps, connectionId, stream, {
      version: newVersion,
      generation: headGeneration,
      dataHash,
      blobName,
      recordCount,
      observedAt,
      complete: head.complete,
      parts,
      watermark,
      lastDeleteVersion: head.lastDeleteVersion ?? 0,
      replaceBelow: plan.replaceBelow,
      primaryKey: head.primaryKey,
      profile: head.profile,
      isNewVersion: true,
    });
    return { stream, outcome: "published", watermark };
  }

  return { stream, outcome: "backoff", watermark };
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
        sql: "UPDATE run_streams SET decision='discarded',reason=?,replace=0 WHERE run_id=? AND stream=?",
        params: [trip.trip, run.run_id, stream],
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
  const runs = await deps.db.query<RetainedRun>(
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
};

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
