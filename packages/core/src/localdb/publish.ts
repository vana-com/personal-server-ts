// What a log publish plans from: the retained ended runs of a stream, the
// fences that discard a run (a lifetime that ended, a delete), the seeds that
// publish only into generation 1, and the run-to-publication evidence a commit
// writes. The writer is `publishLog` (log-publish.ts); this module holds the
// steps its snapshot shares with the run store.

import { keccakOf, type StreamCryptoPort } from "../stream-sync/crypto-port.js";
import {
  toHex,
  utf8,
  type Head,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  planStreamStep,
  type PlanHead,
  type PlanRun,
  type StepDecision,
} from "../stream-sync/publish-plan.js";
import {
  AmbiguousRegistryReplyError,
  type RegistryBatchResult,
  type SignedRegistryBatch,
  type StreamSyncRegistry,
} from "../stream-sync/ports.js";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";
import { dropRunRows, withOrigin } from "./merge.js";
import { checkRunFence } from "./fence.js";
import { replaceMayApply } from "./replace.js";

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

/** metadataHash for a head: keccak over the UTF-8 JSON of the envelope facts. */
export async function metadataHashFor(
  scope: string,
  collectedAt: string,
  sizeBytes: number,
  port: StreamCryptoPort | undefined,
): Promise<`0x${string}`> {
  return `0x${toHex(await keccakOf(port)(utf8(JSON.stringify({ scope, collectedAt, sizeBytes }))))}`;
}

export type ConnectionRow = {
  connector: string;
  ns: string;
  generation: number;
};

export type LocalStream = {
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

/** The identical request twice at most: a lost reply is resent once. */
export async function postBatchOnce(
  registry: StreamSyncRegistry,
  request: SignedRegistryBatch,
): Promise<RegistryBatchResult> {
  try {
    return await registry.postBatch!(request);
  } catch (error) {
    if (!(error instanceof AmbiguousRegistryReplyError)) throw error;
  }
  // The first send may have landed. The gateway answers a row it already holds
  // with its own hash, which settleRow reads as published. A second lost
  // reply is an unknown outcome and throws, as a lost single write does.
  return registry.postBatch!(request);
}

/** Whether the connection's local lifetime is still generation `generation`. */
export async function lifetimeHolds(
  deps: LocalSyncDeps,
  connectionId: string,
  generation: number,
): Promise<boolean> {
  const [row] = await deps.db.query(
    `SELECT generation FROM connections WHERE connection_id = ?`,
    [connectionId],
  );
  return row !== undefined && Number(row.generation) === generation;
}

/** A local delete of the connector is under way: nothing is published. */
export async function hasDeleteIntent(
  deps: LocalSyncDeps,
  connector: string,
): Promise<boolean> {
  const rows = await deps.db.query(
    "SELECT 1 FROM delete_intents WHERE connector=?",
    [connector],
  );
  return rows.length > 0;
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
      ...dropRunRows(connectionId, run.stream, run.o, run.run_id),
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
  // The discarded rows were collected against a lifetime that ended: the next
  // run collects in full instead of resuming from their checkpoint.
  statements.push({
    sql: "UPDATE connections SET checkpoint = NULL WHERE connection_id = ?",
    params: [connectionId],
  });
  await deps.db.batch(withOrigin("purge", statements));
  return true;
}

export async function discardFencedRuns(
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
      ...dropRunRows(id, stream, run.o, run.run_id),
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
  await deps.db.batch(withOrigin("purge", statements));
  return true;
}

export type StreamPlan = {
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

export async function planStream(
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
export async function excludeSeedsIfAny(
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

/** What a publication confirmed, and the runs it covered. */
export type RunEvidence = {
  version: number;
  generation: number;
  dataHash: `0x${string}`;
  watermark: number | null;
  replaceBelow: { o: number; r: string } | undefined;
  /** The plan's accepted runs for this stream: the runs this publication covers. */
  runIds: readonly string[];
};

const RUN_ID_CHUNK = 400;

/**
 * Durable run-to-publication evidence, written in the same batch as the head.
 * Only runs still `pending` move to `published`, so a later publication never
 * rewrites older evidence and runs from before this column stay `unknown`.
 * The ids are the plan's: a run that ended after planning is not covered.
 * The watermark is stored as evidence only; it is a local change sequence and
 * is never compared with a run's `o`.
 */
export async function runPublicationStatements(
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
