import { normalizeRawEnd } from "../stream-sync/normalize-raw-end.js";
import { readRawRecordEvidence } from "./raw-end-evidence.js";
import { readEndReceipt } from "./run-receipts.js";
import {
  checkpointDecision,
  type StreamRunResult,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  RunIntakeError,
  type BeginResponse,
  type EndResponse,
} from "../stream-sync/intake.js";
import {
  parseEndRequest,
  planRunFinish,
  type RunFinishPlan,
  type RunFinishStream,
} from "../stream-sync/run-finish-plan.js";
import {
  compareConnectorVersions,
  planStreamStep,
} from "../stream-sync/publish-plan.js";
import { announceRecordsCommitted, type LocalSyncDeps } from "./deps.js";
import {
  compactTombstones,
  replaceOwnRunRows,
  tombstoneRunDeletes,
} from "./admit.js";
import type { SqlStatement } from "./driver.js";
import { checkRunFence } from "./fence.js";
import { planInputs } from "./plan-inputs.js";
import { deleteRunRecords, mergeIncoming, withOrigin } from "./merge.js";
import { decideReplace } from "./replace.js";

/**
 * Run end and abort, in the connection queue (C.1 "end"). Order: the run's
 * finish plan from the host's observations (`planRunFinish`; a `failed` plan
 * ends the run as an abort); fence; `planStreamStep` per stream on local
 * state (refused = drop the stream's `run_rows`; deferred or publish/noop =
 * merge the covered streams' upserts and every stream's deletes, store the
 * decision, advance the floor); then the checkpoint and retry rule in the
 * SAME batch (`retry_pending` merges accepted streams and saves only a
 * checkpoint that does not advance a refused stream); then the EndResult
 * table. `stuck` stays false until publish says otherwise.
 */
type RunEndResponse = Omit<EndResponse, "stuck">;

export interface RunEndStore {
  /** `body` is the host's `EndRequest`; its shape is checked here. */
  end(runId: string, body: unknown): Promise<RunEndResponse>;
  abort(runId: string, reason: "failed" | "cancelled"): Promise<void>;
  /**
   * The runs of a process that is gone: those `collecting` now. Run bindings
   * live in memory, so when a sync starts nothing can end them. Read once, at
   * start, before any run of this sync begins: a later read would also return
   * live runs. The host holds the database exclusively (`LiteDatabasePort`),
   * so no live run of another sync shares it. With the flag off only runs that
   * admitted their batches count (`runs.admitting`, set while it was on): they
   * hold tombstones back. A flag-off run stays exactly as it was.
   */
  orphans(): Promise<string[]>;
  /**
   * Ends each run of `ids` as failed (rows it admitted stay, as for any failed
   * run) and returns the ids it could not end. Never rejects.
   */
  endOrphans(ids: readonly string[]): Promise<string[]>;
}

type Run = {
  connection_id: string;
  o: number;
  generation: number | null;
  artifact_version: string;
  collection_mode: "full_refresh" | "incremental";
  state: "collecting" | "ended";
  last_batch: number;
  admitting: number;
  begin_response: string | null;
  selected_streams: string | null;
};

/** The run's START per declared stream. Runs stored no response before it existed. */
function declaredStreams(
  run: Run,
  streams: readonly { stream: string; coverage_strategy: string | null }[],
): Record<string, RunFinishStream> {
  const declared: Record<string, RunFinishStream> = Object.create(null);
  const begin = run.begin_response
    ? (JSON.parse(run.begin_response) as BeginResponse)
    : null;
  for (const stream of begin?.streams ?? [])
    declared[stream.name] = {
      mode: stream.mode,
      coverageStrategy: stream.coverageStrategy ?? null,
      stateParents: stream.stateParents ?? [],
    };
  for (const stream of streams)
    declared[stream.stream] ??= {
      mode: run.collection_mode,
      coverageStrategy:
        stream.coverage_strategy as RunFinishStream["coverageStrategy"],
      stateParents: [],
    };
  return declared;
}

function answer(
  plan: Pick<RunFinishPlan, "covered" | "provenFull" | "unconfirmed"> & {
    readonly outcome: EndResponse["outcome"];
  },
  result: EndResponse["result"],
  updateRequired: boolean,
): RunEndResponse {
  return {
    result,
    updateRequired,
    outcome: plan.outcome,
    coveredStreams: plan.covered,
    provenFullStreams: plan.provenFull,
    unconfirmed: plan.unconfirmed,
  };
}

type Stream = {
  stream: string;
  primary_key: string | null;
  profile_key: string | null;
  profile_version: string | null;
  full_read: number;
  coverage_strategy: string | null;
  semantics: string | null;
  foreign_checkpoint: number;
  seed: "none" | "merged" | "unresolved";
  local_primary_key: string | null;
  local_profile_key: string | null;
  local_profile_version: string | null;
  complete: number;
  head_version: number;
  head_generation: number | null;
  floor_version: string | null;
  floor_o: number | null;
  floor_r: string | null;
  upserts: number;
  deletes: number;
  /** Set by batch admission: the connector is below the head's version or key. */
  marked_reason: string | null;
  unadmitted: number;
};

export function createRunEndStore(deps: LocalSyncDeps): RunEndStore {
  const { db, queue } = deps;
  /** `abort`: end the run as failed or cancelled, whatever the host saw. */
  const finish = async (
    runId: string,
    body: unknown,
    abort?: "failed" | "cancelled",
  ): Promise<RunEndResponse> => {
    const [binding] = await db.query<{ connection_id: string }>(
      "SELECT connection_id FROM runs WHERE run_id = ?",
      [runId],
    );
    if (!binding) throw new RunIntakeError("gone");
    return queue.run(
      binding.connection_id,
      "end",
      async (): Promise<RunEndResponse> => {
        // Re-read after acquiring the queue: an earlier end or delete may have won.
        const [run] = await db.query<Run>(
          "SELECT * FROM runs WHERE run_id = ?",
          [runId],
        );
        if (!run) throw new RunIntakeError("gone");
        if (run.state !== "collecting") {
          const receipt = await readEndReceipt(db, runId);
          if (receipt) return receipt;
          throw new RunIntakeError("gone");
        }
        const cleanup = (receipt: RunEndResponse): SqlStatement[] => [
          { sql: "DELETE FROM run_rows WHERE run_id = ?", params: [runId] },
          {
            sql: "DELETE FROM run_record_evidence WHERE run_id = ?",
            params: [runId],
          },
          {
            sql: "UPDATE runs SET state = 'ended',end_response=?,raw_end=? WHERE run_id = ?",
            params: [
              JSON.stringify(receipt),
              body !== null && typeof body === "object" && "wireDialect" in body
                ? JSON.stringify(body)
                : null,
              runId,
            ],
          },
          // This run no longer holds back older tombstones. Last, so the
          // compaction sees the run as ended.
          // Whatever the flag says now: tombstones outlive a flag that went off.
          ...compactTombstones(run.connection_id),
        ];
        const discard = async (
          reason: "failed" | "cancelled",
          unconfirmed: boolean,
        ): Promise<RunEndResponse> => {
          const response = answer(
            { outcome: reason, covered: [], provenFull: [], unconfirmed },
            "aborted",
            false,
          );
          await db.batch([
            {
              sql: "UPDATE run_streams SET decision = 'discarded', reason = ?, replace = 0, publication_state = 'superseded', publication_reason = ? WHERE run_id = ?",
              params: [reason, reason, runId],
            },
            ...cleanup(response),
          ]);
          return response;
        };
        if (abort) return discard(abort, false);
        const streams = await db.query<Stream>(
          `SELECT rs.stream, rs.primary_key, rs.profile_key, rs.profile_version,
                rs.full_read, rs.coverage_strategy, rs.semantics, rs.foreign_checkpoint, rs.seed,
                s.primary_key AS local_primary_key, s.profile_key AS local_profile_key,
                s.profile_version AS local_profile_version, s.complete,
                s.head_version, s.head_generation, s.floor_version, s.floor_o, s.floor_r,
                (SELECT COUNT(*) FROM run_rows rr WHERE rr.run_id = rs.run_id AND rr.stream = rs.stream AND rr.op = 'upsert') AS upserts,
                (SELECT COUNT(*) FROM run_rows rr WHERE rr.run_id = rs.run_id AND rr.stream = rs.stream AND rr.op = 'delete') AS deletes,
                rs.reason AS marked_reason, rs.unadmitted
           FROM run_streams rs LEFT JOIN stream_state s
             ON s.connection_id = ? AND s.stream = rs.stream
          WHERE rs.run_id = ? ORDER BY rs.stream`,
          [run.connection_id, runId],
        );
        const raw =
          body !== null && typeof body === "object" && "wireDialect" in body;
        const declarations = declaredStreams(run, streams);
        const req = raw
          ? normalizeRawEnd(
              body,
              {
                selectedStreams:
                  run.selected_streams === null
                    ? (() => {
                        throw new RunIntakeError(
                          "invalid_request",
                          "raw end requires explicit selection at begin",
                        );
                      })()
                    : JSON.parse(run.selected_streams),
                streams: Object.fromEntries(
                  streams.map((stream) => [
                    stream.stream,
                    {
                      ...declarations[stream.stream]!,
                      fullRead: stream.full_read === 1,
                    },
                  ]),
                ),
              },
              await readRawRecordEvidence(db, runId),
            )
          : parseEndRequest(
              body,
              streams.map((stream) => stream.stream),
            );
        if (req.lastBatch !== run.last_batch) {
          throw new RunIntakeError(
            "batch_gap",
            "batch_gap",
            run.last_batch + 1,
          );
        }
        const plan = planRunFinish(req, declarations);
        if (plan.outcome === "failed")
          return discard("failed", plan.unconfirmed);
        const covered = new Set(plan.covered);
        const trips = await checkRunFence(deps, runId, "end");
        if (trips.length > 0) {
          const fenced = answer(plan, "discarded", false);
          await db.batch([
            {
              sql: "UPDATE connections SET checkpoint = NULL WHERE connection_id = ?",
              params: [run.connection_id],
            },
            {
              sql: "UPDATE run_streams SET decision = 'discarded', reason = 'fence', replace = 0, publication_state = 'superseded', publication_reason = 'fence' WHERE run_id = ?",
              params: [runId],
            },
            ...trips.map(({ stream, trip }) => ({
              sql: "UPDATE run_streams SET reason = ?, publication_reason = ? WHERE run_id = ? AND stream = ?",
              params: [trip, trip, runId, stream],
            })),
            {
              sql: `UPDATE stream_state SET needs_full = 1, complete = 0
              WHERE connection_id = ? AND stream IN (SELECT stream FROM run_streams WHERE run_id = ?)`,
              params: [run.connection_id, runId],
            },
            ...cleanup(fenced),
          ]);
          return fenced;
        }
        const [connection] = await db.query<{
          connector: string;
          generation: number;
          control_state: string;
          checkpoint: string | null;
        }>(
          "SELECT connector, generation, control_state, checkpoint FROM connections WHERE connection_id = ?",
          [run.connection_id],
        );
        if (!connection) throw new RunIntakeError("gone");
        const [before] = await db.query<{ seq: number }>(
          "SELECT COALESCE(MAX(seq),0) AS seq FROM record_changes",
        );
        const op = deps.newOp();
        const statements: SqlStatement[] = [];
        const results: Record<string, StreamRunResult> = Object.create(null);
        let merged = false;
        let lateAdmission = false;
        let updateRequired = false;
        const outcome = plan.outcome;
        const retry = outcome === "retry_pending";
        for (const stream of streams) {
          if (stream.local_primary_key === null) {
            throw new Error("Missing local stream state");
          }
          const { primaryKey, profile, head } = planInputs(
            { ...stream, local_primary_key: stream.local_primary_key },
            run,
            connection.connector,
          );
          // A partial run proves success per stream (r5 H), not for every
          // stream it initially requested whole. Publish must replay this
          // result, never the optimistic mode recorded at begin.
          // An uncovered stream keeps only its explicit deletes.
          const isCovered = covered.has(stream.stream);
          const kept = (isCovered ? stream.upserts : 0) + stream.deletes;
          const full =
            !retry &&
            isCovered &&
            stream.full_read === 1 &&
            (outcome === "succeeded" ||
              plan.provenFull.includes(stream.stream));
          const decision = planStreamStep(
            {
              head,
              floor: {
                version: stream.floor_version,
                committed:
                  stream.floor_o !== null && stream.floor_r !== null
                    ? { observedAt: stream.floor_o, runId: stream.floor_r }
                    : null,
              },
            },
            {
              runId,
              observedAt: run.o,
              generation: run.generation,
              primaryKey,
              profile,
              full,
              foreignCheckpoint: stream.foreign_checkpoint === 1,
              empty: kept === 0,
              seed: stream.seed,
            },
          );
          updateRequired ||=
            stream.marked_reason === "connector_update_required" ||
            (decision.kind === "refused" &&
              decision.reason === "connector_update_required");
          const accepted = decision.kind !== "refused";
          const replace =
            accepted &&
            full &&
            decideReplace({
              stream: stream.stream,
              coverageStrategy: stream.coverage_strategy,
              semantics: stream.semantics,
              outcome,
              collectionMode: run.collection_mode,
              coveredStreams: plan.covered,
              provenFullStreams: plan.provenFull,
            });
          statements.push({
            sql: "UPDATE run_streams SET decision = ?, reason = ?, replace = ?, full_read = ?, publication_state = ?, publication_reason = ? WHERE run_id = ? AND stream = ?",
            params: [
              decision.kind,
              "reason" in decision ? decision.reason : null,
              replace ? 1 : 0,
              full ? 1 : 0,
              // Accepted work waits for a publication; refused work never gets one.
              accepted ? "pending" : "superseded",
              "reason" in decision ? decision.reason : null,
              runId,
              stream.stream,
            ],
          });
          if (!accepted) {
            results[stream.stream] = { state: "discarded" };
            continue;
          }
          // A run that admitted its batches has its upserts in `records` already,
          // except a stream with rows staged and not admitted. Admitted upserts
          // of an uncovered stream stay: publish while collecting shows rows
          // before the run ends.
          if (isCovered && run.admitting === 1 && stream.unadmitted === 1)
            lateAdmission = true;
          if (isCovered && (run.admitting !== 1 || stream.unadmitted === 1))
            statements.push({
              sql: `INSERT INTO incoming (op, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o)
              SELECT ?, stream, pk_hash, record_key, ?, ?, body, body_sha256, ?
                FROM run_rows WHERE run_id = ? AND stream = ? AND op = 'upsert'`,
              params: [op, run.o, runId, run.o, runId, stream.stream],
            });
          statements.push(
            ...deleteRunRecords(
              run.connection_id,
              stream.stream,
              runId,
              run.o,
              before!.seq,
            ),
            ...tombstoneRunDeletes(
              run.connection_id,
              stream.stream,
              runId,
              run.o,
              deps.publishWhileCollecting === true,
            ),
          );
          merged ||= kept > 0;
          const nextVersion =
            stream.floor_version === null ||
            compareConnectorVersions(profile.version, stream.floor_version) ===
              "higher"
              ? profile.version
              : stream.floor_version;
          const newer =
            stream.floor_o === null ||
            run.o > stream.floor_o ||
            (run.o === stream.floor_o &&
              (stream.floor_r === null || runId > stream.floor_r));
          statements.push({
            sql: "UPDATE stream_state SET floor_version = ?, floor_o = ?, floor_r = ? WHERE connection_id = ? AND stream = ?",
            params: [
              nextVersion,
              newer ? run.o : stream.floor_o,
              newer ? runId : stream.floor_r,
              run.connection_id,
              stream.stream,
            ],
          });
          if (decision.kind === "deferred") {
            results[stream.stream] = { state: "pending" };
          } else {
            const complete = retry
              ? stream.complete === 1
              : decision.head.complete;
            statements.push({
              sql: `UPDATE stream_state SET primary_key = ?, profile_key = ?, profile_version = ?, complete = ?
                    WHERE connection_id = ? AND stream = ?`,
              params: [
                JSON.stringify(decision.head.primaryKey),
                decision.head.profile.key,
                decision.head.profile.version,
                complete ? 1 : 0,
                run.connection_id,
                stream.stream,
              ],
            });
            results[stream.stream] =
              run.generation === null
                ? { state: "pending" }
                : {
                    state: decision.kind === "noop" ? "noop" : "committed",
                    generation: run.generation,
                    complete,
                  };
          }
        }
        // A later batch of the run wins over an earlier one admitted before.
        if (lateAdmission)
          statements.push(
            replaceOwnRunRows(op, run.connection_id, runId, run.o),
          );
        statements.push(...mergeIncoming(op, run.connection_id));
        const candidate = plan.candidate;
        const refused = Object.keys(results).filter(
          (stream) => results[stream]!.state === "discarded",
        );
        const stored =
          connection.checkpoint === null
            ? null
            : (JSON.parse(connection.checkpoint) as Record<string, unknown>);
        // Partial retries save the same dependency-safe candidate as an
        // all-pending retry, including finished streams' committed progress.
        const retryCheckpoint =
          retry ||
          (outcome === "partial" &&
            req.finish === "completed" &&
            Object.values(req.streams).some((stream) => stream.retryableSkip));
        let retryCanSave = retryCheckpoint;
        if (retryCheckpoint && refused.length > 0) {
          // Cursors are opaque: only unchanged or absent refused-stream entries
          // prove that this candidate carries no progress for refused rows.
          retryCanSave =
            refused.length < streams.length &&
            refused.every(
              (stream) =>
                !Object.prototype.hasOwnProperty.call(candidate, stream) ||
                JSON.stringify(candidate[stream]) ===
                  JSON.stringify(stored?.[stream]),
            );
        }
        const canSave =
          retryCanSave ||
          (outcome === "succeeded" &&
            run.generation !== null &&
            checkpointDecision({
              target: run.generation,
              streams: results,
              control:
                connection.control_state === "active"
                  ? { kind: "active", generation: connection.generation }
                  : { kind: "absent" },
              seedReceiptsPending: streams.some(
                (stream) => stream.seed === "unresolved",
              ),
            }).kind === "save");
        const saved = canSave;
        if (saved) {
          // A stream the plan held back keeps the cursor it had.
          statements.push({
            sql: "UPDATE connections SET checkpoint = ? WHERE connection_id = ?",
            params: [
              JSON.stringify({ ...stored, ...candidate }),
              run.connection_id,
            ],
          });
        }
        const response = answer(
          plan,
          merged ? "queued" : saved ? "checkpoint_only" : "no_checkpoint",
          updateRequired,
        );
        statements.push(...cleanup(response));
        await db.batch(withOrigin("local", statements));
        announceRecordsCommitted(deps);
        return response;
      },
    );
  };
  return {
    end: (runId, body) => finish(runId, body),
    async abort(runId, reason) {
      await finish(runId, undefined, reason);
    },
    async orphans() {
      const rows = await db.query<{ run_id: string }>(
        "SELECT run_id FROM runs WHERE state = 'collecting' AND (admitting = 1 OR ? = 1) ORDER BY o, run_id",
        [deps.publishWhileCollecting === true ? 1 : 0],
      );
      return rows.map((row) => row.run_id);
    },
    async endOrphans(ids) {
      const left: string[] = [];
      for (const runId of ids) {
        try {
          await finish(runId, undefined, "failed");
        } catch (error) {
          // Gone (deleted) or already ended: nothing left to end.
          if (error instanceof RunIntakeError && error.code === "gone")
            continue;
          left.push(runId);
          deps.logger.warn(
            { runId, error: String(error) },
            "could not end an orphaned run",
          );
        }
      }
      return left;
    },
  };
}
