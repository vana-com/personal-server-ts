import { readEndReceipt } from "./run-receipts.js";
import {
  checkpointDecision,
  type StreamRunResult,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  RunIntakeError,
  type EndRequest,
  type EndResponse,
} from "../stream-sync/intake.js";
import {
  compareConnectorVersions,
  planStreamStep,
  type PlanHead,
} from "../stream-sync/publish-plan.js";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";
import { checkRunFence } from "./fence.js";
import { deleteRunRecords, mergeIncoming, withOrigin } from "./merge.js";
import { decideReplace } from "./replace.js";

/**
 * Run end and abort, in the connection queue (C.1 "end"). Order: fence;
 * `planStreamStep` per stream on local state (refused = drop the stream's
 * `run_rows`; deferred or publish/noop = merge, store the decision, advance
 * the floor); then the checkpoint and retry rule in the SAME batch
 * (`retry_pending` merges accepted streams and saves only a checkpoint that
 * does not advance a refused stream); then the EndResult table. The result
 * of `end` is `EndResult`; `stuck` stays false until publish says otherwise.
 */
type RunEndResponse = Pick<EndResponse, "result" | "updateRequired">;

export interface RunEndStore {
  end(runId: string, req: EndRequest): Promise<RunEndResponse>;
  abort(runId: string, reason: "failed" | "cancelled"): Promise<void>;
}

type Run = {
  connection_id: string;
  o: number;
  generation: number | null;
  artifact_version: string;
  collection_mode: "full_refresh" | "incremental";
  state: "collecting" | "ended";
  last_batch: number;
};

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
  row_count: number;
};

export function createRunEndStore(deps: LocalSyncDeps): RunEndStore {
  const { db, queue } = deps;
  const end: RunEndStore["end"] = async (runId, req) => {
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
            sql: "UPDATE runs SET state = 'ended',end_response=? WHERE run_id = ?",
            params: [JSON.stringify(receipt), runId],
          },
        ];
        if (req.outcome === "failed" || req.outcome === "cancelled") {
          await db.batch([
            {
              sql: "UPDATE run_streams SET decision = 'discarded', reason = ?, replace = 0, publication_state = 'superseded', publication_reason = ? WHERE run_id = ?",
              params: [req.outcome, req.outcome, runId],
            },
            ...cleanup({ result: "aborted", updateRequired: false }),
          ]);
          return { result: "aborted", updateRequired: false };
        }
        if (req.lastBatch !== run.last_batch) {
          throw new RunIntakeError(
            "batch_gap",
            "batch_gap",
            run.last_batch + 1,
          );
        }
        const trips = await checkRunFence(deps, runId, "end");
        if (trips.length > 0) {
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
            ...cleanup({ result: "discarded", updateRequired: false }),
          ]);
          return { result: "discarded", updateRequired: false };
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
        const streams = await db.query<Stream>(
          `SELECT rs.stream, rs.primary_key, rs.profile_key, rs.profile_version,
                rs.full_read, rs.coverage_strategy, rs.semantics, rs.foreign_checkpoint, rs.seed,
                s.primary_key AS local_primary_key, s.profile_key AS local_profile_key,
                s.profile_version AS local_profile_version, s.complete,
                s.head_version, s.head_generation, s.floor_version, s.floor_o, s.floor_r,
                (SELECT COUNT(*) FROM run_rows rr WHERE rr.run_id = rs.run_id AND rr.stream = rs.stream) AS row_count
           FROM run_streams rs LEFT JOIN stream_state s
             ON s.connection_id = ? AND s.stream = rs.stream
          WHERE rs.run_id = ? ORDER BY rs.stream`,
          [run.connection_id, runId],
        );
        const [before] = await db.query<{ seq: number }>(
          "SELECT COALESCE(MAX(seq),0) AS seq FROM record_changes",
        );
        const op = deps.newOp();
        const statements: SqlStatement[] = [];
        const results: Record<string, StreamRunResult> = Object.create(null);
        let merged = false;
        let updateRequired = false;
        const retry = req.outcome === "retry_pending";
        for (const stream of streams) {
          if (stream.local_primary_key === null) {
            throw new Error("Missing local stream state");
          }
          const primaryKey = JSON.parse(
            stream.primary_key ?? stream.local_primary_key,
          ) as string[];
          const profile = {
            key: stream.profile_key ?? connection.connector,
            version: stream.profile_version ?? run.artifact_version,
          };
          const head: PlanHead | null =
            stream.head_version > 0 || stream.floor_o !== null
              ? {
                  generation: stream.head_generation ?? run.generation,
                  primaryKey: JSON.parse(stream.local_primary_key) as string[],
                  profile: {
                    key: stream.local_profile_key ?? connection.connector,
                    version:
                      stream.local_profile_version ??
                      stream.floor_version ??
                      run.artifact_version,
                  },
                  complete: stream.complete === 1,
                }
              : null;
          // A partial run proves success per stream (r5 H), not for every
          // stream it initially requested whole. Publish must replay this
          // result, never the optimistic mode recorded at begin.
          const full =
            !retry &&
            req.coveredStreams.includes(stream.stream) &&
            stream.full_read === 1 &&
            (req.outcome === "succeeded" ||
              (req.provenFullStreams ?? []).includes(stream.stream));
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
              empty: stream.row_count === 0,
              seed: stream.seed,
            },
          );
          updateRequired ||=
            decision.kind === "refused" &&
            decision.reason === "connector_update_required";
          const accepted = decision.kind !== "refused";
          const replace =
            accepted &&
            full &&
            decideReplace({
              stream: stream.stream,
              coverageStrategy: stream.coverage_strategy,
              semantics: stream.semantics,
              outcome: req.outcome,
              collectionMode: run.collection_mode,
              coveredStreams: req.coveredStreams,
              provenFullStreams: req.provenFullStreams ?? [],
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
          );
          merged ||= stream.row_count > 0;
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
        statements.push(...mergeIncoming(op, run.connection_id));
        const candidate = req.checkpointCandidate;
        const refused = Object.keys(results).filter(
          (stream) => results[stream]!.state === "discarded",
        );
        let retryCanSave = retry;
        if (retry && refused.length > 0) {
          const stored =
            connection.checkpoint === null
              ? null
              : (JSON.parse(connection.checkpoint) as Record<string, unknown>);
          // Cursors are opaque: only unchanged or absent refused-stream entries
          // prove that this candidate carries no progress for refused rows.
          retryCanSave =
            refused.length < streams.length &&
            candidate != null &&
            refused.every(
              (stream) =>
                !Object.prototype.hasOwnProperty.call(candidate, stream) ||
                JSON.stringify(candidate[stream]) ===
                  JSON.stringify(stored?.[stream]),
            );
        }
        const canSave =
          retryCanSave ||
          (req.outcome === "succeeded" &&
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
        const saved = candidate != null && canSave;
        if (saved) {
          statements.push({
            sql: "UPDATE connections SET checkpoint = ? WHERE connection_id = ?",
            params: [JSON.stringify(candidate), run.connection_id],
          });
        }
        const response: RunEndResponse = {
          result: merged
            ? "queued"
            : saved
              ? "checkpoint_only"
              : "no_checkpoint",
          updateRequired,
        };
        statements.push(...cleanup(response));
        await db.batch(withOrigin("local", statements));
        return response;
      },
    );
  };
  return {
    end,
    async abort(runId, reason) {
      await end(runId, { outcome: reason, coveredStreams: [], lastBatch: -1 });
    },
  };
}
