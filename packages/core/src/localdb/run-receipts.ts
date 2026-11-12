import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  RunIntakeError,
  type BeginRequest,
  type BeginResponse,
  type EndResponse,
  type RunPublicationState,
  type RunPublicationStatus,
  type RunStreamPublication,
} from "../stream-sync/intake.js";
import type { SqlDriver } from "./driver.js";
import { streamFenceTrip } from "./fence.js";

export type LocalEndReceipt = Pick<EndResponse, "result" | "updateRequired">;

/** Immutable local acknowledgement. Publication is a separate operation. */
export async function readEndReceipt(
  db: SqlDriver,
  runId: string,
): Promise<LocalEndReceipt | null> {
  const [row] = await db.query<{ end_response: string | null }>(
    "SELECT end_response FROM runs WHERE run_id=? AND state='ended'",
    [runId],
  );
  return row?.end_response
    ? (JSON.parse(row.end_response) as LocalEndReceipt)
    : null;
}

/** An ended id never starts another collector, even after a process restart. */
export async function readBeginReceipt(
  db: SqlDriver,
  runId: string,
  req: BeginRequest,
): Promise<BeginResponse | null> {
  if (
    typeof req.connector !== "string" ||
    typeof req.artifactDigest !== "string" ||
    !req.artifactDigest
  )
    throw new RunIntakeError("invalid_request");
  let connectionId: string;
  try {
    connectionId = controlScope(req.connector, "");
  } catch {
    throw new RunIntakeError("invalid_request");
  }
  const [row] = await db.query<{
    connection_id: string;
    begin_request: string | null;
    begin_response: string | null;
    end_response: string | null;
  }>(
    "SELECT connection_id,begin_request,begin_response,end_response FROM runs WHERE run_id=? AND state='ended'",
    [runId],
  );
  if (!row) return null;
  if (row.connection_id !== connectionId)
    throw new RunIntakeError("run_conflict");
  // Older runs have no exact saved acknowledgement. Never invent one.
  if (!row.begin_request || !row.begin_response || !row.end_response)
    throw new RunIntakeError("gone", "run receipt unavailable");
  const original = JSON.parse(row.begin_request) as BeginRequest;
  if (original.artifactDigest !== req.artifactDigest)
    throw new RunIntakeError("run_conflict");
  return {
    ...(JSON.parse(row.begin_response) as BeginResponse),
    status: "ended",
    receipt: {
      ...(JSON.parse(row.end_response) as LocalEndReceipt),
      stuck: false,
    },
  };
}

type PublicationRow = {
  run_state: "collecting" | "ended";
  connection_id: string;
  stream: string | null;
  decision: string | null;
  decision_reason: string | null;
  publication_state: RunPublicationState | null;
  publication_reason: string | null;
  published_generation: number | null;
  published_version: number | null;
  published_data_hash: string | null;
  published_watermark: number | null;
  control_state: string | null;
  connection_generation: number | null;
  last_delete_version: number | null;
  delete_requested: number;
  run_generation: number | null;
  delete_snapshot: number | null;
};

/**
 * Whether an ended run is saved. One SELECT, so one snapshot: a delete or a
 * publication lands wholly before or wholly after it. The durable evidence is
 * written with the head (publish.ts); this read only adds what changed since:
 * a deleted or restarted connection, a stream deleted after publication.
 * `publish_watermark` is never compared with the run's `o`: one counts local
 * changes, the other is a time.
 */
export async function readPublicationStatus(
  db: SqlDriver,
  runId: string,
  expect?: { readonly connector?: string },
): Promise<RunPublicationStatus> {
  const rows = await db.query<PublicationRow>(
    `SELECT r.state AS run_state, r.connection_id, rs.stream, rs.decision, rs.reason AS decision_reason,
            rs.publication_state, rs.publication_reason, rs.published_generation, rs.published_version,
            rs.published_data_hash, rs.published_watermark,
            c.control_state, c.generation AS connection_generation,
            s.last_delete_version, r.generation AS run_generation, rs.delete_snapshot,
            EXISTS (SELECT 1 FROM delete_intents d WHERE d.connector = c.connector) AS delete_requested
       FROM runs r
       LEFT JOIN run_streams rs ON rs.run_id = r.run_id
       LEFT JOIN connections c ON c.connection_id = r.connection_id
       LEFT JOIN stream_state s ON s.connection_id = r.connection_id AND s.stream = rs.stream
      WHERE r.run_id = ?
      ORDER BY rs.stream`,
    [runId],
  );
  const first = rows[0];
  if (!first) throw new RunIntakeError("gone");
  if (expect?.connector !== undefined) {
    let connectionId: string;
    try {
      connectionId = controlScope(expect.connector, "");
    } catch {
      throw new RunIntakeError("invalid_request");
    }
    if (first.connection_id !== connectionId)
      throw new RunIntakeError("run_conflict");
  }
  if (first.run_state !== "ended")
    return { runId, state: "unknown", reason: "run_not_ended", streams: [] };
  const streams = rows
    .filter((row) => row.stream !== null)
    .map((row) => streamPublication(row));
  const accepted = rows.filter(
    (row) =>
      row.decision === "publish" ||
      row.decision === "noop" ||
      row.decision === "deferred",
  );
  if (accepted.length === 0)
    return { runId, state: "unknown", reason: "no_accepted_streams", streams };
  // One stream that is superseded, pending or unknown keeps the run from
  // reading as saved. Refused and discarded streams count: their work is gone.
  const states = new Set(streams.map((stream) => stream.state));
  const state =
    (["superseded", "pending", "unknown"] as const).find((candidate) =>
      states.has(candidate),
    ) ?? "published";
  return { runId, state, streams };
}

function streamPublication(row: PublicationRow): RunStreamPublication {
  const name = row.stream!;
  const stored = row.publication_state ?? "unknown";
  const evidence =
    row.published_generation !== null &&
    row.published_version !== null &&
    row.published_data_hash !== null &&
    row.published_watermark !== null
      ? {
          publication: {
            generation: row.published_generation,
            version: row.published_version,
            dataHash: row.published_data_hash,
            watermark: row.published_watermark,
          },
        }
      : {};
  const result = (state: RunPublicationState, reason: string | null) => ({
    name,
    state,
    ...(reason !== null && { reason }),
    ...evidence,
  });
  if (row.decision === "refused" || row.decision === "discarded")
    return result(
      "superseded",
      row.publication_reason ?? row.decision_reason ?? row.decision,
    );
  if (stored === "unknown") return result("unknown", row.publication_reason);
  if (stored === "superseded")
    return result("superseded", row.publication_reason);
  // The connection is gone or being deleted: pending work will never publish,
  // and published work is no longer there to rely on.
  if (row.control_state === "deleted" || row.control_state === null)
    return result("superseded", "connection_deleted");
  if (row.delete_requested === 1)
    return result("superseded", "connection_delete_requested");
  if (stored === "pending") {
    // Pending work whose generation or delete snapshot was overtaken by an
    // applied reset or tombstone can never publish; say so now, with the
    // same facts the publish fence uses, rather than after the next pass.
    const trip = streamFenceTrip({
      runGeneration: row.run_generation,
      deleteSnapshot: row.delete_snapshot ?? 0,
      connectionGeneration: row.connection_generation ?? undefined,
      lastDeleteVersion: row.last_delete_version ?? undefined,
    });
    if (trip !== undefined)
      return result(
        "superseded",
        trip === "generation_moved_by_delete"
          ? "generation_changed"
          : "stream_deleted",
      );
    return result("pending", row.publication_reason);
  }
  if (row.published_generation !== row.connection_generation)
    return result("superseded", "generation_changed");
  if ((row.last_delete_version ?? 0) > (row.published_version ?? 0))
    return result("superseded", "stream_deleted");
  return result("published", null);
}
