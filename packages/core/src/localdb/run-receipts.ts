import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  RunIntakeError,
  type BeginRequest,
  type BeginResponse,
  type EndResponse,
} from "../stream-sync/intake.js";
import type { SqlDriver } from "./driver.js";

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
