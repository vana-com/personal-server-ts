import {
  canonicalJson,
  replicaOperationSchema,
  type ReplicaOperation,
} from "./envelope.js";
import {
  REPLICA_LIMITS_VERSION,
  ReplicaResourceLimitError,
  type ReplicaResourceLimits,
} from "./limits.js";
import type { ReplicaAdmission } from "./outcome.js";

/** Created only by an enabled worker, alongside the admission schema. */
export const REPLICA_PREPARATION_MIGRATION = `
CREATE TABLE IF NOT EXISTS pdpp_transport_preparation (
 batch TEXT PRIMARY KEY, version INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('preparing','prep_failed_permanent','rebuilding','prep_failed_unknown','prepared','released')),
 wait_json TEXT);
CREATE TABLE IF NOT EXISTS pdpp_transport_operation_outcomes (
 batch TEXT NOT NULL, position INTEGER NOT NULL, operation_json TEXT,
 writer_id TEXT, operation_id TEXT,
 encoding_failed INTEGER NOT NULL DEFAULT 0, outcome TEXT, reason TEXT, admission_json TEXT,
 PRIMARY KEY(batch,position));
-- Large valid operations stay in bounded JSON text parts and are rejoined in JS.
CREATE TABLE IF NOT EXISTS pdpp_transport_operation_parts (
 batch TEXT NOT NULL, position INTEGER NOT NULL, part INTEGER NOT NULL,
 json TEXT NOT NULL, PRIMARY KEY(batch,position,part));
CREATE TABLE IF NOT EXISTS pdpp_transport_operation_retention (
 batch TEXT NOT NULL, position INTEGER NOT NULL,
 representation TEXT NOT NULL CHECK(representation IN ('inline','parts','invalid')),
 part_count INTEGER NOT NULL, operation_bytes INTEGER NOT NULL,
 operation_sha256 TEXT,
 PRIMARY KEY(batch,position));
CREATE TABLE IF NOT EXISTS pdpp_transport_upload_attempts (
 batch TEXT NOT NULL, kind TEXT NOT NULL, position INTEGER NOT NULL, started_at INTEGER NOT NULL,
 PRIMARY KEY(batch,kind,position));
`;

export type ReplicaPreparationState =
  | "preparing"
  | "prep_failed_permanent"
  | "rebuilding"
  | "prep_failed_unknown"
  | "prepared"
  | "released";
export type ReplicaPreparation = {
  batch: string;
  version: number;
  state: ReplicaPreparationState;
  wait_json: string | null;
};
export type RetainedPreparationOperation = {
  position: number;
  operation_json: string | null;
  encoding_failed: number;
};

/** Persisted preparation parts failed their completeness or digest fence. */
export class ReplicaPreparationIntegrityError extends Error {
  constructor(batch: string, position: number, reason: string) {
    super(
      `replica preparation integrity failed at ${batch}:${position} (${reason})`,
    );
    this.name = "ReplicaPreparationIntegrityError";
  }
}

/** This error is minted only at the sender's own operation-encoding boundary. */
export class ReplicaPreparationInputError extends Error {
  constructor(readonly positions: readonly number[]) {
    super("replica operation cannot be encoded");
    this.name = "ReplicaPreparationInputError";
  }
}

export type ReplicaPreparationFailure =
  | {
      kind: "permanent";
      admission: ReplicaAdmission;
      positions?: readonly number[];
    }
  | { kind: "unknown" };

/** No message matching, generic RangeError, crypto error or I/O error is permanent. */
export function classifyReplicaPreparationError(
  error: unknown,
): ReplicaPreparationFailure {
  if (error instanceof ReplicaPreparationInputError)
    return {
      kind: "permanent",
      positions: error.positions,
      admission: { reason: "operation_encoding_unsupported" },
    };
  if (
    error instanceof ReplicaResourceLimitError &&
    [
      "operation_count",
      "operation_bytes",
      "single_blob_bytes",
      "aggregate_blob_bytes",
      "aggregate_ciphertext_bytes",
      "total_bytes",
    ].includes(error.limit)
  )
    return {
      kind: "permanent",
      admission: {
        reason: "resource_unsupported",
        limit: error.limit,
        limitsVersion: REPLICA_LIMITS_VERSION,
      },
    };
  return { kind: "unknown" };
}

/** An invalid operation retains its position, never a lossy JSON replacement. */
export function snapshotReplicaOperation(operation: ReplicaOperation): {
  operation_json: string | null;
  encoding_failed: number;
} {
  // A parser must not silently strip input fields. A false parse proves an
  // input problem; an exception here remains unknown and must never drop it.
  if (!replicaOperationSchema.safeParse(operation).success)
    return { operation_json: null, encoding_failed: 1 };
  return { operation_json: canonicalJson(operation), encoding_failed: 0 };
}

/** Attribute each sender-owned streamed limit to the op that crosses it. */
export function preparationOperationFailures(
  rows: readonly RetainedPreparationOperation[],
  limits: ReplicaResourceLimits,
):
  | {
      positions: number[];
      error: ReplicaPreparationInputError | ReplicaResourceLimitError;
    }
  | undefined {
  const encoding = rows
    .filter((row) => row.encoding_failed)
    .map((row) => row.position);
  if (encoding.length)
    return {
      positions: encoding,
      error: new ReplicaPreparationInputError(encoding),
    };
  const acceptedBlobs = new Set<string>();
  let blobBytes = 0;
  let count = 0;
  const failures: { position: number; error: ReplicaResourceLimitError }[] = [];
  for (const row of rows) {
    const op = JSON.parse(row.operation_json!) as ReplicaOperation;
    const blobs =
      op.kind === "upsert"
        ? op.blobs
        : op.kind === "blob-claim"
          ? [op.blob]
          : [];
    const newBlobs = [
      ...new Map(
        blobs
          .filter((blob) => !acceptedBlobs.has(blob.blobId))
          .map((blob) => [blob.blobId, blob]),
      ).values(),
    ];
    const newBytes = newBlobs.reduce((n, blob) => n + blob.sizeBytes, 0);
    const bytes = new TextEncoder().encode(row.operation_json!).length;
    const oversizedBlob = blobs.find(
      (blob) => blob.sizeBytes > limits.maxSingleBlobBytes,
    );
    const error =
      count >= limits.maxOperations
        ? new ReplicaResourceLimitError(
            "operation_count",
            count + 1,
            limits.maxOperations,
          )
        : bytes > limits.maxOperationBytes
          ? new ReplicaResourceLimitError(
              "operation_bytes",
              bytes,
              limits.maxOperationBytes,
            )
          : oversizedBlob
            ? new ReplicaResourceLimitError(
                "single_blob_bytes",
                oversizedBlob.sizeBytes,
                limits.maxSingleBlobBytes,
              )
            : blobBytes + newBytes > limits.maxBlobTotalBytes
              ? new ReplicaResourceLimitError(
                  "aggregate_blob_bytes",
                  blobBytes + newBytes,
                  limits.maxBlobTotalBytes,
                )
              : undefined;
    if (error) {
      failures.push({ position: row.position, error });
      continue;
    }
    count++;
    blobBytes += newBytes;
    for (const blob of newBlobs) acceptedBlobs.add(blob.blobId);
  }
  // Settle one reason per transition; a subsequent pass checks the survivors.
  const first = failures[0];
  return (
    first && {
      positions: failures
        .filter((failure) => failure.error.limit === first.error.limit)
        .map((failure) => failure.position),
      error: first.error,
    }
  );
}
