/**
 * Whether a stream-sync run's work is saved: a Web write reports "saved", a
 * phone may retire the old copies of the data. Pure: publication receipts,
 * the run's durable publication status and the connection's state in, a
 * verdict out. Vectors: `contracts/run-saved.json`.
 */
import type { ControlState } from "@opendatalabs/personal-server-ts-stream-sync";
import type { PublicationReceipt } from "../localdb/publish.js";
import type { RunPublicationStatus } from "./intake.js";

/**
 * `receipt_or_status`: a publication receipt that lists the run, or, when
 * the cycle gave none (a lost reply, a noop cycle), the run's durable status
 * `published`. `strict_receipt`: only a receipt. Retiring old copies uses it:
 * no decision lets a status alone delete data.
 */
export type RunSavedMode = "receipt_or_status" | "strict_receipt";

export interface RunSavedInput {
  readonly runId: string;
  readonly connector: string;
  /** Every stream the run must have published. Empty is never saved. */
  readonly requiredStreams: readonly string[];
  /** The receipts of the publication cycle the host awaited, if any. */
  readonly receipts: readonly PublicationReceipt[];
  readonly status: RunPublicationStatus | null;
  /**
   * The ids of this connector's connections that are not deleted, from the
   * local database. `null`: the host cannot read them; `strict_receipt` then
   * never answers saved.
   */
  readonly liveConnections: readonly string[] | null;
  /** The connection's control state now. Saved needs `active`. */
  readonly control: ControlState | null;
  readonly mode: RunSavedMode;
}

export type RunSavedRefusal =
  | "no_required_streams"
  | "no_receipt"
  | "streams_uncovered"
  | "connection_mismatch"
  | "connection_unknown"
  | "not_active";

export type RunSavedVerdict =
  | {
      readonly saved: true;
      readonly proof: "receipt" | "status";
      /** The connection the receipts name; `null` for a status proof. */
      readonly connectionId: string | null;
    }
  | { readonly saved: false; readonly reason: RunSavedRefusal };

/** A head a publication can stand on, and a watermark of this database. */
function soundReceipt(receipt: PublicationReceipt): boolean {
  const { head, watermark } = receipt;
  return (
    Number.isSafeInteger(head.version) &&
    head.version > 0 &&
    Number.isSafeInteger(head.generation) &&
    head.generation > 0 &&
    typeof head.dataHash === "string" &&
    head.dataHash !== "" &&
    Number.isSafeInteger(watermark) &&
    watermark >= 0
  );
}

export function decideRunSaved(input: RunSavedInput): RunSavedVerdict {
  const refuse = (reason: RunSavedRefusal): RunSavedVerdict => ({
    saved: false,
    reason,
  });
  const required = [...new Set(input.requiredStreams)];
  if (required.length === 0) return refuse("no_required_streams");
  const receipts = input.receipts.filter(
    (receipt) =>
      receipt.connector === input.connector &&
      receipt.runIds.includes(input.runId) &&
      soundReceipt(receipt),
  );
  const receiptCovers = required.every((stream) =>
    receipts.some((receipt) => receipt.stream === stream),
  );
  const status = input.status;
  const statusCovers =
    input.mode === "receipt_or_status" &&
    status !== null &&
    status.runId === input.runId &&
    status.state === "published" &&
    required.every((stream) =>
      status.streams.some(
        (entry) => entry.name === stream && entry.state === "published",
      ),
    );
  if (!receiptCovers && !statusCovers)
    return refuse(receipts.length > 0 ? "streams_uncovered" : "no_receipt");
  let connectionId: string | null = null;
  if (receiptCovers) {
    const ids = new Set(receipts.map((receipt) => receipt.connectionId));
    if (ids.size !== 1) return refuse("connection_mismatch");
    connectionId = [...ids][0]!;
  }
  if (input.liveConnections === null) {
    if (input.mode === "strict_receipt") return refuse("connection_unknown");
  } else if (
    input.liveConnections.length !== 1 ||
    (connectionId !== null && input.liveConnections[0] !== connectionId)
  ) {
    return refuse("connection_mismatch");
  }
  if (input.control?.kind !== "active") return refuse("not_active");
  return {
    saved: true,
    proof: receiptCovers ? "receipt" : "status",
    connectionId,
  };
}
