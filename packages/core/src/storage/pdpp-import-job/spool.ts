/**
 * Pumps an immutable spool into an open job in byte-bounded batches, from
 * the job's durable offset. Never holds more than one batch (or one record
 * up to `IMPORT_JOB_MAX_RECORD_BYTES`) of the spool.
 */

import {
  IMPORT_JOB_MAX_RECORD_BYTES,
  ImportJobError,
  type ImportBatchReceipt,
  type ImportJobStatus,
  type ImportSpoolHandle,
  type PdppImportJobs,
} from "./contract.js";
import { sha256HexOf } from "./engine.js";

export type ImportSpoolRead = (
  spool: ImportSpoolHandle,
  offset: number,
  maxBytes: number,
) => Promise<Uint8Array>;

const NEWLINE = 0x0a;
const decoder = new TextDecoder("utf-8", { fatal: true });

/** Appends every remaining batch of the job's spool. Returns the final status. */
export async function importSpool(
  jobs: PdppImportJobs,
  jobId: string,
  read: ImportSpoolRead,
  options: {
    onBatch?: (receipt: ImportBatchReceipt) => void;
    maxRecordBytes?: number;
  } = {},
): Promise<ImportJobStatus> {
  const maxRecordBytes = options.maxRecordBytes ?? IMPORT_JOB_MAX_RECORD_BYTES;
  let current = await jobs.status(jobId);
  if (!current.resume) return current;
  const { spool, batchBytes } = current.job;
  let { seq, spoolOffset: offset } = current.resume;
  while (offset < spool.byteLength) {
    const remaining = spool.byteLength - offset;
    let chunk = await read(spool, offset, Math.min(batchBytes, remaining));
    if (chunk.byteLength === 0)
      throw new ImportJobError(
        "invalid_request",
        "spool ended before its byteLength",
      );
    const end = chunk.lastIndexOf(NEWLINE);
    if (end >= 0) {
      chunk = chunk.subarray(0, end + 1);
    } else if (offset + chunk.byteLength < spool.byteLength) {
      // One record larger than the batch budget: read it alone, bounded.
      const window = await read(
        spool,
        offset,
        Math.min(maxRecordBytes + 1, remaining),
      );
      const lineEnd = window.indexOf(NEWLINE);
      const length =
        lineEnd >= 0
          ? lineEnd + 1
          : offset + window.byteLength === spool.byteLength
            ? window.byteLength
            : -1;
      if (length < 0 || length > maxRecordBytes)
        throw new ImportJobError(
          "record_too_large",
          `a spool record at byte ${offset} exceeds ${maxRecordBytes} bytes`,
        );
      chunk = window.subarray(0, length);
    }
    let text: string;
    try {
      text = decoder.decode(chunk);
    } catch {
      throw new ImportJobError(
        "invalid_request",
        `spool bytes at ${offset} are not UTF-8`,
      );
    }
    const receipt = await jobs.append({
      jobId,
      seq,
      text,
      sha256: await sha256HexOf(chunk),
      spoolStart: offset,
      spoolEnd: offset + chunk.byteLength,
    });
    options.onBatch?.(receipt);
    offset += chunk.byteLength;
    seq += 1;
  }
  current = await jobs.status(jobId);
  return current;
}
