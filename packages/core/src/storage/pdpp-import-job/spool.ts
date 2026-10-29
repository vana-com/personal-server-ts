/**
 * Pumps a spool into an open job in byte-bounded batches, from the job's
 * durable offset. Never holds more than one batch (or one record up to
 * `IMPORT_JOB_MAX_RECORD_BYTES`) of the spool.
 *
 * An open spool (`ImportOpenSpoolHandle`) needs `available` or `seal`:
 * - `available`: the bytes the host has written so far. Only full batches go
 *   in, each followed by at least one written byte, so the cuts equal those of
 *   the sealed spool and the batch that ends the spool is still to come.
 * - `seal`: the host wrote the last byte. The rest goes in; its last batch
 *   carries the seal.
 */

import {
  IMPORT_JOB_MAX_RECORD_BYTES,
  ImportJobError,
  sealedSpool,
  type ImportBatchReceipt,
  type ImportJobStatus,
  type ImportOpenSpoolHandle,
  type ImportSpoolHandle,
  type ImportSpoolSeal,
  type PdppImportJobs,
} from "./contract.js";
import { sha256HexOf } from "./engine.js";

export type ImportSpoolRead = (
  spool: ImportSpoolHandle | ImportOpenSpoolHandle,
  offset: number,
  maxBytes: number,
) => Promise<Uint8Array>;

const NEWLINE = 0x0a;
const decoder = new TextDecoder("utf-8", { fatal: true });

/** Appends every batch the spool holds now. Returns the final status. */
export async function importSpool(
  jobs: PdppImportJobs,
  jobId: string,
  read: ImportSpoolRead,
  options: {
    onBatch?: (receipt: ImportBatchReceipt) => void;
    maxRecordBytes?: number;
    /** Open spool only: bytes written so far. */
    available?: number;
    /** Open spool only: the length and digest of the finished spool. */
    seal?: ImportSpoolSeal;
  } = {},
): Promise<ImportJobStatus> {
  const maxRecordBytes = options.maxRecordBytes ?? IMPORT_JOB_MAX_RECORD_BYTES;
  let current = await jobs.status(jobId);
  if (!current.resume) return current;
  const { spool, batchBytes } = current.job;
  const sealed = sealedSpool(spool);
  if (
    sealed &&
    options.seal &&
    (options.seal.byteLength !== sealed.byteLength ||
      options.seal.sha256 !== sealed.sha256)
  )
    throw new ImportJobError(
      "invalid_request",
      "seal differs from the job's spool",
    );
  const seal = sealed ? undefined : options.seal;
  // Bytes known to be written, and whether they are the whole spool.
  const end = sealed?.byteLength ?? seal?.byteLength ?? options.available;
  if (end === undefined)
    throw new ImportJobError(
      "invalid_request",
      "an open spool needs `available` or `seal`",
    );
  const final = sealed !== undefined || seal !== undefined;
  let { seq, spoolOffset: offset } = current.resume;
  while (offset < end) {
    const remaining = end - offset;
    // A growing spool waits for more than one batch, so the cut is the one a
    // sealed spool gets and written bytes follow it.
    if (!final && remaining <= batchBytes) break;
    let chunk = await read(spool, offset, Math.min(batchBytes, remaining));
    if (chunk.byteLength === 0)
      throw new ImportJobError(
        "invalid_request",
        "spool ended before its byteLength",
      );
    const newline = chunk.lastIndexOf(NEWLINE);
    if (newline >= 0) {
      chunk = chunk.subarray(0, newline + 1);
    } else if (!final || offset + chunk.byteLength < end) {
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
          : final && offset + window.byteLength === end
            ? window.byteLength
            : -1;
      // Its end is not written yet.
      if (
        !final &&
        (length < 0 ? remaining <= maxRecordBytes : offset + length >= end)
      )
        break;
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
    const spoolEnd = offset + chunk.byteLength;
    const receipt = await jobs.append({
      jobId,
      seq,
      text,
      sha256: await sha256HexOf(chunk),
      spoolStart: offset,
      spoolEnd,
      ...(seal && spoolEnd === end ? { seal } : {}),
    });
    options.onBatch?.(receipt);
    offset = spoolEnd;
    seq += 1;
  }
  current = await jobs.status(jobId);
  return current;
}
