/**
 * Turn one record into a spool line (and, for a long body, a body file)
 * without ever holding the record as one string or one buffer.
 *
 * The envelope leads with the body's hash and length, so the body is
 * serialized in pieces and hashed on the way. A body that stays within
 * `INLINE_BODY_BYTES` is kept while it is hashed and goes onto its line. A
 * longer one is hashed and dropped, then serialized a second time straight
 * into its file. Peak memory is the record object the caller holds plus one
 * piece (about 100 KiB), whatever the record size.
 */

import {
  canonicalJsonChunks,
  frameBytes,
  toHex,
  type Envelope,
  type Sha256StreamFactory,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { StreamSyncFiles } from "./ports.js";
import {
  fileSpoolLine,
  INLINE_BODY_BYTES,
  inlineSpoolLine,
  type SpoolWriter,
} from "./spool.js";

const encoder = new TextEncoder();
/** Bytes buffered before a body file is appended to. */
const FILE_BATCH_BYTES = 1024 * 1024;

export interface RecordTarget {
  readonly files: StreamSyncFiles;
  readonly spool: SpoolWriter;
  readonly makeSha256: Sha256StreamFactory;
}

export interface SpooledRecord {
  readonly envelope: Envelope;
  /** Frame size: envelope, LF, body, LF. */
  readonly size: number;
}

/**
 * Spool one record under `logPath`. `bodyPath` names the file for a long
 * body (the caller makes it unique). The record must be a JSON object that
 * holds the key fields `k` was computed from.
 */
export async function spoolRecord(
  target: RecordTarget,
  logPath: string,
  bodyPath: () => string,
  stamp: { readonly k: string; readonly o: number; readonly r: string },
  record: unknown,
): Promise<SpooledRecord> {
  const hash = target.makeSha256();
  let n = 0;
  let kept: string[] | null = [];
  for (const text of canonicalJsonChunks(record)) {
    const bytes = encoder.encode(text);
    hash.update(bytes);
    n += bytes.length;
    if (kept !== null) {
      if (n <= INLINE_BODY_BYTES) kept.push(text);
      else kept = null;
    }
  }
  const envelope: Envelope = { h: toHex(hash.digest()), n, ...stamp };
  const size = frameBytes(envelope);
  if (kept !== null) {
    await target.spool.add(logPath, inlineSpoolLine(envelope, kept.join("")));
    return { envelope, size };
  }
  const path = bodyPath();
  let batch: Uint8Array[] = [];
  let batched = 0;
  const flush = async () => {
    if (batched === 0) return;
    const out = new Uint8Array(batched);
    let at = 0;
    for (const piece of batch) {
      out.set(piece, at);
      at += piece.length;
    }
    batch = [];
    batched = 0;
    await target.files.appendMany([{ path, bytes: out }]);
  };
  for (const text of canonicalJsonChunks(record)) {
    const bytes = encoder.encode(text);
    batch.push(bytes);
    batched += bytes.length;
    if (batched >= FILE_BATCH_BYTES) await flush();
  }
  await flush();
  await target.spool.add(logPath, fileSpoolLine(envelope, path));
  return { envelope, size };
}
