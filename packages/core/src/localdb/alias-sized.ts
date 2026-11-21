import type { AliasViewCheck } from "./alias-view.js";
import { PartialViewMoved } from "./partial-read.js";
import type { AliasRecordQuery, SizedRecord, StoredRecord } from "./query.js";

/**
 * Stored bytes of bodies read in one batch when the whole stream is held
 * anyway (its memory reserved as a whole): a parent stream, an other stream or
 * a whole projection. The batch only bounds the statement's result.
 */
export const WHOLE_STREAM_BATCH_BYTES = 1024 * 1024;

/** What a read sized a stream at, and so reserved memory for. */
export interface StreamLimits {
  readonly rows: number;
  readonly bytes: number;
  readonly maxBytes: number;
}

/** A body and the size and hash it was read against. */
export interface SizedBody {
  readonly record: StoredRecord;
  readonly sized: SizedRecord;
}

/**
 * Read every body of a stream, a batch at a time, each batch of at most
 * `batchBytes` sized bytes (one record, if that is larger). Each batch is
 * read by a statement that returns a record only while it still has the hash
 * and size it was sized with, so no batch takes more bytes than its sizes add
 * up to. The whole read stays inside `limits`, the sizes the memory was
 * reserved for.
 *
 * A record that is missing, changed or grown, or a stream that is larger than
 * `limits`, means the rows are not those the read reserved memory for:
 * `PartialViewMoved`, the read to be asked again. Nothing in it depends on the
 * change marks, so it holds whatever the marks say.
 */
export async function* sizedBodies(
  query: AliasRecordQuery,
  connectionId: string,
  stream: string,
  limits: StreamLimits,
  batchBytes: number,
  current: AliasViewCheck,
): AsyncGenerator<SizedBody[]> {
  let batch: SizedRecord[] = [];
  let batchSize = 0;
  let rows = 0;
  let bytes = 0;
  const flush = async (): Promise<SizedBody[]> => {
    const records = await query.recordsByHash(
      connectionId,
      stream,
      batch,
      current.guard,
    );
    if (records.length !== batch.length) throw new PartialViewMoved();
    const sizes = new Map(batch.map((s) => [s.pkHash, s]));
    batch = [];
    batchSize = 0;
    return records.map((record) => ({
      record,
      sized: sizes.get(record.pkHash)!,
    }));
  };
  for await (const size of query.recordSizes(connectionId, stream)) {
    rows += 1;
    bytes += size.bytes;
    if (
      rows > limits.rows ||
      bytes > limits.bytes ||
      size.bytes > limits.maxBytes
    ) {
      throw new PartialViewMoved();
    }
    if (batch.length > 0 && batchSize + size.bytes > batchBytes) {
      yield await flush();
    }
    batch.push(size);
    batchSize += size.bytes;
  }
  if (batch.length > 0) yield await flush();
}
