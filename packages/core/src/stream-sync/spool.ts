/**
 * Run spool (§2.6). A spool line is `<pkHash> <canonical line>\n`.
 *
 * Intake appends every line of a stream to one intake log, `<dir>.log`, in
 * bounded batches, so intake memory does not grow with the stream. The log
 * is the durable copy: the caller syncs it once, when intake ends
 * (`StreamSyncFiles.sync`). One file per stream means one fsync per stream,
 * not one per shard.
 *
 * The 256 shard files of `<dir>/<hh>`, keyed by the first pkHash byte, are
 * derived from the log (`deriveShards`) when a run is planned. They are
 * never synced and can be derived again at any time. The byte count of a
 * shard counts each canonical line plus its terminator, the same measure as
 * part bytes, so the planner can sum shard counts as run bytes.
 */

import {
  BucketReducer,
  SHARD_COUNT,
  shardOf,
  utf8Length,
  type Line,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { StreamSyncFiles } from "./ports.js";

const encoder = new TextEncoder();

/**
 * The UTF-8 bytes of `lines` in one buffer. Joining them first would hold the
 * joined string and its encoding at once, twice the flush size.
 */
function encodeLines(lines: readonly string[]): Uint8Array {
  let total = 0;
  for (const line of lines) total += utf8Length(line);
  const out = new Uint8Array(total);
  let at = 0;
  for (const line of lines)
    at += encoder.encodeInto(line, out.subarray(at)).written;
  return out;
}
/** Default spool flush threshold: buffered lines written per append batch. */
export const FLUSH_BYTES = 8 * 1024 * 1024;

export function shardName(shard: number): string {
  return shard.toString(16).padStart(2, "0");
}

export function shardPath(dir: string, shard: number): string {
  return `${dir}/${shardName(shard)}`;
}

/** The durable intake log of the spool whose shards live under `dir`. */
export function spoolLogPath(dir: string): string {
  return `${dir}.log`;
}

export function emptyShardBytes(): number[] {
  return new Array<number>(SHARD_COUNT).fill(0);
}

/** Buffered appender for the intake logs of a run. */
export class SpoolWriter {
  private readonly buffers = new Map<string, string[]>();
  private buffered = 0;
  private failure: unknown = null;

  constructor(
    private readonly files: StreamSyncFiles,
    private readonly flushBytes: number = FLUSH_BYTES,
  ) {}

  /** Queue one line. `bytes` is the canonical line's UTF-8 length. */
  async add(
    logPath: string,
    pkHash: string,
    text: string,
    bytes: number,
  ): Promise<void> {
    let buffer = this.buffers.get(logPath);
    if (!buffer) {
      buffer = [];
      this.buffers.set(logPath, buffer);
    }
    buffer.push(`${pkHash} ${text}\n`);
    this.buffered += bytes + 66;
    if (this.buffered >= this.flushBytes) await this.flush();
  }

  /** Drop every buffered line without writing it. */
  clear(): void {
    this.buffers.clear();
    this.buffered = 0;
  }

  /**
   * Append the buffered lines. The buffers are taken before the append, so a
   * failed append has lost lines. Every later flush then fails too, and the
   * run cannot end as if its log were whole.
   */
  async flush(): Promise<void> {
    if (this.failure) throw this.failure;
    const pending = [...this.buffers.entries()];
    this.buffers.clear();
    this.buffered = 0;
    try {
      await this.files.appendMany(
        pending.map(([path, lines]) => ({
          path,
          bytes: encodeLines(lines),
        })),
      );
    } catch (error) {
      this.failure = error;
      throw error;
    }
  }
}

/**
 * Write the 256 shard files of `dir` from the intake log, in log order, so a
 * later line stays later. Replaces what is there. Memory is one flush batch.
 */
export async function deriveShards(
  files: StreamSyncFiles,
  dir: string,
  flushBytes: number = FLUSH_BYTES,
): Promise<void> {
  await files.remove(dir);
  const buffers = new Map<number, string[]>();
  let buffered = 0;
  const flush = async () => {
    const pending = [...buffers.entries()];
    buffers.clear();
    buffered = 0;
    await files.appendMany(
      pending.map(([shard, lines]) => ({
        path: shardPath(dir, shard),
        bytes: encodeLines(lines),
      })),
    );
  };
  for await (const line of readSpool(files, spoolLogPath(dir))) {
    const shard = shardOf(line.pkHash);
    let buffer = buffers.get(shard);
    if (!buffer) {
      buffer = [];
      buffers.set(shard, buffer);
    }
    buffer.push(`${line.pkHash} ${line.text}\n`);
    buffered += line.text.length + 66;
    if (buffered >= flushBytes) await flush();
  }
  await flush();
}

export interface SpoolLine {
  readonly pkHash: string;
  /** Canonical line text, no terminator. */
  readonly text: string;
}

/** The lines of one spool shard file, in file order. */
export async function* readSpool(
  files: StreamSyncFiles,
  path: string,
): AsyncGenerator<SpoolLine> {
  // ignoreBOM keeps a U+FEFF in the decoded text. A decoder strips a BOM at the
  // start of every decode call, so a per-line decode would strip one from every
  // line. The whole-file decoder strips only the file's first BOM; match that.
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  // Split on the newline byte, then decode each line on its own. Decoding the
  // whole chunk and slicing lines out of it would make every line a view that
  // pins its 1 MiB chunk for as long as any caller keeps the line's text.
  // 0x0a cannot occur inside a multi-byte UTF-8 sequence, so the split is safe.
  let rest = new Uint8Array(0);
  let firstLine = true;
  for await (const chunk of files.readChunks(path)) {
    const bytes = new Uint8Array(rest.length + chunk.length);
    bytes.set(rest);
    bytes.set(chunk, rest.length);
    let start = 0;
    let newline = bytes.indexOf(0x0a, start);
    while (newline !== -1) {
      let raw = decoder.decode(bytes.subarray(start, newline));
      if (firstLine && raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
      firstLine = false;
      yield parseSpoolLine(raw);
      start = newline + 1;
      newline = bytes.indexOf(0x0a, start);
    }
    rest = bytes.slice(start);
  }
  if (rest.length !== 0) {
    // A file that holds only a BOM has no lines, as the whole-file decoder gives.
    const bomOnly =
      firstLine &&
      rest.length === 3 &&
      rest[0] === 0xef &&
      rest[1] === 0xbb &&
      rest[2] === 0xbf;
    if (bomOnly) return;
    throw new Error(`spool file ${path} ends mid-line`);
  }
}

function parseSpoolLine(raw: string): SpoolLine {
  const space = raw.indexOf(" ");
  if (space !== 64) throw new Error("malformed spool line");
  return { pkHash: raw.slice(0, 64), text: raw.slice(65) };
}

const STAMP = /^\{"o":(\d+),"r":("(?:[^"\\]|\\.)*"),"v":/;

/**
 * The `(o, r)` stamp of a canonical line, read from its fixed prefix so the
 * record itself is not parsed. The reducer compares stamps only.
 */
export function lineStamp(text: string): Line {
  const match = STAMP.exec(text);
  if (!match) throw new Error("spool line is not a canonical line");
  return {
    o: Number(match[1]),
    r: JSON.parse(match[2]!) as string,
    v: {},
  };
}

/**
 * Rewrite one shard with its winning lines only, so the planner's estimate
 * stops counting repeated keys. The reduce uses the package reducer. It
 * gives up and keeps the shard as it is once the winners would pass
 * `budgetBytes`, so compaction memory stays bounded.
 *
 * Returns the new byte count, or `null` when the shard was kept.
 */
export async function compactShard(
  files: StreamSyncFiles,
  path: string,
  shard: number,
  budgetBytes: number,
): Promise<number | null> {
  const prefix = shard.toString(2).padStart(8, "0");
  const reducer = new BucketReducer(prefix);
  let seenBytes = 0;
  let seenLines = 0;
  for await (const line of readSpool(files, path)) {
    seenLines += 1;
    seenBytes += line.text.length + 1;
    reducer.add(line.pkHash, lineStamp(line.text), line.text);
    // Average line size times distinct keys: an estimate of winner bytes.
    if ((reducer.size * seenBytes) / seenLines > budgetBytes) return null;
  }
  const result = reducer.finish(Number.MAX_SAFE_INTEGER);
  if (result.kind !== "ok") return null;
  if (result.winners.length === seenLines) return null;
  const text = result.winners.map((w) => `${w.pkHash} ${w.text}\n`).join("");
  // Replace the shard without a durable write per file: the run is still
  // collecting, and its one `sync` follows the last compaction (§2.6). A stop
  // between the two calls fails the run, as any stop while collecting does.
  await files.remove(path);
  await files.appendMany([{ path, bytes: encoder.encode(text) }]);
  return result.bytes;
}

/** Bytes per second pkHash byte for one shard: the planner's counting pass. */
export async function countShard(
  files: StreamSyncFiles,
  paths: readonly string[],
): Promise<number[]> {
  const counts = emptyShardBytes();
  for (const path of paths) {
    for await (const line of readSpool(files, path)) {
      const second = parseInt(line.pkHash.slice(2, 4), 16);
      counts[second]! += encoder.encode(line.text).length + 1;
    }
  }
  return counts;
}
