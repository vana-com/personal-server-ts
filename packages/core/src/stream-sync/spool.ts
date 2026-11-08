/**
 * Run spool (§2.6). A spool line is `<k>\t<envelope>\t<body>\n`: the key hash,
 * the frame's canonical envelope, and then either the body itself (canonical
 * JSON) or `@<path>`, the file that holds a body too long to keep on a line.
 * Canonical JSON escapes control characters, so neither the TAB nor the LF
 * can occur inside an envelope or a body.
 *
 * Intake appends every line of a stream to one intake log, `<dir>.log`, in
 * bounded batches, so intake memory does not grow with the stream. The log
 * is the durable copy: the caller syncs it once, when intake ends
 * (`StreamSyncFiles.sync`). One file per stream means one fsync per stream,
 * not one per shard.
 *
 * The 256 shard files of `<dir>/<hh>`, keyed by the first key-hash byte, are
 * derived from the log (`deriveShards`) when a run is planned. They are
 * never synced and can be derived again at any time. The byte count of a
 * shard counts each frame (envelope, body and their two terminators), the
 * same measure as part bytes, so the planner can sum shard counts as run
 * bytes. A body file stays where intake wrote it; shards copy the line, not
 * the body.
 */

import {
  decodeEnvelope,
  encodeEnvelope,
  frameBytes,
  FrameReducer,
  SHARD_COUNT,
  shardOf,
  type Envelope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { StreamSyncFiles } from "./ports.js";

const encoder = new TextEncoder();
const textDecoder = new TextDecoder();
/** Default spool flush threshold: buffered lines written per append batch. */
export const FLUSH_BYTES = 8 * 1024 * 1024;
/** A body longer than this goes to its own file instead of onto its line. */
export const INLINE_BODY_BYTES = 1024 * 1024;

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

/** Directory of the body files of the spool whose shards live under `dir`. */
export function spoolBodyDir(dir: string): string {
  return `${dir}.bodies`;
}

export function emptyShardBytes(): number[] {
  return new Array<number>(SHARD_COUNT).fill(0);
}

/** One spool line, parsed. A body kept in a file is not read. */
export interface SpoolEntry {
  readonly envelope: Envelope;
  /** Frame size: envelope, LF, body, LF. */
  readonly size: number;
  /** The raw line without its terminator, for copying between files. */
  readonly line: string;
  readonly body:
    | { readonly kind: "inline"; readonly text: string }
    | { readonly kind: "file"; readonly path: string };
}

function envelopeText(envelope: Envelope): string {
  return textDecoder.decode(encodeEnvelope(envelope));
}

/** The spool line of a frame whose body is held on the line. */
export function inlineSpoolLine(envelope: Envelope, bodyText: string): string {
  return `${envelope.k}\t${envelopeText(envelope)}\t${bodyText}`;
}

/** The spool line of a frame whose body is in the file at `path`. */
export function fileSpoolLine(envelope: Envelope, path: string): string {
  return `${envelope.k}\t${envelopeText(envelope)}\t@${path}`;
}

/** Parse one spool line (no terminator). */
export function parseSpoolLine(line: string): SpoolEntry {
  const first = line.indexOf("\t");
  const second = line.indexOf("\t", first + 1);
  if (first !== 64 || second === -1) throw new Error("malformed spool line");
  const envelope = decodeEnvelope(
    encoder.encode(line.slice(first + 1, second)),
  );
  if (envelope.k !== line.slice(0, 64)) {
    throw new Error("spool line key does not match its envelope");
  }
  const rest = line.slice(second + 1);
  return {
    envelope,
    size: frameBytes(envelope),
    line,
    body: rest.startsWith("@")
      ? { kind: "file", path: rest.slice(1) }
      : { kind: "inline", text: rest },
  };
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

  /** Queue one spool line (no terminator). */
  async add(logPath: string, line: string): Promise<void> {
    let buffer = this.buffers.get(logPath);
    if (!buffer) {
      buffer = [];
      this.buffers.set(logPath, buffer);
    }
    buffer.push(`${line}\n`);
    this.buffered += line.length + 1;
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
          bytes: encoder.encode(lines.join("")),
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
        bytes: encoder.encode(lines.join("")),
      })),
    );
  };
  for await (const entry of readSpool(files, spoolLogPath(dir))) {
    const shard = shardOf(entry.envelope.k);
    let buffer = buffers.get(shard);
    if (!buffer) {
      buffer = [];
      buffers.set(shard, buffer);
    }
    buffer.push(`${entry.line}\n`);
    buffered += entry.line.length + 1;
    if (buffered >= flushBytes) await flush();
  }
  await flush();
}

/** The entries of one spool file, in file order. */
export async function* readSpool(
  files: StreamSyncFiles,
  path: string,
): AsyncGenerator<SpoolEntry> {
  // ignoreBOM keeps a U+FEFF in the decoded text. A decoder strips a BOM at the
  // start of every decode call, so a per-line decode would strip one from every
  // line. The whole-file decoder strips only the file's first BOM; match that.
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  // Split on the newline byte, then decode each line on its own. A line is at
  // most `INLINE_BODY_BYTES` plus an envelope, because a longer body lives in
  // a file. 0x0a cannot occur inside a multi-byte UTF-8 sequence.
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

/**
 * Rewrite one shard with its winning lines only, so the planner's estimate
 * stops counting repeated keys. The reduce uses the package reducer, which
 * reads envelopes only. It gives up and keeps the shard as it is once the
 * winners' lines would pass `budgetBytes`, so compaction memory stays
 * bounded.
 *
 * Returns the new byte count (frame bytes), or `null` when the shard was kept.
 */
export async function compactShard(
  files: StreamSyncFiles,
  path: string,
  shard: number,
  budgetBytes: number,
): Promise<number | null> {
  const prefix = shard.toString(2).padStart(8, "0");
  const reducer = new FrameReducer<string>(prefix);
  let seenChars = 0;
  let seenLines = 0;
  for await (const entry of readSpool(files, path)) {
    seenLines += 1;
    seenChars += entry.line.length + 1;
    reducer.add({
      k: entry.envelope.k,
      o: entry.envelope.o,
      r: entry.envelope.r,
      size: entry.size,
      held: true,
      ref: entry.line,
    });
    // Average line size times distinct keys: an estimate of winner bytes.
    if ((reducer.size * seenChars) / seenLines > budgetBytes) return null;
  }
  const result = reducer.finish(Number.MAX_SAFE_INTEGER);
  if (result.kind !== "ok") return null;
  if (result.winners.length === seenLines) return null;
  const text = result.winners.map((w) => `${w.ref}\n`).join("");
  let bytes = 0;
  for (const w of result.winners) bytes += w.size;
  // Replace the shard without a durable write per file: the run is still
  // collecting, and its one `sync` follows the last compaction (§2.6). A stop
  // between the two calls fails the run, as any stop while collecting does.
  await files.remove(path);
  await files.appendMany([{ path, bytes: encoder.encode(text) }]);
  return bytes;
}

/** Bytes per second key-hash byte for one shard: the planner's counting pass. */
export async function countShard(
  files: StreamSyncFiles,
  paths: readonly string[],
): Promise<number[]> {
  const counts = emptyShardBytes();
  for (const path of paths) {
    for await (const entry of readSpool(files, path)) {
      const second = parseInt(entry.envelope.k.slice(2, 4), 16);
      counts[second]! += entry.size;
    }
  }
  return counts;
}
