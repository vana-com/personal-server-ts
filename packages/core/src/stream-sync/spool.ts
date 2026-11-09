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
  utf8Length,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import type { StreamSyncFiles } from "./ports.js";

const encoder = new TextEncoder();
const textDecoder = new TextDecoder();

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

/**
 * A line written before format 2: `<k> <canonical {"o":..,"r":..,"v":BODY}>`
 * (a space at offset 64, not a TAB). A run that was durable and ready before
 * the upgrade holds such lines, and the upgrade must still publish and
 * overlay it. The envelope is derived from the line, as `frameOfLine` does
 * for a format-1 part. `size` keeps the old measure (line bytes + 1), the
 * one the persisted shard totals and the overlay log byte count were written
 * in, so those totals stay true. The planner tolerates the few bytes by which
 * this differs from the frame size.
 */
function parseLegacySpoolLine(line: string): SpoolEntry {
  const k = line.slice(0, 64);
  const text = line.slice(65);
  const at = text.indexOf(',"v":');
  if (at === -1 || !text.endsWith("}")) throw new Error("malformed spool line");
  const head = JSON.parse(text) as { o: number; r: string };
  const bodyText = text.slice(at + 5, -1);
  const body = encoder.encode(bodyText);
  const envelope: Envelope = {
    h: bytesToHex(sha256(body)),
    k,
    n: body.length,
    o: head.o,
    r: head.r,
  };
  return {
    envelope,
    size: encoder.encode(text).length + 1,
    line,
    body: { kind: "inline", text: bodyText },
  };
}

/** Parse one spool line (no terminator). Reads the legacy form too. */
export function parseSpoolLine(line: string): SpoolEntry {
  const first = line.indexOf("\t");
  if (first !== 64 && line.charCodeAt(64) === 0x20 && line.indexOf("\t") < 0) {
    return parseLegacySpoolLine(line);
  }
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
    this.buffered += utf8Length(line) + 1;
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
  for await (const entry of readSpool(files, spoolLogPath(dir))) {
    const shard = shardOf(entry.envelope.k);
    let buffer = buffers.get(shard);
    if (!buffer) {
      buffer = [];
      buffers.set(shard, buffer);
    }
    buffer.push(`${entry.line}\n`);
    buffered += utf8Length(entry.line) + 1;
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
  // Split on the newline byte, then decode each line on its own. Decoding the
  // whole chunk and slicing lines out of it would make every line a view that
  // pins its 1 MiB chunk for as long as any caller keeps the line's text.
  // 0x0a cannot occur inside a multi-byte UTF-8 sequence, so the split is safe.
  // The line still open at the end of the last chunk lives in one growable
  // buffer. Retained memory then tracks the line's size, not the number of
  // chunks it arrived in, and doubling keeps the copying linear. The line's
  // bytes are dropped before the parsed line is yielded, so a caller that
  // holds the line holds one copy of its text, not its bytes too.
  let open: OpenLine | null = null;
  let firstLine = true;
  for await (const chunk of files.readChunks(path)) {
    let start = 0;
    let newline = chunk.indexOf(0x0a, start);
    while (newline !== -1) {
      let raw: string;
      if (open === null) {
        raw = decoder.decode(chunk.subarray(start, newline));
      } else {
        open.append(chunk.subarray(start, newline));
        raw = decoder.decode(open.view());
        open = null;
      }
      if (firstLine && raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
      firstLine = false;
      yield parseSpoolLine(raw);
      start = newline + 1;
      newline = chunk.indexOf(0x0a, start);
    }
    if (start < chunk.length) {
      open ??= new OpenLine();
      open.append(chunk.subarray(start));
    }
  }
  if (open !== null && open.size > 0) {
    // A file that holds only a BOM has no lines, as the whole-file decoder gives.
    const rest = open.view();
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
 * Bytes of one spool line that has not reached its newline yet. Appends go
 * into one buffer that doubles when full, so a line in any number of chunks
 * is one allocation chain with at most twice its size in capacity.
 */
class OpenLine {
  private buffer = new Uint8Array(0);
  private length = 0;

  get size(): number {
    return this.length;
  }

  append(bytes: Uint8Array): void {
    const need = this.length + bytes.length;
    if (need > this.buffer.length) {
      const grown = new Uint8Array(
        Math.max(need, this.buffer.length * 2, 4096),
      );
      grown.set(this.buffer.subarray(0, this.length));
      this.buffer = grown;
    }
    this.buffer.set(bytes, this.length);
    this.length = need;
  }

  view(): Uint8Array {
    return this.buffer.subarray(0, this.length);
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
  flushBytes: number = FLUSH_BYTES,
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
  let bytes = 0;
  for (const w of result.winners) bytes += w.size;
  // Replace the shard without a durable write per file: the run is still
  // collecting, and its one `sync` follows the last compaction (§2.6). A stop
  // between the two calls fails the run, as any stop while collecting does.
  await files.remove(path);
  const writer = new SpoolWriter(files, flushBytes);
  for (const winner of result.winners) await writer.add(path, winner.ref);
  await writer.flush();
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
