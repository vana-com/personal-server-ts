/**
 * Run spool (§2.6): 256 shard files per stream, keyed by the first pkHash
 * byte. A spool line is `<pkHash> <canonical line>\n`. The byte count of a
 * shard counts each canonical line plus its terminator, the same measure as
 * part bytes, so the planner can sum shard counts as run bytes.
 *
 * Appends are buffered and flushed in bounded batches, so intake memory does
 * not grow with the stream. A flush is not durable: the caller syncs the
 * spool directory once, when intake ends (`StreamSyncFiles.sync`).
 */

import {
  BucketReducer,
  SHARD_COUNT,
  type Line,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { StreamSyncFiles } from "./ports.js";

const encoder = new TextEncoder();
const FLUSH_BYTES = 8 * 1024 * 1024;

export function shardName(shard: number): string {
  return shard.toString(16).padStart(2, "0");
}

export function shardPath(dir: string, shard: number): string {
  return `${dir}/${shardName(shard)}`;
}

export function emptyShardBytes(): number[] {
  return new Array<number>(SHARD_COUNT).fill(0);
}

/** Buffered appender for the spool shards of one directory. */
export class SpoolWriter {
  private readonly buffers = new Map<string, string[]>();
  private buffered = 0;

  constructor(private readonly files: StreamSyncFiles) {}

  /** Queue one line. `bytes` is the canonical line's UTF-8 length. */
  async add(
    dir: string,
    shard: number,
    pkHash: string,
    text: string,
    bytes: number,
  ): Promise<void> {
    const path = shardPath(dir, shard);
    let buffer = this.buffers.get(path);
    if (!buffer) {
      buffer = [];
      this.buffers.set(path, buffer);
    }
    buffer.push(`${pkHash} ${text}\n`);
    this.buffered += bytes + 66;
    if (this.buffered >= FLUSH_BYTES) await this.flush();
  }

  async flush(): Promise<void> {
    const pending = [...this.buffers.entries()];
    this.buffers.clear();
    this.buffered = 0;
    await this.files.appendMany(
      pending.map(([path, lines]) => ({
        path,
        bytes: encoder.encode(lines.join("")),
      })),
    );
  }
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
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let rest = "";
  for await (const chunk of files.readChunks(path)) {
    rest += decoder.decode(chunk, { stream: true });
    let newline = rest.indexOf("\n");
    let start = 0;
    while (newline !== -1) {
      yield parseSpoolLine(rest.slice(start, newline));
      start = newline + 1;
      newline = rest.indexOf("\n", start);
    }
    rest = rest.slice(start);
  }
  rest += decoder.decode();
  if (rest !== "") throw new Error(`spool file ${path} ends mid-line`);
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
