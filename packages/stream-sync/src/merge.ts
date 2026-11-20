/**
 * §2.6 merge rule and winner-only reduce.
 *
 * Per primary key, the greatest `(o, r)` wins: `o` by number, then `r` by
 * UTF-16 code unit. On equal `(o, r)` the later line wins, so a host feeds a
 * bucket's base part lines first and the run's spool lines after them, each
 * in file order.
 *
 * The reducer keeps one winning line per key, so memory scales with the
 * distinct keys of the bucket, not with the versions fed to it.
 */

import { PART_LIMIT_BYTES, PLANNER_DEPTH_CAP, utf8Length } from "./bytes.js";
import { InvalidArgumentError } from "./errors.js";
import { encodeLine, inPrefix, type Line } from "./records.js";

export interface Stamp {
  readonly o: number;
  readonly r: string;
}

/** Negative when `a` is older than `b`, 0 when equal, positive when newer. */
export function compareStamp(a: Stamp, b: Stamp): number {
  if (a.o !== b.o) return a.o < b.o ? -1 : 1;
  if (a.r === b.r) return 0;
  return a.r < b.r ? -1 : 1;
}

export interface Winner {
  readonly pkHash: string;
  /** Canonical line text, no terminator. */
  readonly text: string;
}

export type BucketResult =
  | {
      readonly kind: "ok";
      readonly prefix: string;
      /** Winners sorted by pkHash, ready for `encodePart`. */
      readonly winners: readonly Winner[];
      /** Part size: sum of line bytes plus one `\n` per line. */
      readonly bytes: number;
    }
  /**
   * Ruling Q4: winners over the limit in a bucket shallower than the 16-bit
   * cap. The estimate was wrong; the host re-plans: it splits the bucket by
   * the next bit (`prefix + "0"`, `prefix + "1"`, with the counting pass when
   * the children are deeper than 8 bits) and reduces each child again.
   */
  | {
      readonly kind: "split";
      readonly prefix: string;
      readonly bytes: number;
    }
  /** Winners over the limit at the 16-bit cap: the stream cannot publish. */
  | {
      readonly kind: "bucket_too_large";
      readonly prefix: string;
      readonly bytes: number;
    };

interface Slot {
  o: number;
  r: string;
  text: string;
}

export class BucketReducer {
  readonly prefix: string;
  private readonly winners = new Map<string, Slot>();

  constructor(prefix: string) {
    if (!/^[01]*$/.test(prefix)) {
      throw new InvalidArgumentError("prefix must be a string of 0 and 1");
    }
    this.prefix = prefix;
  }

  /**
   * Feed one line. `text` is the line's canonical text when the host already
   * has it (it was read from a part or spool); otherwise it is encoded here.
   */
  add(pkHash: string, line: Line, text?: string): void {
    if (!inPrefix(pkHash, this.prefix)) {
      throw new InvalidArgumentError(
        `key ${pkHash} is outside bucket "${this.prefix}"`,
      );
    }
    const current = this.winners.get(pkHash);
    if (current && compareStamp(line, current) < 0) return;
    this.winners.set(pkHash, {
      o: line.o,
      r: line.r,
      text: text ?? encodeLine(line),
    });
  }

  get size(): number {
    return this.winners.size;
  }

  /**
   * Winners sorted by pkHash. Over `limitBytes`: `split` below the 16-bit cap
   * (ruling Q4), `bucket_too_large` only at the cap.
   */
  finish(limitBytes: number = PART_LIMIT_BYTES): BucketResult {
    const keys = [...this.winners.keys()].sort();
    let bytes = 0;
    const winners: Winner[] = [];
    for (const pkHash of keys) {
      const text = this.winners.get(pkHash)!.text;
      bytes += utf8Length(text) + 1;
      winners.push({ pkHash, text });
    }
    if (bytes > limitBytes) {
      return this.prefix.length < PLANNER_DEPTH_CAP
        ? { kind: "split", prefix: this.prefix, bytes }
        : { kind: "bucket_too_large", prefix: this.prefix, bytes };
    }
    return { kind: "ok", prefix: this.prefix, winners, bytes };
  }
}

/** Merge whole line lists in memory: base first, then run (tests, vectors, small streams). */
export function mergeLines(
  entries: readonly { readonly pkHash: string; readonly line: Line }[],
  prefix = "",
  limitBytes: number = PART_LIMIT_BYTES,
): BucketResult {
  const reducer = new BucketReducer(prefix);
  for (const entry of entries) reducer.add(entry.pkHash, entry.line);
  return reducer.finish(limitBytes);
}

/**
 * A frame that won its key, with where its bytes are. The reducer never
 * reads `ref`: the host decides what it points at (frame bytes held in
 * memory, a run of base parts, a spool body file).
 */
export interface FrameWinner<Ref> {
  readonly k: string;
  readonly o: number;
  readonly r: string;
  /** Frame size: envelope, LF, body, LF. */
  readonly size: number;
  /** True when the host keeps the frame's bytes in memory; only these count toward the split. */
  readonly held: boolean;
  readonly ref: Ref;
}

export type FrameBucketResult<Ref> =
  | {
      readonly kind: "ok";
      readonly prefix: string;
      /** Winners sorted by key hash. */
      readonly winners: readonly FrameWinner<Ref>[];
      /** Bytes of the small winners, which a writer holds in memory. */
      readonly smallBytes: number;
    }
  | {
      readonly kind: "split";
      readonly prefix: string;
      readonly smallBytes: number;
    }
  | {
      readonly kind: "bucket_too_large";
      readonly prefix: string;
      readonly smallBytes: number;
    };

/**
 * The §2.6 merge over envelopes. Per key the greatest `(o, r)` wins and, on
 * equal stamps, the later `add` wins. It reads no body. A bucket splits when
 * its held winners (frames the host keeps in memory, normally those up to
 * `FRAME_SMALL_BYTES`) pass the limit; long frames are located, not held, so
 * they do not count.
 */
export class FrameReducer<Ref> {
  readonly prefix: string;
  private readonly winners = new Map<string, FrameWinner<Ref>>();

  constructor(prefix: string) {
    if (!/^[01]*$/.test(prefix)) {
      throw new InvalidArgumentError("prefix must be a string of 0 and 1");
    }
    this.prefix = prefix;
  }

  add(winner: FrameWinner<Ref>): void {
    if (!inPrefix(winner.k, this.prefix)) {
      throw new InvalidArgumentError(
        `key ${winner.k} is outside bucket "${this.prefix}"`,
      );
    }
    const current = this.winners.get(winner.k);
    if (current && compareStamp(winner, current) < 0) return;
    this.winners.set(winner.k, winner);
  }

  get size(): number {
    return this.winners.size;
  }

  finish(limitBytes: number = PART_LIMIT_BYTES): FrameBucketResult<Ref> {
    const winners = [...this.winners.values()].sort((a, b) =>
      a.k < b.k ? -1 : a.k > b.k ? 1 : 0,
    );
    let smallBytes = 0;
    for (const w of winners) if (w.held) smallBytes += w.size;
    if (smallBytes > limitBytes) {
      return this.prefix.length < PLANNER_DEPTH_CAP
        ? { kind: "split", prefix: this.prefix, smallBytes }
        : { kind: "bucket_too_large", prefix: this.prefix, smallBytes };
    }
    return { kind: "ok", prefix: this.prefix, winners, smallBytes };
  }
}
