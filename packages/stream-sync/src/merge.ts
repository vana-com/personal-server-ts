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

import { PART_LIMIT_BYTES, utf8Length } from "./bytes.js";
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

  /** Winners sorted by pkHash, or `bucket_too_large` over `limitBytes`. */
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
      return { kind: "bucket_too_large", prefix: this.prefix, bytes };
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
