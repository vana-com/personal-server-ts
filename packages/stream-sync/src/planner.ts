/**
 * §2.6 bucket planner.
 *
 * The run spool has 256 shard files keyed by the first pkHash byte, with a
 * byte count per shard. The planner starts with one bucket (prefix `""`) and
 * splits any bucket whose estimate is over the target by the next bit, never
 * deeper than 16 bits. A bucket's estimate is its base part bytes plus its
 * run shard bytes.
 *
 * Run bytes are exact down to 8 bits (sums of shard counts). Deeper than 8
 * bits they need bytes per 16-bit prefix, which the host gets with at most
 * one counting pass per shard: the planner asks for those shards with
 * `needs_counts`, and the host calls it again with the counts.
 *
 * Base bytes: a base part inside the bucket counts in full. A base part that
 * covers a larger range than the bucket counts in proportion to the share of
 * the key space the bucket covers (see DESIGN-QUESTIONS.md, Q3).
 *
 * Buckets with an estimate of 0 hold no records and are left out. The output
 * is prefix-free and sorted by prefix.
 */

import { PLANNER_DEPTH_CAP, SHARD_COUNT } from "./bytes.js";
import { InvalidArgumentError } from "./errors.js";

export interface PlannerInput {
  /** Writer target per part, in bytes. */
  readonly targetBytes: number;
  /** The base head's parts (prefix and bytes). Empty for an empty base. */
  readonly baseParts: readonly {
    readonly prefix: string;
    readonly bytes: number;
  }[];
  /** Run spool bytes per shard (first pkHash byte), 256 entries. */
  readonly shardBytes: readonly number[];
  /**
   * Counting-pass results: for a shard, run bytes per second pkHash byte
   * (256 entries, summing to that shard's bytes). Keyed by shard index.
   */
  readonly prefix16Bytes?: Readonly<Record<number, readonly number[]>>;
}

export interface PlannedBucket {
  readonly prefix: string;
  readonly estimate: number;
  /** At the 16-bit cap and still over target. */
  readonly capped: boolean;
}

export type PlannerResult =
  | { readonly kind: "needs_counts"; readonly shards: readonly number[] }
  | { readonly kind: "plan"; readonly buckets: readonly PlannedBucket[] };

function checkCount(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new InvalidArgumentError(
      `${label} must be a non-negative safe integer`,
    );
  }
  return value;
}

function checkInput(input: PlannerInput): void {
  if (!Number.isSafeInteger(input.targetBytes) || input.targetBytes < 1) {
    throw new InvalidArgumentError(
      "targetBytes must be a positive safe integer",
    );
  }
  if (input.shardBytes.length !== SHARD_COUNT) {
    throw new InvalidArgumentError("shardBytes must have 256 entries");
  }
  input.shardBytes.forEach((v, i) => checkCount(v, `shardBytes[${i}]`));
  for (const part of input.baseParts) {
    if (
      !/^[01]*$/.test(part.prefix) ||
      part.prefix.length > PLANNER_DEPTH_CAP
    ) {
      throw new InvalidArgumentError(
        `bad base part prefix ${JSON.stringify(part.prefix)}`,
      );
    }
    checkCount(part.bytes, "base part bytes");
  }
  for (const [key, counts] of Object.entries(input.prefix16Bytes ?? {})) {
    const shard = Number(key);
    if (!Number.isInteger(shard) || shard < 0 || shard >= SHARD_COUNT) {
      throw new InvalidArgumentError(`bad counting-pass shard ${key}`);
    }
    if (counts.length !== SHARD_COUNT) {
      throw new InvalidArgumentError(
        "counting-pass result must have 256 entries",
      );
    }
    let sum = 0;
    counts.forEach(
      (v, i) => (sum += checkCount(v, `prefix16Bytes[${key}][${i}]`)),
    );
    if (sum !== input.shardBytes[shard]) {
      throw new InvalidArgumentError(
        `counting pass for shard ${shard} sums to ${sum}, shard has ${input.shardBytes[shard]}`,
      );
    }
  }
}

/** Sum `values[from .. from + 2^(8 - bits.length))` for a prefix of ≤ 8 bits. */
function sumRange(values: readonly number[], bits: string): number {
  const span = 1 << (8 - bits.length);
  const from = bits === "" ? 0 : parseInt(bits, 2) * span;
  let sum = 0;
  for (let i = from; i < from + span; i += 1) sum += values[i]!;
  return sum;
}

export function planBuckets(input: PlannerInput): PlannerResult {
  checkInput(input);
  const counts = input.prefix16Bytes ?? {};
  const needs = new Set<number>();
  const buckets: PlannedBucket[] = [];

  /** Run bytes, or `null` when a counting pass is missing. */
  const runBytes = (prefix: string): number | null => {
    if (prefix.length <= 8) return sumRange(input.shardBytes, prefix);
    const shard = parseInt(prefix.slice(0, 8), 2);
    const shardCounts = counts[shard];
    if (!shardCounts) return null;
    return sumRange(shardCounts, prefix.slice(8));
  };

  const baseBytes = (prefix: string): number => {
    let sum = 0;
    for (const part of input.baseParts) {
      if (part.prefix.startsWith(prefix)) sum += part.bytes;
      else if (prefix.startsWith(part.prefix)) {
        sum += part.bytes / 2 ** (prefix.length - part.prefix.length);
      }
    }
    return sum;
  };

  const visit = (prefix: string, run: number): void => {
    const estimate = baseBytes(prefix) + run;
    if (estimate === 0) return;
    if (estimate <= input.targetBytes || prefix.length >= PLANNER_DEPTH_CAP) {
      buckets.push({
        prefix,
        estimate,
        capped: estimate > input.targetBytes,
      });
      return;
    }
    const left = runBytes(`${prefix}0`);
    const right = runBytes(`${prefix}1`);
    if (left === null || right === null) {
      needs.add(parseInt(prefix.slice(0, 8), 2));
      return;
    }
    visit(`${prefix}0`, left);
    visit(`${prefix}1`, right);
  };

  visit("", runBytes("")!);
  if (needs.size > 0) {
    return { kind: "needs_counts", shards: [...needs].sort((a, b) => a - b) };
  }
  return { kind: "plan", buckets };
}

/** The base parts a bucket's reduce must read (their ranges overlap). */
export function basePartsFor<P extends { readonly prefix: string }>(
  bucketPrefix: string,
  baseParts: readonly P[],
): P[] {
  return baseParts.filter(
    (part) =>
      part.prefix.startsWith(bucketPrefix) ||
      bucketPrefix.startsWith(part.prefix),
  );
}
