import {
  SHARD_COUNT,
  planBuckets,
  type HeadPart,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";

/**
 * What a record adds to a part beyond its body: the frame envelope (key hash,
 * body hash, length, stamp, first-seen). An estimate, only used to size parts.
 */
export const FRAME_OVERHEAD_BYTES = 160;

/** Changed keys per row-size query, under the SQL variable limit. */
const KEYS_PER_QUERY = 500;

/** The first `bits` bits of a hex string, as a bit string. */
export function prefixBits(hex: string, bits: number): string {
  if (bits === 0) return "";
  const needed = Math.ceil(bits / 4);
  const value = BigInt(`0x${hex.slice(0, needed)}`);
  return value
    .toString(2)
    .padStart(needed * 4, "0")
    .slice(0, bits);
}

const overlaps = (a: string, b: string) => a.startsWith(b) || b.startsWith(a);

/**
 * Which planned buckets to encode. A bucket holding a changed key is encoded.
 * A base part that overlaps an encoded bucket is dropped, so every other
 * bucket that overlaps a dropped part is encoded too (its rows were in that
 * part); this repeats until no part is half dropped. What is left is a set of
 * encoded buckets and retained base parts that do not overlap. `rewriteAll`
 * drops every base part first (a format upgrade or a replace).
 */
export function selectChangedBuckets(
  buckets: readonly string[],
  changedKeys: readonly string[],
  baseParts: readonly { readonly prefix: string }[],
  rewriteAll: boolean,
): string[] {
  const changed = new Set<string>();
  for (const key of changedKeys) {
    const bucket = buckets.find(
      (prefix) => prefixBits(key, prefix.length) === prefix,
    );
    if (bucket !== undefined) changed.add(bucket);
  }
  const dropped = new Set<string>(
    rewriteAll ? baseParts.map((p) => p.prefix) : [],
  );
  for (;;) {
    const before = changed.size + dropped.size;
    for (const part of baseParts) {
      if ([...changed].some((bucket) => overlaps(bucket, part.prefix))) {
        dropped.add(part.prefix);
      }
    }
    for (const bucket of buckets) {
      if ([...dropped].some((prefix) => overlaps(bucket, prefix))) {
        changed.add(bucket);
      }
    }
    if (changed.size + dropped.size === before) break;
  }
  return [...changed].sort();
}

/**
 * The prefixes to encode for a publish: the spec's bucket planner (§2.6,
 * `planBuckets`) over the base head's parts and the changed rows' bytes, then
 * `selectChangedBuckets`. A fresh stream is one bucket until it passes the
 * byte target, then splits bit by bit, so it becomes a few parts and not one
 * part per record. The encoder still cuts a bucket that turns out over the
 * target into several parts of the same prefix.
 */
export async function planChangedPrefixes(
  deps: LocalSyncDeps,
  input: {
    readonly connectionId: string;
    readonly stream: string;
    readonly changedKeys: readonly string[];
    readonly baseParts: readonly HeadPart[];
    readonly targetBytes: number;
    readonly rewriteAll: boolean;
  },
): Promise<string[]> {
  const keys = [...new Set(input.changedKeys)];
  if (keys.length === 0 && !input.rewriteAll) return [];
  const shardBytes = new Array<number>(SHARD_COUNT).fill(0);
  const prefix16Bytes: Record<number, number[]> = {};
  for (let at = 0; at < keys.length; at += KEYS_PER_QUERY) {
    const page = keys.slice(at, at + KEYS_PER_QUERY);
    const rows = await deps.db.query<{ pk_hash: string; n: number }>(
      `SELECT pk_hash, LENGTH(CAST(body AS BLOB)) AS n FROM records
        WHERE connection_id = ? AND stream = ?
          AND pk_hash IN (${page.map(() => "?").join(",")})`,
      [input.connectionId, input.stream, ...page],
    );
    for (const { pk_hash, n } of rows) {
      const bytes = n + FRAME_OVERHEAD_BYTES;
      const shard = parseInt(pk_hash.slice(0, 2), 16);
      const second = parseInt(pk_hash.slice(2, 4), 16);
      shardBytes[shard]! += bytes;
      (prefix16Bytes[shard] ??= new Array<number>(SHARD_COUNT).fill(0))[
        second
      ]! += bytes;
    }
  }
  // A shard with no surviving changed row has zero delta bytes. Its counts are
  // known, so they are zeros, not missing: the planner splits a base group that
  // is heavier than the target there without a counting pass.
  for (let shard = 0; shard < SHARD_COUNT; shard += 1) {
    prefix16Bytes[shard] ??= new Array<number>(SHARD_COUNT).fill(0);
  }
  const plan = planBuckets({
    targetBytes: input.targetBytes,
    baseParts: input.baseParts.map(({ prefix, bytes }) => ({ prefix, bytes })),
    shardBytes,
    prefix16Bytes,
  });
  if (plan.kind !== "plan") {
    throw new Error("planner asked for counts it was given");
  }
  return selectChangedBuckets(
    plan.buckets.map((bucket) => bucket.prefix),
    keys,
    input.baseParts,
    input.rewriteAll,
  );
}
