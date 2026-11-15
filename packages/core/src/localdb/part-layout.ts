import {
  SHARD_COUNT,
  planBuckets,
  type HeadPart,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { SqlReader } from "./driver.js";
import { SEEN_BEFORE, seenBeforeParams } from "./merge.js";

/**
 * What a record adds to a part beyond its body: the frame envelope (key hash,
 * body hash, length, stamp, first-seen). An estimate, only used to size parts.
 */
export const FRAME_OVERHEAD_BYTES = 160;

/**
 * The bytes of a record's body. Prototype switch: a stored `body_bytes` column
 * (the proxy for a size kept at write time) or the byte length of the text.
 */
export const BODY_BYTES =
  process.env.PUBLISH_BODY_BYTES === "1"
    ? "body_bytes"
    : "LENGTH(CAST(body AS BLOB))";

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

/** Key bits in the lookup table: a bucket of at most this many bits depends only on them. */
const KEY_TABLE_BITS = 16;

/**
 * The bucket of each changed key: the first bucket, in `buckets` order, whose
 * bits are a prefix of the key's bits (the same answer as `find` over each
 * key). Keys are grouped by their first 16 bits, so each distinct value is
 * resolved once instead of once per key. Buckets longer than 16 bits, or keys
 * without four leading hex digits, take the per-key path.
 */
function bucketsOfKeys(
  buckets: readonly string[],
  changedKeys: readonly string[],
): Set<string> {
  const found = new Set<string>();
  const tableable =
    buckets.every((prefix) => prefix.length <= KEY_TABLE_BITS) &&
    changedKeys.every((key) => /^[0-9a-fA-F]{4}/.test(key));
  if (!tableable) {
    for (const key of changedKeys) {
      const bucket = buckets.find(
        (prefix) => prefixBits(key, prefix.length) === prefix,
      );
      if (bucket !== undefined) found.add(bucket);
    }
    return found;
  }
  const marked = new Uint8Array(1 << KEY_TABLE_BITS);
  for (const key of changedKeys) marked[parseInt(key.slice(0, 4), 16)] = 1;
  const firstIndex = new Map<string, number>();
  buckets.forEach((prefix, index) => {
    if (!firstIndex.has(prefix)) firstIndex.set(prefix, index);
  });
  const lengths = [...new Set(buckets.map((prefix) => prefix.length))];
  for (let value = 0; value < marked.length; value += 1) {
    if (marked[value] === 0) continue;
    const bits = value.toString(2).padStart(KEY_TABLE_BITS, "0");
    let best = -1;
    for (const length of lengths) {
      const index = firstIndex.get(bits.slice(0, length));
      if (index !== undefined && (best === -1 || index < best)) best = index;
    }
    if (best !== -1) found.add(buckets[best]!);
  }
  return found;
}

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
  const changed = bucketsOfKeys(buckets, changedKeys);
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
  reader: SqlReader,
  input: {
    readonly connectionId: string;
    readonly stream: string;
    readonly changedKeys: readonly string[];
    /** Rows a replace drops, by 16-bit key prefix (see `replacedPrefixGroups`). */
    readonly replaced?: readonly { prefix: string; bytes: number }[];
    readonly baseParts: readonly HeadPart[];
    readonly targetBytes: number;
    readonly rewriteAll: boolean;
  },
): Promise<string[]> {
  const keys = [...new Set(input.changedKeys)];
  const replaced = input.replaced ?? [];
  if (keys.length === 0 && replaced.length === 0 && !input.rewriteAll)
    return [];
  const tally = newTally();
  for (let at = 0; at < keys.length; at += KEYS_PER_QUERY) {
    const page = keys.slice(at, at + KEYS_PER_QUERY);
    const rows = await reader.query<{ pk_hash: string; n: number }>(
      `SELECT pk_hash, ${BODY_BYTES} AS n FROM records
        WHERE connection_id = ? AND stream = ?
          AND pk_hash IN (${page.map(() => "?").join(",")})`,
      [input.connectionId, input.stream, ...page],
    );
    for (const { pk_hash, n } of rows) {
      addBytes(tally, pk_hash.slice(0, 4), n + FRAME_OVERHEAD_BYTES);
    }
  }
  for (const { prefix, bytes } of replaced) addBytes(tally, prefix, bytes);
  return planFromTally(tally, {
    changedKeys: [...keys, ...replaced.map((group) => group.prefix)],
    baseParts: input.baseParts,
    targetBytes: input.targetBytes,
    rewriteAll: input.rewriteAll,
  });
}

type Tally = {
  readonly shardBytes: number[];
  readonly prefix16Bytes: Record<number, number[]>;
};

const newTally = (): Tally => ({
  shardBytes: new Array<number>(SHARD_COUNT).fill(0),
  prefix16Bytes: {},
});

/** Add `bytes` under the 16-bit key prefix (four hex digits) of `hex`. */
function addBytes(tally: Tally, hex: string, bytes: number): void {
  const shard = parseInt(hex.slice(0, 2), 16);
  const second = parseInt(hex.slice(2, 4), 16);
  tally.shardBytes[shard]! += bytes;
  (tally.prefix16Bytes[shard] ??= new Array<number>(SHARD_COUNT).fill(0))[
    second
  ]! += bytes;
}

function planFromTally(
  tally: Tally,
  input: {
    readonly changedKeys: readonly string[];
    readonly baseParts: readonly HeadPart[];
    readonly targetBytes: number;
    readonly rewriteAll: boolean;
  },
): string[] {
  const { shardBytes, prefix16Bytes } = tally;
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
    // A prefix of four hex digits marks the same bucket as any key under it.
    input.changedKeys,
    input.baseParts,
    input.rewriteAll,
  );
}

/**
 * The publishable changes of a stream in `(from, to]`, as the rows of
 * `record_changes` a publish sends: the origins a publish carries, minus those
 * of a run that was refused or discarded.
 */
export const PUBLISHABLE_CHANGES = `connection_id = ? AND stream = ?
        AND seq > ? AND seq <= ?
        AND origin IN ('local', 'import', 'refresh')
        AND NOT EXISTS (SELECT 1 FROM runs r JOIN run_streams rs ON rs.run_id=r.run_id
          WHERE r.connection_id=record_changes.connection_id AND rs.stream=record_changes.stream
            AND r.run_id=record_changes.stamp_r AND r.o=record_changes.stamp_o
            AND rs.decision IN ('refused','discarded'))`;

/**
 * `planChangedPrefixes` for a caller that reads through a frozen view: the part
 * sizes come from two grouped reads in the view (one entry per 16-bit key
 * prefix, at most 65,536 however many rows changed) instead of one lookup per
 * 500 changed keys, and no key list passes through memory. The result is the
 * same: the bytes under a prefix are the sum over the changed keys that still
 * have a row, and a changed key whose row is gone still marks its prefix.
 */
export async function planChangedPrefixesIn(
  view: SqlReader,
  input: {
    readonly connectionId: string;
    readonly stream: string;
    readonly from: number;
    readonly to: number;
    readonly replaced?: readonly { prefix: string; bytes: number }[];
    readonly baseParts: readonly HeadPart[];
    readonly targetBytes: number;
    readonly rewriteAll: boolean;
  },
): Promise<string[]> {
  const replaced = input.replaced ?? [];
  const range = [input.connectionId, input.stream, input.from, input.to];
  const changed = await view.query<{ prefix: string }>(
    `SELECT DISTINCT SUBSTR(pk_hash, 1, 4) AS prefix FROM record_changes
      WHERE ${PUBLISHABLE_CHANGES}`,
    range,
  );
  if (changed.length === 0 && replaced.length === 0 && !input.rewriteAll)
    return [];
  const sized = await view.query<{ prefix: string; bytes: number }>(
    `SELECT SUBSTR(r.pk_hash, 1, 4) AS prefix,
            SUM(${BODY_BYTES} + ${FRAME_OVERHEAD_BYTES}) AS bytes
       FROM records r
      WHERE r.connection_id = ? AND r.stream = ?
        AND r.pk_hash IN (SELECT pk_hash FROM record_changes
                           WHERE ${PUBLISHABLE_CHANGES})
      GROUP BY prefix`,
    [input.connectionId, input.stream, ...range],
  );
  const tally = newTally();
  for (const { prefix, bytes } of sized) addBytes(tally, prefix, Number(bytes));
  for (const { prefix, bytes } of replaced) addBytes(tally, prefix, bytes);
  return planFromTally(tally, {
    changedKeys: [
      ...changed.map((group) => group.prefix),
      ...replaced.map((group) => group.prefix),
    ],
    baseParts: input.baseParts,
    targetBytes: input.targetBytes,
    rewriteAll: input.rewriteAll,
  });
}

/**
 * The rows a full refresh will drop, as one entry per 16-bit key prefix: the
 * first four hex digits of the key hash, the rows there and their estimated
 * part bytes. That is at most 65,536 entries however many rows go, which is
 * all the part planner reads (it sizes buckets of at most 16 bits). The rows
 * are the ones last observed before the replacing run `marker`; the read seeks
 * on `records_by_observation`.
 */
export async function replacedPrefixGroups(
  db: SqlReader,
  connectionId: string,
  stream: string,
  marker: { readonly o: number; readonly r: string },
): Promise<{ prefix: string; rows: number; bytes: number }[]> {
  const groups = await db.query<{
    prefix: string;
    rows: number;
    bytes: number;
  }>(
    `SELECT SUBSTR(pk_hash, 1, 4) AS prefix, COUNT(*) AS rows,
            SUM(LENGTH(CAST(body AS BLOB)) + ${FRAME_OVERHEAD_BYTES}) AS bytes
       FROM records
      WHERE connection_id = ? AND stream = ? AND ${SEEN_BEFORE}
      GROUP BY prefix`,
    [connectionId, stream, ...seenBeforeParams(marker.o, marker.r)],
  );
  return groups.map((g) => ({
    prefix: g.prefix,
    rows: Number(g.rows),
    bytes: Number(g.bytes),
  }));
}
