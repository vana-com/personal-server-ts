import { describe, expect, it } from "vitest";
import {
  InvalidArgumentError,
  InvalidPartError,
  MissingKeyFieldError,
} from "./errors.js";
import { BucketReducer, compareStamp, mergeLines } from "./merge.js";
import { decodePart, encodePart, encodeWinners } from "./parts.js";
import { planBuckets, basePartsFor } from "./planner.js";
import {
  decodeLine,
  encodeLine,
  inPrefix,
  lineSize,
  pkHash,
  pkHashBits,
  shardOf,
  type Line,
} from "./records.js";
import { int, pick, rng, sha256 } from "./test-support/ports.js";

interface Fed {
  pkHash: string;
  line: Line;
}

async function randomFeed(
  seed: number,
  keys: number,
  lines: number,
): Promise<Fed[]> {
  const random = rng(seed);
  const out: Fed[] = [];
  for (let i = 0; i < lines; i += 1) {
    const id = int(random, keys);
    const line: Line = {
      o: int(random, 5),
      r: pick(random, ["a", "b", "seed", "é"]),
      v: { id, n: i },
    };
    out.push({ pkHash: await pkHash(sha256, line.v, ["id"]), line });
  }
  return out;
}

/** Brute force: greatest (o, r), later line on ties. */
function oracle(feed: readonly Fed[]): Map<string, string> {
  const best = new Map<string, Line>();
  for (const { pkHash: k, line } of feed) {
    const cur = best.get(k);
    if (!cur || compareStamp(line, cur) >= 0) best.set(k, line);
  }
  return new Map([...best].map(([k, l]) => [k, encodeLine(l)]));
}

describe("merge", () => {
  it("matches a brute-force oracle (property)", async () => {
    for (let seed = 1; seed <= 60; seed += 1) {
      const feed = await randomFeed(seed, 1 + (seed % 9), 3 + seed * 2);
      const result = mergeLines(feed);
      if (result.kind !== "ok") throw new Error("unexpected");
      const want = oracle(feed);
      expect(result.winners.map((w) => w.pkHash)).toEqual(
        [...want.keys()].sort(),
      );
      for (const w of result.winners) expect(w.text).toBe(want.get(w.pkHash));
    }
  });

  it("is independent of bucket split points (property)", async () => {
    for (let seed = 1; seed <= 30; seed += 1) {
      const feed = await randomFeed(seed * 31, 40, 120);
      const whole = mergeLines(feed);
      if (whole.kind !== "ok") throw new Error("unexpected");
      const depth = seed % 6;
      const pieces: string[] = [];
      for (let b = 0; b < 2 ** depth; b += 1) {
        const prefix = depth === 0 ? "" : b.toString(2).padStart(depth, "0");
        const part = mergeLines(
          feed.filter((f) => inPrefix(f.pkHash, prefix)),
          prefix,
        );
        if (part.kind !== "ok") throw new Error("unexpected");
        pieces.push(...part.winners.map((w) => w.text));
      }
      expect(pieces).toEqual(whole.winners.map((w) => w.text));
    }
  });

  it("keeps one entry per key however many versions are fed", async () => {
    const reducer = new BucketReducer("");
    const key = await pkHash(sha256, { id: 1 }, ["id"]);
    for (let i = 0; i < 100_000; i += 1) {
      reducer.add(key, { o: i % 997, r: "r", v: { id: 1, i } });
    }
    expect(reducer.size).toBe(1);
    const result = reducer.finish();
    if (result.kind !== "ok") throw new Error("unexpected");
    expect(decodeLine(result.winners[0]!.text).o).toBe(996);
  });

  it("asks for a split over the limit below the 16-bit cap (Q4)", async () => {
    const feed = await randomFeed(5, 50, 50);
    const result = mergeLines(feed, "", 100);
    expect(result).toMatchObject({ kind: "split", prefix: "" });
  });

  it("reports bucket_too_large over the limit only at the 16-bit cap", async () => {
    const key = await pkHash(sha256, { id: 1 }, ["id"]);
    const capped = pkHashBits(key, 16);
    const reducer = new BucketReducer(capped);
    reducer.add(key, { o: 1, r: "r", v: { id: 1, pad: "x".repeat(200) } });
    expect(reducer.finish(100)).toMatchObject({
      kind: "bucket_too_large",
      prefix: capped,
    });
    const shallow = new BucketReducer(pkHashBits(key, 15));
    shallow.add(key, { o: 1, r: "r", v: { id: 1, pad: "x".repeat(200) } });
    expect(shallow.finish(100).kind).toBe("split");
  });

  it("rejects a key outside the bucket", async () => {
    const key = await pkHash(sha256, { id: 1 }, ["id"]);
    const other = pkHashBits(key, 1) === "0" ? "1" : "0";
    expect(() =>
      new BucketReducer(other).add(key, { o: 1, r: "r", v: { id: 1 } }),
    ).toThrow(InvalidArgumentError);
  });
});

describe("records", () => {
  it("rejects a record without a key field", async () => {
    await expect(pkHash(sha256, { a: 1 }, ["id"])).rejects.toThrow(
      MissingKeyFieldError,
    );
  });

  it("derives shard and bits from the same hash", async () => {
    const key = await pkHash(sha256, { id: "x" }, ["id"]);
    expect(pkHashBits(key, 8)).toBe(shardOf(key).toString(2).padStart(8, "0"));
    expect(inPrefix(key, "")).toBe(true);
  });

  it("flags only lines over 8 MiB", () => {
    const shell = encodeLine({ o: 0, r: "r", v: { x: "" } }).length;
    const at = encodeLine({
      o: 0,
      r: "r",
      v: { x: "a".repeat(8 * 1024 * 1024 - shell) },
    });
    expect(lineSize(at).fits).toBe(true);
    expect(lineSize(`${at}a`)).toMatchObject({
      fits: false,
      reason: "record_too_large",
    });
  });
});

describe("parts", () => {
  it("round-trips and verifies (property)", async () => {
    for (let seed = 1; seed <= 20; seed += 1) {
      const result = mergeLines(await randomFeed(seed * 7, 30, 60));
      if (result.kind !== "ok") throw new Error("unexpected");
      const part = await encodePart(sha256, result);
      if (!part) throw new Error("empty");
      const lines = await decodePart(sha256, part.data, part.entry, ["id"]);
      expect(lines.map((l) => l.text)).toEqual(
        result.winners.map((w) => w.text),
      );
      expect(part.entry.count).toBe(result.winners.length);
      expect(part.entry.bytes).toBe(result.bytes);
    }
  });

  it("returns no part for an empty bucket", async () => {
    expect(await encodeWinners(sha256, "0", [])).toBeNull();
  });

  it("fails closed on tampering", async () => {
    const result = mergeLines(await randomFeed(3, 10, 20), "");
    if (result.kind !== "ok") throw new Error("unexpected");
    const part = (await encodePart(sha256, result))!;
    const flipped = part.data.slice();
    flipped[5] = flipped[5]! ^ 1;
    await expect(decodePart(sha256, flipped, part.entry)).rejects.toThrow(
      InvalidPartError,
    );
    await expect(
      decodePart(sha256, part.data, {
        ...part.entry,
        count: part.entry.count + 1,
      }),
    ).rejects.toThrow(InvalidPartError);
    await expect(
      decodePart(sha256, part.data, { ...part.entry, bytes: 1 }),
    ).rejects.toThrow(InvalidPartError);
    await expect(
      decodePart(sha256, part.data, { ...part.entry, prefix: "0" }, ["id"]),
    ).rejects.toThrow(InvalidPartError);
  });

  it("rejects unsorted winners", async () => {
    await expect(
      encodeWinners(sha256, "", [
        { pkHash: "b".repeat(64), text: "{}" },
        { pkHash: "a".repeat(64), text: "{}" },
      ]),
    ).rejects.toThrow(InvalidArgumentError);
  });
});

describe("planner", () => {
  function check(
    result: ReturnType<typeof planBuckets>,
    target: number,
    shards: number[],
  ) {
    if (result.kind !== "plan") throw new Error("expected a plan");
    const prefixes = result.buckets.map((b) => b.prefix);
    expect([...prefixes].sort()).toEqual(prefixes);
    for (let i = 1; i < prefixes.length; i += 1) {
      expect(prefixes[i]!.startsWith(prefixes[i - 1]!)).toBe(false);
    }
    for (const b of result.buckets) {
      expect(b.prefix.length).toBeLessThanOrEqual(16);
      if (!b.capped) expect(b.estimate).toBeLessThanOrEqual(target);
      else expect(b.prefix.length).toBe(16);
    }
    // Every shard with bytes is covered by exactly one bucket range.
    shards.forEach((bytes, shard) => {
      if (bytes === 0) return;
      const bits = shard.toString(2).padStart(8, "0");
      const covering = prefixes.filter(
        (p) => bits.startsWith(p) || p.startsWith(bits),
      );
      expect(covering.length).toBeGreaterThan(0);
    });
  }

  it("terminates with a prefix-free cover within the cap (property)", () => {
    const random = rng(11);
    for (let i = 0; i < 300; i += 1) {
      const target = 1 + int(random, 5000);
      const shards = Array.from({ length: 256 }, () =>
        random() < 0.2 ? int(random, 20000) : 0,
      );
      let result = planBuckets({
        targetBytes: target,
        baseParts: [],
        shardBytes: shards,
      });
      if (result.kind === "needs_counts") {
        const counts: Record<number, number[]> = {};
        for (const shard of result.shards) {
          const row = new Array(256).fill(0);
          let left = shards[shard]!;
          // Skew: most bytes on one second byte.
          row[int(random, 256)] = Math.floor(left * 0.9);
          left -= Math.floor(left * 0.9);
          while (left > 0) {
            const take = Math.min(left, 1 + int(random, 500));
            row[int(random, 256)] += take;
            left -= take;
          }
          counts[shard] = row;
        }
        result = planBuckets({
          targetBytes: target,
          baseParts: [],
          shardBytes: shards,
          prefix16Bytes: counts,
        });
      }
      check(result, target, shards);
    }
  });

  it("asks for at most one counting pass per shard", () => {
    const shards = new Array(256).fill(0);
    shards[3] = 100;
    const first = planBuckets({
      targetBytes: 10,
      baseParts: [],
      shardBytes: shards,
    });
    expect(first).toEqual({ kind: "needs_counts", shards: [3] });
    const row = new Array(256).fill(0);
    row[0] = 100;
    const second = planBuckets({
      targetBytes: 10,
      baseParts: [],
      shardBytes: shards,
      prefix16Bytes: { 3: row },
    });
    expect(second).toEqual({
      kind: "plan",
      buckets: [{ prefix: "0000001100000000", estimate: 100, capped: true }],
    });
  });

  it("routes base parts to overlapping buckets", () => {
    const parts = [{ prefix: "0" }, { prefix: "10" }, { prefix: "11" }];
    expect(basePartsFor("1", parts)).toEqual([
      { prefix: "10" },
      { prefix: "11" },
    ]);
    expect(basePartsFor("01", parts)).toEqual([{ prefix: "0" }]);
    expect(basePartsFor("", parts)).toEqual(parts);
  });
});
