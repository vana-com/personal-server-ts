/**
 * Property tests (fast-check) for the parts of the package the TLA+ model
 * abstracts away: merge, reduce, the bucket planner, the codecs and the
 * names. conformance/README.md lists what each property stands in for.
 *
 * Runs are seeded at random; a failure prints its seed and path, and
 * `FC_SEED=<seed>` replays it.
 */

import { createHash } from "node:crypto";
import fc from "fast-check";
import { describe, expect, it, vi } from "vitest";
import {
  BucketReducer,
  PLANNER_DEPTH_CAP,
  SHARD_COUNT,
  canonicalJson,
  compareStamp,
  controlScope,
  decodeHead,
  decodeLine,
  decodePart,
  encodeHead,
  encodeLine,
  encodePart,
  mergeLines,
  parseBlobName,
  parseScope,
  partBlobName,
  pkHash,
  planBuckets,
  streamScope,
  type Head,
  type JsonObject,
  type JsonValue,
  type Line,
  type PlannerInput,
} from "./index.js";
import { sha256 } from "./test-support/ports.js";

const RUNS = Number(process.env["FC_RUNS"] ?? 300);
const seed = process.env["FC_SEED"]
  ? Number(process.env["FC_SEED"])
  : undefined;
// A larger FC_RUNS needs more time per test than the default 5 s.
vi.setConfig({ testTimeout: Math.max(5_000, RUNS * 20) });

const params = (numRuns = RUNS) => ({
  numRuns,
  ...(seed === undefined ? {} : { seed }),
});

const hex = (n: number) =>
  fc.string({
    unit: fc.constantFrom(..."0123456789abcdef"),
    minLength: n,
    maxLength: n,
  });
const hex16 = hex(16);
const hex64 = hex(64);
const sha256Sync = (text: string) =>
  createHash("sha256").update(text).digest("hex");

// ------------------------------------------------------------ merge, reduce

/** A line version of one key. `v` names its stamp, so text differs per stamp. */
interface Version {
  readonly id: number;
  readonly line: Line;
}

const stampArb = fc.record({
  o: fc.integer({ min: 0, max: 5 }),
  r: fc.constantFrom("seed", "raw", "run-000001", "run-000002", "run-000010"),
});

/** Versions over a few keys; per key the stamps are distinct. */
const versionsArb = fc
  .array(
    fc.record({
      id: fc.integer({ min: 0, max: 7 }),
      stamp: stampArb,
      x: fc.integer(),
    }),
    { maxLength: 40 },
  )
  .map((items) => {
    const seen = new Set<string>();
    const out: Version[] = [];
    for (const { id, stamp, x } of items) {
      const k = `${id}/${stamp.o}/${stamp.r}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push({ id, line: { o: stamp.o, r: stamp.r, v: { id, x } } });
    }
    return out;
  });

const keyHash = (id: number) => sha256Sync(canonicalJson([id]));
const entriesOf = (versions: readonly Version[]) =>
  versions.map((v) => ({ pkHash: keyHash(v.id), line: v.line }));

/** The expected winner per key: greatest (o, r), computed without the package. */
function expectedWinners(versions: readonly Version[]): Map<string, string> {
  const best = new Map<string, Line>();
  for (const { id, line } of versions) {
    const h = keyHash(id);
    const cur = best.get(h);
    if (!cur || line.o > cur.o || (line.o === cur.o && line.r > cur.r))
      best.set(h, line);
  }
  return new Map([...best].map(([h, l]) => [h, encodeLine(l)]));
}

describe("merge (§2.6)", () => {
  it("does not depend on feed order when stamps per key are distinct", () => {
    fc.assert(
      fc.property(
        versionsArb.chain((vs) =>
          fc.tuple(
            fc.constant(vs),
            fc.shuffledSubarray(vs, { minLength: vs.length }),
          ),
        ),
        ([vs, shuffled]) => {
          expect(mergeLines(entriesOf(shuffled))).toEqual(
            mergeLines(entriesOf(vs)),
          );
        },
      ),
      params(),
    );
  });

  it("on equal stamps keeps the later line", () => {
    fc.assert(
      fc.property(stampArb, fc.integer(), fc.integer(), (stamp, a, b) => {
        const h = keyHash(0);
        const first = { o: stamp.o, r: stamp.r, v: { id: 0, x: a } };
        const second = { o: stamp.o, r: stamp.r, v: { id: 0, x: b } };
        const result = mergeLines([
          { pkHash: h, line: first },
          { pkHash: h, line: second },
        ]);
        expect(result.kind === "ok" && result.winners[0]!.text).toBe(
          encodeLine(second),
        );
      }),
      params(),
    );
  });

  it("compareStamp is a total order consistent with (o, r)", () => {
    fc.assert(
      fc.property(stampArb, stampArb, stampArb, (a, b, c) => {
        expect(
          Math.sign(compareStamp(a, b)) === -Math.sign(compareStamp(b, a)),
        ).toBe(true);
        if (compareStamp(a, b) <= 0 && compareStamp(b, c) <= 0) {
          expect(compareStamp(a, c)).toBeLessThanOrEqual(0);
        }
      }),
      params(),
    );
  });
});

const bitsOf = (hash: string) =>
  BigInt(`0x${hash}`).toString(2).padStart(256, "0");

describe("BucketReducer", () => {
  it("over the part limit, splits below the 16-bit cap and stops at it (Q4)", () => {
    let splitRuns = 0;
    let cappedRuns = 0;
    fc.assert(
      fc.property(
        fc.uniqueArray(hex64, { minLength: 1, maxLength: 60 }),
        fc.integer({ min: 20, max: 3000 }),
        (hashes, limit) => {
          const entries = hashes.map((pkHash, i) => ({
            pkHash,
            line: { o: 1, r: "run-000001", v: { id: i } },
          }));
          // The host's re-plan loop: reduce a bucket, split it on `split`.
          const queue = [""];
          const finished: { prefix: string; keys: string[]; bytes: number }[] =
            [];
          const tooLarge: string[] = [];
          let reductions = 0;
          while (queue.length > 0) {
            reductions += 1;
            expect(reductions).toBeLessThanOrEqual(
              hashes.length * 2 * PLANNER_DEPTH_CAP + 1,
            );
            const prefix = queue.pop()!;
            const reducer = new BucketReducer(prefix);
            for (const e of entries) {
              if (bitsOf(e.pkHash).startsWith(prefix))
                reducer.add(e.pkHash, e.line);
            }
            const result = reducer.finish(limit);
            if (result.kind === "ok") {
              finished.push({
                prefix,
                keys: result.winners.map((w) => w.pkHash),
                bytes: result.bytes,
              });
            } else if (result.kind === "split") {
              expect(prefix.length).toBeLessThan(PLANNER_DEPTH_CAP);
              queue.push(`${prefix}0`, `${prefix}1`);
            } else {
              expect(prefix.length).toBe(PLANNER_DEPTH_CAP);
              tooLarge.push(prefix);
            }
          }
          if (reductions > 1) splitRuns += 1;
          if (tooLarge.length > 0) cappedRuns += 1;
          for (const f of finished) expect(f.bytes).toBeLessThanOrEqual(limit);
          // Every key lands in exactly one finished or capped bucket.
          const placed = hashes.map(
            (h) =>
              finished.filter((f) => f.keys.includes(h)).length +
              tooLarge.filter((p) => bitsOf(h).startsWith(p)).length,
          );
          expect(placed.every((n) => n === 1)).toBe(true);
        },
      ),
      params(),
    );
    expect(splitRuns).toBeGreaterThan(0);
    expect(cappedRuns).toBeGreaterThan(0);
  });

  it("keeps exactly the winning line per key", () => {
    fc.assert(
      fc.property(versionsArb, (vs) => {
        const reducer = new BucketReducer("");
        for (const e of entriesOf(vs)) reducer.add(e.pkHash, e.line);
        const want = expectedWinners(vs);
        expect(reducer.size).toBe(want.size);
        const result = reducer.finish();
        if (result.kind !== "ok") throw new Error(result.kind);
        expect(result.winners.map((w) => w.pkHash)).toEqual(
          [...want.keys()].sort(),
        );
        for (const w of result.winners) expect(w.text).toBe(want.get(w.pkHash));
        expect(result.bytes).toBe(
          result.winners.reduce((n, w) => n + Buffer.byteLength(w.text) + 1, 0),
        );
      }),
      params(),
    );
  });

  it("rejects a key outside its prefix", () => {
    fc.assert(
      fc.property(hex64, fc.constantFrom("0", "1", "01", "10"), (h, prefix) => {
        const bits = BigInt(`0x${h}`).toString(2).padStart(256, "0");
        const reducer = new BucketReducer(prefix);
        const line = { o: 0, r: "raw", v: {} };
        if (bits.startsWith(prefix)) reducer.add(h, line);
        else expect(() => reducer.add(h, line)).toThrow();
      }),
      params(),
    );
  });
});

// ------------------------------------------------------------- the planner

/** A prefix-free set of base parts, from random splits of the key space. */
const basePartsArb: fc.Arbitrary<{ prefix: string; bytes: number }[]> = fc
  .array(fc.boolean(), { maxLength: 64 })
  .chain((splits) => {
    const leaves: string[] = [];
    let i = 0;
    const walk = (prefix: string): void => {
      const split = prefix.length < PLANNER_DEPTH_CAP && (splits[i++] ?? false);
      if (!split) {
        leaves.push(prefix);
        return;
      }
      walk(`${prefix}0`);
      walk(`${prefix}1`);
    };
    walk("");
    return fc.tuple(
      ...leaves.map((prefix) =>
        fc
          .option(fc.integer({ min: 1, max: 1 << 20 }), { nil: undefined })
          .map((bytes) => ({
            prefix,
            bytes,
          })),
      ),
    );
  })
  .map((parts) =>
    parts.filter(
      (p): p is { prefix: string; bytes: number } => p.bytes !== undefined,
    ),
  );

/** Shard bytes: mostly empty, a few hot shards (to drive splits below 8 bits). */
const shardBytesArb = fc
  .array(
    fc.tuple(
      fc.integer({ min: 0, max: SHARD_COUNT - 1 }),
      fc.integer({ min: 1, max: 1 << 24 }),
    ),
    { maxLength: 12 },
  )
  .map((hot) => {
    const bytes = new Array<number>(SHARD_COUNT).fill(0);
    for (const [i, b] of hot) bytes[i] += b;
    return bytes;
  });

/** A counting pass: split a shard's bytes over 256 second bytes. */
function countsFor(total: number, weights: readonly number[]): number[] {
  const sum = weights.reduce((a, b) => a + b, 0) || 1;
  const out = weights.map((w) => Math.floor((total * w) / sum));
  out[0]! += total - out.reduce((a, b) => a + b, 0);
  return out;
}

describe("planBuckets", () => {
  it("terminates within one counting round and respects the 16-bit cap", () => {
    let cappedRuns = 0;
    fc.assert(
      fc.property(
        basePartsArb,
        shardBytesArb,
        // At least 64 KiB, so a plan has at most a few thousand buckets.
        fc.integer({ min: 1 << 16, max: 1 << 22 }),
        // Counting-pass spread: often all in one 16-bit prefix, to reach the cap.
        fc.oneof(
          fc
            .nat({ max: 255 })
            .map((i) =>
              Array.from({ length: 256 }, (_, j) => (j === i ? 1 : 0)),
            ),
          fc.array(fc.nat({ max: 1000 }), { minLength: 256, maxLength: 256 }),
        ),
        (baseParts, shardBytes, targetBytes, weights) => {
          let input: PlannerInput = { targetBytes, baseParts, shardBytes };
          let result = planBuckets(input);
          let rounds = 0;
          while (result.kind === "needs_counts") {
            rounds += 1;
            expect(rounds).toBeLessThanOrEqual(1);
            const prefix16Bytes: Record<number, readonly number[]> = {
              ...(input.prefix16Bytes ?? {}),
            };
            for (const shard of result.shards) {
              prefix16Bytes[shard] = countsFor(shardBytes[shard]!, weights);
            }
            input = { ...input, prefix16Bytes };
            result = planBuckets(input);
          }
          const prefixes = result.buckets.map((b) => b.prefix);
          expect(prefixes).toEqual([...prefixes].sort());
          for (let i = 1; i < prefixes.length; i += 1) {
            expect(prefixes[i]!.startsWith(prefixes[i - 1]!)).toBe(false);
          }
          for (const b of result.buckets) {
            expect(b.prefix.length).toBeLessThanOrEqual(PLANNER_DEPTH_CAP);
            expect(b.estimate).toBeGreaterThan(0);
            expect(b.capped).toBe(b.estimate > targetBytes);
            if (b.capped) expect(b.prefix.length).toBe(PLANNER_DEPTH_CAP);
          }
          if (result.buckets.some((b) => b.capped)) cappedRuns += 1;
          // Every run shard with bytes lies under some bucket.
          shardBytes.forEach((bytes, shard) => {
            if (bytes === 0) return;
            const bits = shard.toString(2).padStart(8, "0");
            expect(
              prefixes.some((p) => p.startsWith(bits) || bits.startsWith(p)),
              `shard ${shard}`,
            ).toBe(true);
          });
        },
      ),
      params(),
    );
    expect(cappedRuns).toBeGreaterThan(0);
  });
});

// ------------------------------------------------------------------ codecs

describe("canonical JSON", () => {
  it("is a fixed point of parse and keeps the JSON value", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        const text = canonicalJson(value);
        const back = JSON.parse(text) as JsonValue;
        expect(canonicalJson(back)).toBe(text);
        expect(back).toEqual(JSON.parse(JSON.stringify(value)));
      }),
      params(),
    );
  });

  it("does not depend on object key order", () => {
    fc.assert(
      fc.property(
        fc.dictionary(fc.string(), fc.jsonValue({ maxDepth: 2 })),
        fc.nat(),
        (object, rot) => {
          const keys = Object.keys(object);
          const k = keys.length ? rot % keys.length : 0;
          const rotated = Object.fromEntries(
            [...keys.slice(k), ...keys.slice(0, k)].map((key) => [
              key,
              object[key],
            ]),
          );
          expect(canonicalJson(rotated)).toBe(canonicalJson(object));
        },
      ),
      params(),
    );
  });

  it("lines round-trip through encodeLine and decodeLine", () => {
    fc.assert(
      fc.property(
        fc.nat(),
        fc.string({ minLength: 1 }),
        fc.dictionary(fc.string(), fc.jsonValue({ maxDepth: 2 })),
        (o, r, v) => {
          const text = encodeLine({ o, r, v: v as JsonObject });
          expect(encodeLine(decodeLine(text))).toBe(text);
        },
      ),
      params(),
    );
  });
});

const prefixFree = (n: number) =>
  fc
    .uniqueArray(fc.string({ unit: fc.constantFrom("0", "1"), maxLength: 4 }), {
      maxLength: n,
    })
    .map((ps) =>
      [...ps]
        .sort()
        .filter((p, i, all) => !all.slice(0, i).some((q) => p.startsWith(q))),
    );

const headArb: fc.Arbitrary<Head> = fc
  .record({
    complete: fc.boolean(),
    connector: fc.string({ minLength: 1 }).filter((c) => !c.includes("~")),
    generation: fc.integer({ min: 1, max: Number.MAX_SAFE_INTEGER }),
    keyCheck: hex16,
    ns: fc.oneof(fc.constant(""), hex16),
    observedAt: fc.nat(),
    prefixes: prefixFree(6),
    counts: fc.array(fc.integer({ min: 1, max: 1000 }), {
      minLength: 6,
      maxLength: 6,
    }),
    hashes: fc.array(hex64, { minLength: 6, maxLength: 6 }),
    primaryKey: fc.uniqueArray(fc.string({ minLength: 1 }), {
      minLength: 1,
      maxLength: 3,
    }),
    key: fc.option(fc.string()),
    version: fc.string({ minLength: 1 }),
    stream: fc.string({ minLength: 1 }),
  })
  .map((h) => {
    const parts = h.prefixes.map((prefix, i) => ({
      bytes: h.counts[i]! * 10,
      count: h.counts[i]!,
      hash: h.hashes[i]!,
      prefix,
    }));
    return {
      complete: h.complete,
      connector: h.connector,
      format: 1 as const,
      generation: h.generation,
      keyCheck: h.keyCheck,
      ns: h.ns,
      observedAt: h.observedAt,
      parts,
      primaryKey: h.primaryKey,
      profile: { key: h.key, version: h.version },
      recordCount: parts.reduce((n, p) => n + p.count, 0),
      stream: h.stream,
    };
  });

describe("heads", () => {
  it("round-trip through encodeHead and decodeHead", () => {
    fc.assert(
      fc.property(headArb, (head) => {
        const bytes = encodeHead(head);
        expect(decodeHead(bytes)).toEqual({ kind: "ok", head });
        expect(encodeHead((decodeHead(bytes) as { head: Head }).head)).toEqual(
          bytes,
        );
      }),
      params(),
    );
  });

  it("reject non-canonical bytes of a valid head", () => {
    fc.assert(
      fc.property(headArb, (head) => {
        const text = new TextDecoder().decode(encodeHead(head));
        const spaced = JSON.stringify(JSON.parse(text), null, 1);
        expect(decodeHead(new TextEncoder().encode(spaced)).kind).toBe(
          "malformed",
        );
      }),
      params(),
    );
  });
});

// ------------------------------------------------------------------- names

const connectorArb = fc
  .string({ minLength: 1, maxLength: 40 })
  .filter((c) => !c.includes("~"));
const nsArb = fc.oneof(fc.constant(""), hex16);
const streamArb = fc.string({ minLength: 1, maxLength: 60 });

/** Names built from the scope grammar's own pieces, to reach its edges. */
const scopeLikeArb = fc
  .array(
    fc.oneof(
      fc.constantFrom(
        "pdpp.",
        "~",
        ".",
        "pdpp",
        "0123456789abcdef",
        "0123456789ABCDEF",
        "a",
      ),
      hex(1),
      fc.string({ maxLength: 3 }),
    ),
    { maxLength: 8 },
  )
  .map((pieces) => pieces.join(""));

describe("scope names (§2.1)", () => {
  it("streamScope and controlScope round-trip through parseScope", () => {
    fc.assert(
      fc.property(connectorArb, nsArb, streamArb, (c, ns, s) => {
        expect(parseScope(streamScope(c, ns, s))).toEqual({
          kind: "stream",
          connector: c,
          ns,
          stream: s,
        });
        expect(parseScope(controlScope(c, ns))).toEqual({
          kind: "control",
          connector: c,
          ns,
        });
      }),
      params(),
    );
  });

  it("parse accepts only names the builders produce", () => {
    const builtArb = fc.oneof(
      fc
        .tuple(connectorArb, nsArb, streamArb)
        .map(([c, ns, s]) => streamScope(c, ns, s)),
      fc.tuple(connectorArb, nsArb).map(([c, ns]) => controlScope(c, ns)),
    );
    // A built name with one character replaced by 0-2 others.
    const nearMissArb = fc
      .tuple(builtArb, fc.nat(), fc.string({ maxLength: 2 }))
      .map(([name, i, insert]) => {
        const at = i % (name.length + 1);
        return name.slice(0, at) + insert + name.slice(at + 1);
      });
    let parsedRuns = 0;
    fc.assert(
      fc.property(
        fc.oneof(builtArb, nearMissArb, scopeLikeArb, fc.string()),
        (name) => {
          const parsed = parseScope(name);
          if (parsed === null) return;
          parsedRuns += 1;
          const rebuilt =
            parsed.kind === "stream"
              ? streamScope(parsed.connector, parsed.ns, parsed.stream)
              : controlScope(parsed.connector, parsed.ns);
          expect(rebuilt).toBe(name);
        },
      ),
      params(RUNS * 10),
    );
    expect(parsedRuns).toBeGreaterThan(RUNS);
  });

  it("rejects malformed names", () => {
    fc.assert(
      fc.property(connectorArb, streamArb, (c, s) => {
        // An old raw name has no "~".
        if (!c.includes("~") && !s.includes("~"))
          expect(parseScope(`pdpp.${c}.${s}`)).toBeNull();
        expect(parseScope(`pdpp.~${s}`)).toBeNull();
        if (!c.startsWith("pdpp.")) expect(parseScope(`${c}~.${s}`)).toBeNull();
        expect(parseScope(`pdpp.${c}~0123456789ABCDEF`)).toBeNull();
        expect(parseScope(`pdpp.${c}~0123456789abcdef.`)).toBeNull();
        expect(() => streamScope(c, "", "")).toThrow();
        expect(() => controlScope(`${c}~`, "")).toThrow();
        expect(() => controlScope(c, "0123456789ABCDEF")).toThrow();
      }),
      params(),
    );
  });

  it("rejects scopes over 256 bytes on both sides", () => {
    fc.assert(
      fc.property(
        connectorArb,
        fc.string({ minLength: 260, maxLength: 300 }),
        (c, s) => {
          expect(() => streamScope(c, "", s)).toThrow();
          expect(parseScope(`pdpp.${c}~.${s}`)).toBeNull();
        },
      ),
      params(50),
    );
  });
});

// ------------------------------------------------------------------- parts

describe("parts are content-addressed", () => {
  it("name = generation + SHA-256 of the bytes, and the bytes decode back", async () => {
    await fc.assert(
      fc.asyncProperty(
        versionsArb,
        fc.integer({ min: 1, max: 1e9 }),
        async (vs, g) => {
          const merged = mergeLines(
            await Promise.all(
              vs.map(async (v) => ({
                pkHash: await pkHash(sha256, v.line.v, ["id"]),
                line: v.line,
              })),
            ),
          );
          if (merged.kind !== "ok") throw new Error(merged.kind);
          const part = await encodePart(sha256, merged);
          if (part === null) {
            expect(merged.winners).toEqual([]);
            return;
          }
          const digest = createHash("sha256").update(part.data).digest("hex");
          expect(part.entry.hash).toBe(digest);
          const name = partBlobName(g, part.entry.hash);
          expect(parseBlobName(name)).toEqual({
            kind: "part",
            generation: g,
            sha256: digest,
          });
          const again = await encodePart(
            sha256,
            mergeLines(entriesOfHashed(merged.winners)) as never,
          );
          expect(again?.entry.hash).toBe(digest);
          const lines = await decodePart(sha256, part.data, part.entry, ["id"]);
          expect(lines.map((l) => l.text)).toEqual(
            merged.winners.map((w) => w.text),
          );
          const flipped = part.data.slice();
          flipped[0] = flipped[0]! ^ 1;
          await expect(
            decodePart(sha256, flipped, part.entry),
          ).rejects.toThrow();
        },
      ),
      params(),
    );
  });
});

function entriesOfHashed(winners: readonly { pkHash: string; text: string }[]) {
  return [...winners]
    .reverse()
    .map((w) => ({ pkHash: w.pkHash, line: decodeLine(w.text) }));
}
