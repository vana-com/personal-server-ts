// The disk fold (`log-fold-workspace.ts`) is the in-memory fold
// (`foldLog`, stream-sync `log.ts`) on the same history: the same entries in the
// same order, whatever the history holds. The in-memory fold is the oracle and
// stays; these tests are what lets a compaction or a rebase leave memory.
import { afterEach, describe, expect, it } from "vitest";
import {
  createPartitioner,
  foldLog,
  partitionFold,
  upsertBodyHash,
  LOG_FORMAT,
  type JsonObject,
  type LogBodyRef,
  type LogEntry,
  type LogOmission,
  type LogOperation,
  type Segment,
  type SnapshotPart,
  type WireEntry,
  type WireOperation,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  openLocalDb,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import { openFoldWorkspace } from "../../../core/src/localdb/log-fold-workspace.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
async function database() {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: `0x${"11".repeat(20)}`,
    network: "test",
    deviceId: "d",
  });
  drivers.push(db);
  return db;
}

/** A small deterministic generator: a failing seed is a reproduction. */
function rng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number) => Math.floor(next() * n);
  return { next, int, pick: <T>(xs: readonly T[]) => xs[int(xs.length)]! };
}

const CONTEXT = {
  connector: "c",
  ns: "",
  generation: 1,
  keyCheck: "k",
} as const;
const meta = (stream: string, cursor?: number) => ({
  stream,
  primaryKey: ["id"],
  profile: { key: null, version: "1" },
  complete: true,
  ...(cursor === undefined ? {} : { cursor: { v: cursor } }),
});

interface History {
  readonly segments: Segment<LogOperation>[];
  /** The same segments with some bodies by reference, and what they name. */
  readonly wire: Segment<WireOperation>[];
  readonly refs: Map<string, LogBodyRef>;
}

/**
 * A history over few keys, stamps and runs, so that ties, resurrections and
 * omissions at the stamp of an observation are common. Bodies of `big`
 * upserts are by reference in `wire`; the oracle sees them resolved.
 */
function history(
  seed: number,
  shape: { keys: number; segments: number; opsPerSegment: number },
): History {
  const r = rng(seed);
  const streams = ["s0", "s1"];
  const refs = new Map<string, LogBodyRef>();
  const keyOf = (k: number) => ({
    stream: streams[k % 2]!,
    pkHash: `h${String(k).padStart(4, "0")}`,
    key: [k] as const,
  });
  const segments: Segment<LogOperation>[] = [];
  const wire: Segment<WireOperation>[] = [];
  for (let position = 1; position <= shape.segments; position += 1) {
    const ops: LogOperation[] = [];
    const wireOps: WireOperation[] = [];
    for (let i = 0; i < shape.opsPerSegment; i += 1) {
      const k = keyOf(r.int(shape.keys));
      const stamp = { o: 1 + r.int(4), r: r.pick(["a", "b", "c"]) };
      const roll = r.next();
      if (roll < 0.6) {
        const big = r.next() < 0.3;
        const value: JsonObject = {
          id: k.key[0],
          v: r.int(3),
          ...(big ? { big: 1 } : {}),
        };
        const ordinal = r.pick([undefined, 0, 1, 2]);
        const op: LogOperation = {
          kind: "upsert",
          stream: k.stream,
          pkHash: k.pkHash,
          stamp,
          ...(ordinal === undefined ? {} : { ordinal }),
          firstSeen: r.pick([null, 1, 2, 3]),
          value,
        };
        ops.push(op);
        if (big) {
          const body: LogBodyRef = {
            sha256: upsertBodyHash(value),
            bytes: JSON.stringify(value).length,
            pieces: [`0x${"ab".repeat(32)}`],
          };
          refs.set(body.sha256, body);
          const {
            value: _value,
            kind: _kind,
            ...rest
          } = op as never as {
            value: JsonObject;
            kind: string;
          } & Record<string, unknown>;
          wireOps.push({ ...rest, kind: "upsert-ref", body } as WireOperation);
        } else wireOps.push(op);
      } else if (roll < 0.75) {
        const op: LogOperation = { kind: "delete", ...k, stamp };
        ops.push(op);
        wireOps.push(op);
      } else {
        const omitted: LogOmission[] = [];
        for (let j = 0; j < 1 + r.int(3); j += 1) {
          const o = keyOf(r.int(shape.keys));
          if (
            o.stream === k.stream &&
            !omitted.some((x) => x.pkHash === o.pkHash)
          )
            omitted.push({ pkHash: o.pkHash, key: o.key });
        }
        omitted.sort((a, b) => (a.pkHash < b.pkHash ? -1 : 1));
        const op: LogOperation = {
          kind: "complete",
          stream: k.stream,
          cutoff: stamp,
          omitted,
        };
        ops.push(op);
        wireOps.push(op);
      }
    }
    const common = {
      format: LOG_FORMAT,
      ...CONTEXT,
      position,
      observedAt: position,
      base: 0,
      snapshot: null,
      refs: [],
      streams: streams.map((s) =>
        meta(s, r.next() < 0.5 ? position : undefined),
      ),
    } as const;
    segments.push({ ...common, operations: ops });
    wire.push({ ...common, operations: wireOps });
  }
  return { segments, wire, refs };
}

/** What `foldLog` returned, written the way the workspace writes a reference. */
function asWire(entries: readonly LogEntry[], refs: Map<string, LogBodyRef>) {
  return entries.map((entry): WireEntry => {
    if (entry.kind !== "upsert" || entry.value.big !== 1) return entry;
    const { value, kind: _kind, ...rest } = entry;
    return {
      ...rest,
      kind: "upsert-ref",
      body: refs.get(upsertBodyHash(value))!,
    };
  });
}

async function fold(
  db: Awaited<ReturnType<typeof database>>,
  input: {
    parts: readonly SnapshotPart<WireEntry>[];
    segments: readonly Segment<WireOperation>[];
  },
) {
  const workspace = await openFoldWorkspace(db, "pdpp.c~", "test");
  for (const part of input.parts) await workspace.addPart(part);
  for (const segment of input.segments) await workspace.addSegment(segment);
  const entries: WireEntry[] = [];
  for await (const page of workspace.pages()) entries.push(...page);
  const streams = workspace.streams();
  await workspace.close();
  return { entries, streams };
}

describe("the disk fold is foldLog", () => {
  it("agrees on 300 random histories, with a previous snapshot and bodies by reference", async () => {
    const db = await database();
    for (let seed = 1; seed <= 300; seed += 1) {
      const h = history(seed, { keys: 8, segments: 8, opsPerSegment: 6 });
      // The first segments are an earlier compaction: their fold, in parts.
      const cut = rng(seed + 9000).int(h.segments.length);
      const earlier = foldLog({
        snapshot: [],
        segments: h.segments.slice(0, cut),
      });
      const parts = partitionFold(
        earlier,
        { ...CONTEXT, generation: 1, position: cut },
        120,
      ).map((p) => ({
        ...p,
        // The parts name their bodies the way a compaction did.
        entries: asWire(p.entries as LogEntry[], h.refs),
      }));
      const tail = h.segments.slice(cut);
      const oracle = foldLog({
        snapshot: parts.map((p) => ({
          ...p,
          entries: p.entries.map((e) =>
            e.kind === "upsert-ref"
              ? ({
                  ...e,
                  kind: "upsert" as const,
                  value: valueOf(h, e.body),
                } as never)
              : e,
          ),
        })) as never,
        segments: tail,
      });
      const mine = await fold(db, {
        parts,
        segments: h.wire.slice(cut),
      });
      expect(mine.entries, `seed ${seed}`).toEqual(
        asWire(oracle.entries, h.refs),
      );
      expect(mine.streams, `seed ${seed}`).toEqual(oracle.streams);
    }
  });

  it("agrees across many pages", async () => {
    const db = await database();
    const h = history(7, { keys: 400, segments: 6, opsPerSegment: 120 });
    const oracle = foldLog({ snapshot: [], segments: h.segments });
    expect(oracle.entries.length).toBeGreaterThan(200);
    const mine = await fold(db, { parts: [], segments: h.wire });
    expect(mine.entries).toEqual(asWire(oracle.entries, h.refs));
  });

  it("keeps the first of two upserts that are equal in every compared field", async () => {
    const db = await database();
    const stamp = { o: 1, r: "a" };
    const at = (
      firstSeen: number | null,
      position: number,
    ): Segment<LogOperation> => ({
      format: LOG_FORMAT,
      ...CONTEXT,
      position,
      observedAt: position,
      base: 0,
      snapshot: null,
      refs: [],
      streams: [meta("s0")],
      operations: [
        {
          kind: "upsert",
          stream: "s0",
          pkHash: "h0001",
          stamp,
          firstSeen,
          value: { id: 1 },
        },
      ],
    });
    const segments = [at(5, 1), at(null, 2), at(7, 3)];
    const oracle = foldLog({ snapshot: [], segments });
    const mine = await fold(db, { parts: [], segments });
    expect(mine.entries).toEqual(oracle.entries);
    expect((mine.entries[0] as { firstSeen: number | null }).firstSeen).toBe(5);
  });

  it("leaves no rows behind, and clears a crashed operation's", async () => {
    const db = await database();
    const stale = await openFoldWorkspace(db, "pdpp.c~", "test");
    await stale.addSegment(
      history(3, { keys: 4, segments: 1, opsPerSegment: 4 }).wire[0]!,
    );
    // Not closed: a crash. The next workspace of the connection and purpose starts empty.
    const next = await openFoldWorkspace(db, "pdpp.c~", "test");
    const count = async () =>
      (
        await db.query<{ n: number }>(
          "SELECT COUNT(*) AS n FROM log_fold_cells",
        )
      )[0]!.n;
    expect(await count()).toBe(0);
    await next.addSegment(
      history(4, { keys: 4, segments: 1, opsPerSegment: 4 }).wire[0]!,
    );
    expect(await count()).toBeGreaterThan(0);
    await next.close();
    expect(await count()).toBe(0);
  });
});

function valueOf(h: History, body: LogBodyRef): JsonObject {
  for (const segment of h.segments)
    for (const op of segment.operations)
      if (op.kind === "upsert" && upsertBodyHash(op.value) === body.sha256)
        return op.value;
  throw new Error("a reference names no body of the history");
}

describe("the streaming partitioner is partitionFold", () => {
  it("cuts the same parts on random folds and targets", () => {
    for (let seed = 1; seed <= 100; seed += 1) {
      const h = history(seed, { keys: 30, segments: 4, opsPerSegment: 20 });
      const fold = foldLog({ snapshot: [], segments: h.segments });
      const target = 100 + rng(seed).int(900);
      const context = { ...CONTEXT, position: 4 };
      const whole = partitionFold(fold, context, target);
      const partitioner = createPartitioner(fold.streams, context, target);
      const streamed = [];
      for (const entry of fold.entries) {
        const closed = partitioner.push(entry);
        if (closed) streamed.push(closed);
      }
      streamed.push(partitioner.finish());
      expect(streamed, `seed ${seed}`).toEqual(whole);
    }
  });
});
