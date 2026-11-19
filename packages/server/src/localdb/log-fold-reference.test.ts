import { afterEach, expect, it } from "vitest";
import {
  foldLog,
  LOG_FORMAT,
  type Segment,
  type LogOperation,
  type SnapshotPart,
} from "../../../stream-sync/src/index.js";
import {
  applySegmentOperations,
  applySnapshotPart,
} from "../../../core/src/localdb/log-apply.js";
import {
  world,
  closeWorldDrivers,
  CONNECTION_ID,
  idHash,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

// The production pure fold is the reference. Sequential SQL apply is the independent oracle.
// Each prefix is also a snapshot boundary; the suffix acts as a fork/replay continuation.
it.each([0x12345678, 0xaabbccdd, 0x13579bdf])(
  "folded prefixes and fork suffixes preserve rows, stamps, first seen, tombstones and completion",
  async (seed) => {
    const w = await world({ streams: 1 });
    const a = await w.device("seed");
    await a.run("seed", [{ stream: "s0", id: 99 }]);
    await a.cycle();
    const template = [...(await w.segments()).values()][0]!;
    let random = seed;
    const next = () => {
      random = (Math.imul(random, 1664525) + 1013904223) >>> 0;
      return random;
    };
    const hash = await Promise.all([0, 1, 2, 3].map(idHash));
    const operations: LogOperation[] = [];
    for (let i = 0; i < 32; i++) {
      const id = (next() >>> 16) % 4,
        kind = next() % 3;
      const stamp = { o: 2000 + Math.floor(i / 4), r: `r${Math.floor(i / 4)}` };
      if (kind === 0)
        operations.push({
          kind: "delete",
          stream: "s0",
          pkHash: hash[id]!,
          key: [id],
          stamp,
        });
      else if (kind === 1)
        operations.push({
          kind: "complete",
          stream: "s0",
          cutoff: stamp,
          omitted: [{ pkHash: hash[id]!, key: [id] }],
        });
      else
        operations.push({
          kind: "upsert",
          stream: "s0",
          pkHash: hash[id]!,
          stamp,
          ordinal: i % 2,
          firstSeen: i % 2 ? null : 100,
          value: { id, v: i, text: '\\"é' },
        });
    }
    // Explicit vectors: omission ties lose; explicit ties win; a resurrection keeps its own firstSeen.
    const stamp = { o: 3000, r: "tie" };
    operations.push(
      {
        kind: "upsert",
        stream: "s0",
        pkHash: hash[0]!,
        stamp,
        firstSeen: null,
        value: { id: 0, v: 1 },
      },
      {
        kind: "complete",
        stream: "s0",
        cutoff: stamp,
        omitted: [{ pkHash: hash[0]!, key: [0] }],
      },
      { kind: "delete", stream: "s0", pkHash: hash[0]!, key: [0], stamp },
      {
        kind: "upsert",
        stream: "s0",
        pkHash: hash[0]!,
        stamp: { o: 3001, r: "resurrect" },
        firstSeen: 3001,
        value: { id: 0, v: 2 },
      },
    );
    const history: Segment[] = operations.map((op, i) => ({
      ...template,
      format: LOG_FORMAT,
      position: i + 2,
      refs: Array.from({ length: i + 1 }, (_, j) => ({
        position: j + 1,
        dataHash: `0x${"00".repeat(32)}` as `0x${string}`,
        bytes: 100,
      })),
      base: 0,
      snapshot: null,
      streams: template.streams.map((s) => ({
        ...s,
        complete: i === operations.length - 1,
      })),
      operations: [op],
    }));
    const resurrected = foldLog({
      snapshot: [],
      segments: history,
    }).entries.filter((e) => e.pkHash === hash[0]);
    expect(resurrected).toMatchObject([
      { kind: "delete", key: [0], stamp: { o: 3000, r: "tie" } },
      {
        kind: "upsert",
        firstSeen: 3001,
        stamp: { o: 3001, r: "resurrect" },
        value: { id: 0, v: 2 },
      },
    ]);
    async function state(d: Awaited<ReturnType<typeof w.device>>) {
      return {
        rows: await d.db.query(
          "SELECT stream,pk_hash,record_key,body,body_sha256,stamp_o,stamp_r,stamp_n,first_o FROM records ORDER BY stream,pk_hash",
        ),
        deletions: await d.db.query(
          // Compare the full effective deletion frontier. Dominated receipts may differ:
          // foldLog drops tied omissions; subsequent replay can retain an older receipt.
          `SELECT t.* FROM log_tombstones t WHERE NOT EXISTS (
          SELECT 1 FROM records r WHERE r.connection_id=t.connection_id
          AND r.stream=t.stream AND r.pk_hash=t.pk_hash
          AND (r.stamp_o>t.stamp_o OR (r.stamp_o=t.stamp_o
          AND (r.stamp_r>t.stamp_r OR (r.stamp_r=t.stamp_r AND t.rank=0)))))
          ORDER BY t.stream,t.pk_hash`,
        ),
        completion: await d.db.query(
          "SELECT stream,primary_key,profile_key,profile_version,complete FROM stream_state ORDER BY stream",
        ),
      };
    }
    for (const prefix of [1, 8, 17, 32, 33, 34, 35, 36]) {
      const sequential = await w.device(`seq${prefix}`),
        compact = await w.device(`fold${prefix}`);
      await sequential.cycle();
      await compact.cycle();
      for (const segment of history.slice(0, prefix))
        await applySegmentOperations(sequential.deps, CONNECTION_ID, segment);
      const fold = foldLog({
        snapshot: [],
        segments: history.slice(0, prefix),
      });
      const part: SnapshotPart = {
        format: LOG_FORMAT,
        connector: template.connector,
        ns: template.ns,
        generation: template.generation,
        keyCheck: template.keyCheck,
        position: prefix + 1,
        index: 0,
        streams: fold.streams,
        entries: fold.entries,
      };
      await applySnapshotPart(compact.deps, CONNECTION_ID, part);
      expect(await state(compact)).toEqual(await state(sequential));
      // Replay a fork suffix, including older stamps, after installing the prefix.
      for (const segment of [
        ...history.slice(prefix),
        ...history.slice(0, 3),
      ]) {
        await applySegmentOperations(sequential.deps, CONNECTION_ID, segment);
        await applySegmentOperations(compact.deps, CONNECTION_ID, segment);
      }
      expect(await state(compact)).toEqual(await state(sequential));
    }
  },
  60000,
);
