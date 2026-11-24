// A compaction is the fold of the history it replaces: the parts it spools
// hold the entries `foldLog` gives for the same segments, and name the same
// streams. `foldLog` (stream-sync `log.ts`) is the oracle; the compaction
// builds the same fold on disk (`log-compact.ts`, `log-fold-workspace.ts`).
import { afterEach, describe, expect, it } from "vitest";
import {
  decodeSnapshotPart,
  deriveKeyCheck,
  foldLog,
  type LogEntry,
  type Segment,
  type WireSegment,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { compactLog } from "../../../core/src/localdb/log-compact.js";
import { openSpool } from "../../../core/src/localdb/log-spool.js";
import { readLogState } from "../../../core/src/localdb/log-state.js";
import {
  CONNECTION_ID,
  CONNECTOR,
  LOG,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe("a compaction is the fold of its history", () => {
  for (const seed of [1, 2, 3, 4, 5]) {
    it(`agrees with foldLog on random runs of two devices (seed ${seed})`, async () => {
      const next = rng(seed);
      const int = (n: number) => Math.floor(next() * n);
      const w = await world({ streams: 2, partTargetBytes: 600 });
      const a = await w.device("a");
      const b = await w.device("b");
      for (let i = 0; i < 10; i += 1) {
        const device = i % 2 === 0 ? a : b;
        await device.cycle();
        const records = Array.from({ length: 2 + int(8) }, () => ({
          stream: sName(int(2)),
          id: `k${int(12)}`,
          v: int(3),
          ...(next() < 0.2 ? { remove: true } : {}),
        }));
        await device.run(`r${i}`, records, {
          full: next() < 0.4,
          observedAt: 2000 + i,
        });
        await device.cycle();
      }
      await a.cycle();

      const log = await readLogState(a.deps, CONNECTION_ID);
      const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
      const spool = openSpool(a.db, CONNECTION_ID, "test");
      const plan = await compactLog(
        { ...a.deps, partTargetBytes: 600 },
        {
          connectionId: CONNECTION_ID,
          connector: CONNECTOR,
          ns: "",
          generation: 1,
          keyCheck,
          scope: LOG,
          log,
        },
        spool,
      );
      expect(plan).not.toBeNull();
      const parts = [];
      for (const part of plan!.snapshot.parts) {
        const object = plan!.objects.find((o) =>
          o.name.endsWith(part.dataHash.slice(2)),
        );
        const decoded = decodeSnapshotPart(await object!.read());
        if (decoded.kind !== "ok") throw new Error("part did not decode");
        parts.push(decoded.part);
      }
      const segments = [...(await w.segments()).values()].filter(
        (s: WireSegment) => s.position <= log.position,
      ) as unknown as Segment[];
      const oracle = foldLog({ snapshot: [], segments });
      expect(segments.length).toBeGreaterThan(3);
      expect(parts.length).toBeGreaterThan(1);
      expect(parts.flatMap((p) => p.entries)).toEqual(
        oracle.entries as LogEntry[],
      );
      expect(parts[0]!.streams).toEqual(oracle.streams);
      await spool.discard();
    }, 60_000);
  }
});
