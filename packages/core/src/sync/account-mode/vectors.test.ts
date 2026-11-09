import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  OFF_TTL_MS,
  reduceAccountMode,
  type AccountModeRecord,
  type ModeClock,
  type ModeDecision,
  type ModeEvent,
} from "./mode-machine.js";
import { MemoryAccountModeRecordStore } from "./record-store.js";

interface Vector {
  version: number;
  id: string;
  policy: { offTtlMs: number };
  owners: string[];
  initial: Record<string, AccountModeRecord | null>;
  events: Array<{
    id: string;
    recordOwner: string;
    event: ModeEvent;
    clock: ModeClock;
  }>;
  expect: Array<{
    after: string;
    decision: ModeDecision;
    record?: Partial<AccountModeRecord>;
    unchanged?: boolean;
  }>;
}
const vectors: Vector[] = JSON.parse(
  readFileSync(new URL("./vectors.json", import.meta.url), "utf8"),
);

describe("shared mode vectors through the record-store port", () => {
  it("has all twelve scenarios, unique event IDs and exactly one oracle per event", () => {
    expect(vectors).toHaveLength(12);
    expect(new Set(vectors.map((v) => v.id)).size).toBe(12);
    for (const vector of vectors) {
      expect(vector.version).toBe(1);
      expect(vector.policy.offTtlMs).toBe(OFF_TTL_MS);
      expect(new Set(vector.events.map((e) => e.id)).size).toBe(
        vector.events.length,
      );
      expect(vector.expect.map((e) => e.after)).toEqual(
        vector.events.map((e) => e.id),
      );
    }
  });

  // Every expectation is written in JSON, not derived from a second policy.
  for (const vector of vectors) {
    it(vector.id, async () => {
      const initial = Object.values(vector.initial).filter(
        (r): r is AccountModeRecord => r !== null,
      );
      const store = new MemoryAccountModeRecordStore(initial);
      for (const step of vector.events) {
        const expected = vector.expect.find((e) => e.after === step.id)!;
        const before = await store.read(step.recordOwner);
        // recordOwner is the host's bound record key, deliberately different
        // from event.owner in the mismatch vectors.
        const result = await store.transact(step.recordOwner, (record) =>
          reduceAccountMode(record, step.event, step.clock),
        );
        expect(result.decision, vector.id + "/" + step.id).toEqual(
          expected.decision,
        );
        if (expected.record)
          expect(result.record, step.id).toMatchObject(expected.record);
        if (expected.unchanged) expect(result.record, step.id).toEqual(before);
        expect(await store.read(step.recordOwner)).toEqual(result.record);
      }
    });
  }
});
