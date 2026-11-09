import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import {
  OFF_TTL_MS, createModeRecord, reduceAccountMode,
  type AccountModeRecord, type ModeClock, type ModeDecision, type ModeEvent,
} from "./mode-machine.js";
import {
  MemoryAccountModeRecordStore, reduceStoredAccountMode, type AccountModeRecordStore,
} from "./record-store.js";

const clock: ModeClock = { nowMono: 100, nowWall: 1000, bootId: "boot-1" };
const evidence = (state: "on" | "off" | "unknown", extra: Partial<Extract<ModeEvent, { type: "evidence" }>> = {}): ModeEvent =>
  ({ type: "evidence", owner: "A", authOwner: "A", state, fetchStartMono: 100, rawStatus: 200, ...extra });
const read: ModeEvent = { type: "read", owner: "A" };
const save: ModeEvent = { type: "saveComplete", owner: "A" };
const commit: ModeEvent = { type: "commit", owner: "A", operationId: "same-operation", sink: "legacy" };
const unknown: ModeDecision = { kind: "refuse", code: "ACCOUNT_MODE_UNKNOWN", status: 503, retryable: true, importRequired: false };

interface Vector {
  id: string;
  initial: Record<string, AccountModeRecord | null>;
  events: Array<{ id: string; recordOwner: string; event: ModeEvent; clock: ModeClock }>;
  expect: Array<{ after: string; decision: ModeDecision; record?: Partial<AccountModeRecord>; unchanged?: boolean }>;
}
const vectors: Vector[] = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));

describe("pure real reducer against every shared vector", () => {
  for (const vector of vectors) {
    it(vector.id, () => {
      const records = { ...vector.initial };
      for (const step of vector.events) {
        const before = records[step.recordOwner] ?? null;
        const snapshot = before === null ? null : { ...before };
        if (before) Object.freeze(before);
        Object.freeze(step.event);
        Object.freeze(step.clock);
        const result = reduceAccountMode(before, step.event, step.clock);
        expect(reduceAccountMode(before, step.event, step.clock)).toEqual(result);
        expect(before).toEqual(snapshot);
        const expected = vector.expect.find(e => e.after === step.id)!;
        expect(result.decision, step.id).toEqual(expected.decision);
        if (expected.record) expect(result.record, step.id).toMatchObject(expected.record);
        if (expected.unchanged) expect(result.record, step.id).toEqual(before);
        records[step.recordOwner] = result.record;
      }
    });
  }

  it("reads neither an ambient clock nor storage", () => {
    const now = vi.spyOn(Date, "now").mockImplementation(() => { throw Error("ambient clock"); });
    let result;
    try { result = reduceAccountMode(null, evidence("off"), clock); }
    finally { now.mockRestore(); }
    expect(result?.decision.kind).toBe("legacy");
    const source = readFileSync(new URL("./mode-machine.ts", import.meta.url), "utf8");
    expect(source).not.toMatch(/\b(?:Date|performance|process|fetch)\b|^import\s/m);
  });
});

describe("named safety mutants and boundary cases", () => {
  it("UNKNOWN_AS_OFF: a failed answer invalidates an existing Off", () => {
    const off = reduceAccountMode(null, evidence("off"), clock).record;
    for (const failed of [evidence("unknown", { rawStatus: null }), evidence("off", { rawStatus: 500 })]) {
      const result = reduceAccountMode(off, failed, clock);
      expect(result.decision).toEqual(unknown);
      expect(reduceAccountMode(result.record, commit, clock).decision).toEqual(unknown);
    }
  });

  it("OFF_AFTER_ON_LOWERS: stale Off and outage do not lower saved On", () => {
    const pending = reduceAccountMode(null, evidence("on"), clock).record;
    let record = reduceAccountMode(pending, save, clock).record;
    for (const event of [evidence("off"), evidence("unknown", { rawStatus: null })]) {
      record = reduceAccountMode(record, event, clock).record;
      expect(record?.switched).toBe(true);
      expect(reduceAccountMode(record, read, clock).decision.kind).toBe("streams");
    }
  });

  it("OWNERLESS_READ_ANSWERS: missing and foreign owners change nothing", () => {
    const off = reduceAccountMode(null, evidence("off"), clock).record;
    for (const owner of [undefined, "", "B"]) {
      const result = reduceAccountMode(off, { type: "read", owner } as ModeEvent, clock);
      expect(result).toEqual({ record: off, decision: unknown });
    }
  });

  it("ADMISSION_ONLY_CHECK: commit reloads after a saved On", async () => {
    const store = new MemoryAccountModeRecordStore();
    await reduceStoredAccountMode(store, evidence("off"), clock);
    const admission = await reduceStoredAccountMode(store,
      { type: "admit", owner: "A", operationId: "same-operation" }, clock);
    expect(admission.decision.kind).toBe("legacy");
    await reduceStoredAccountMode(store, evidence("on"), clock);
    await reduceStoredAccountMode(store, save, clock);
    const result = await reduceStoredAccountMode(store, commit, clock);
    expect(result.decision).toEqual({ kind: "refuse", code: "LEGACY_REFUSED_SWITCHED",
      status: 426, retryable: false, importRequired: true });
  });

  it("LATCH_USED_BEFORE_SAVE: pending and failed On never serve either sink", () => {
    let record = reduceAccountMode(null, evidence("on"), clock).record;
    for (const event of [read, commit, { ...commit, sink: "stream" } as ModeEvent]) {
      expect(reduceAccountMode(record, event, clock).decision).toEqual(unknown);
    }
    record = reduceAccountMode(record, { type: "saveFailed", owner: "A" }, clock).record;
    expect(reduceAccountMode(record, read, clock).decision).toEqual(unknown);
    expect(record?.switched).toBe(true);
  });

  it("OFF_NEVER_EXPIRES: deadline equality expires fetch-start freshness", () => {
    const off = reduceAccountMode(null, evidence("off"), { ...clock, nowMono: 1000 }).record;
    expect(reduceAccountMode(off, read, { ...clock, nowMono: 100 + OFF_TTL_MS - 1 }).decision.kind).toBe("legacy");
    expect(reduceAccountMode(off, read, { ...clock, nowMono: 100 + OFF_TTL_MS }).decision).toEqual(unknown);
    expect(reduceAccountMode(off, read, { ...clock, nowMono: 99 }).decision).toEqual(unknown);
    expect(reduceAccountMode(off, read, { ...clock, bootId: "boot-2" }).decision).toEqual(unknown);
  });

  it("EXPIRY_LOWERS_LATCH: expiry and untrusted reboot retain saved On", () => {
    const pending = reduceAccountMode(null, evidence("on"), clock).record;
    const on = reduceAccountMode(pending, save, clock).record;
    const reboot = reduceAccountMode(on, { type: "boot", owner: "A", bootId: "boot-2", clockTrusted: false },
      { ...clock, bootId: "boot-2", nowMono: 0 });
    expect(reboot.record?.switched).toBe(true);
    expect(reduceAccountMode(reboot.record, read, { ...clock, bootId: "boot-2", nowMono: OFF_TTL_MS * 2 }).decision.kind).toBe("streams");
  });

  it("NEVER_SEEN_OWNER_ADMITS: first access is unknown, first explicit Off is immediately usable", () => {
    expect(reduceAccountMode(null, commit, clock).decision).toEqual(unknown);
    const off = reduceAccountMode(null, evidence("off"), clock);
    expect(off.decision.kind).toBe("legacy");
    expect(reduceAccountMode(off.record, commit, clock).decision.kind).toBe("legacy");
  });

  it("MISMATCHED_AUTH_OWNER_OFF: another account cannot mint or erase this record's Off", () => {
    const off = reduceAccountMode(null, evidence("off"), clock).record;
    for (const record of [null, off]) {
      expect(reduceAccountMode(record, evidence("off", { authOwner: "B" }), clock))
        .toEqual({ record, decision: unknown });
    }
  });

  it("delivers import exactly on the first read/commit, never admission or save", () => {
    let record = reduceAccountMode(null, evidence("off"), clock).record;
    record = reduceAccountMode(record, evidence("on"), clock).record;
    const saved = reduceAccountMode(record, save, clock);
    expect(saved.decision.importRequired).toBe(false);
    const admission = reduceAccountMode(saved.record, { type: "admit", owner: "A", operationId: "op" }, clock);
    expect(admission.record?.importPending).toBe(true);
    const first = reduceAccountMode(admission.record, { ...commit, sink: "stream" }, clock);
    expect(first.decision).toEqual({ kind: "streams", importRequired: true });
    expect(reduceAccountMode(first.record, read, clock).decision).toEqual({ kind: "streams", importRequired: false });
  });

  it("rejects future/expired/missing Off timestamps and invalid status without defaulting to Off", () => {
    for (const event of [
      evidence("off", { fetchStartMono: 101 }), evidence("off", { fetchStartMono: null }),
      evidence("off", { rawStatus: null }), evidence("off", { rawStatus: 300 }),
    ]) expect(reduceAccountMode(null, event, clock).decision).toEqual(unknown);
    expect(reduceAccountMode(null, evidence("off"), { ...clock, nowMono: 100 + OFF_TTL_MS }).decision).toEqual(unknown);
  });

  it("does not extend freshness when an older response arrives late", () => {
    const newer = reduceAccountMode(null, evidence("off", { fetchStartMono: 150 }), { ...clock, nowMono: 200 }).record;
    const older = reduceAccountMode(newer, evidence("off", { fetchStartMono: 100 }), { ...clock, nowMono: 300 });
    expect(older.record?.offFetchStartMono).toBe(150);
  });
});

describe("record-store test double and durable port contract", () => {
  it("serializes same-owner transitions and does not alias records", async () => {
    const store = new MemoryAccountModeRecordStore();
    const [off, on] = await Promise.all([
      reduceStoredAccountMode(store, evidence("off"), clock),
      reduceStoredAccountMode(store, evidence("on"), clock),
    ]);
    expect(off.decision.kind).toBe("legacy");
    expect(on.record?.switched).toBe(true);
    const copied = await store.read("A");
    Object.assign(copied!, { switched: false });
    expect((await store.read("A"))?.switched).toBe(true);
    expect(await store.read("B")).toBeNull();
  });

  it("never returns a usable On decision after a durable-port failure", async () => {
    const pending = reduceAccountMode(null, evidence("on"), clock).record!;
    const store: AccountModeRecordStore = {
      read: async () => pending,
      transact: async (_owner, transition) => {
        transition(pending);
        throw Error("durable save failed");
      },
    };
    await expect(reduceStoredAccountMode(store, save, clock)).rejects.toThrow("durable save failed");
    const failed = reduceAccountMode(pending, { type: "saveFailed", owner: "A" }, clock);
    expect(failed.decision).toEqual(unknown);
  });

  it("rejects foreign writes and remains usable after a rejected transition", async () => {
    const store = new MemoryAccountModeRecordStore();
    await expect(store.transact("A", () => ({ record: createModeRecord("B", "boot-1"), decision: unknown })))
      .rejects.toThrow("owner changed");
    expect(await store.read("A")).toBeNull();
    expect((await reduceStoredAccountMode(store, evidence("off"), clock)).decision.kind).toBe("legacy");
  });
});
