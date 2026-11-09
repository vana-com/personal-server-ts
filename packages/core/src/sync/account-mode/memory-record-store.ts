/**
 * An in-memory record store with failure and pause hooks, for tests and for
 * hosts with nothing durable to offer (such a host gets no durable On: every
 * restart starts with no records, so it refuses until the Account answers).
 */

import type { ModeRecordStore, OwnerModeRecord } from "./reduce-adapter.js";

export interface MemoryModeRecordStore extends ModeRecordStore {
  /** What is "on disk" right now. Survives a simulated restart. */
  readonly durable: Map<string, OwnerModeRecord>;
  /** Make the next saves fail until `failSaves(false)`. */
  failSaves(fail: boolean): void;
  /** Hold every save until `releaseSaves()`. Returns after the first is held. */
  pauseSaves(): void;
  releaseSaves(): void;
  /**
   * Forget held saves without letting them write, as a crash does: they stay
   * pending forever and the store accepts new saves again.
   */
  abandonHeldSaves(): void;
  /** Fail every load until `failLoads(false)`. */
  failLoads(fail: boolean): void;
  /** Drop every record, as a wiped data folder would. */
  wipe(): void;
  readonly saveCalls: number;
}

export function createMemoryModeRecordStore(
  initial?: Iterable<[string, OwnerModeRecord]>,
): MemoryModeRecordStore {
  const durable = new Map<string, OwnerModeRecord>(initial ?? []);
  let failing = false;
  let failingLoads = false;
  let gate: Promise<void> | null = null;
  let open: (() => void) | null = null;
  let saveCalls = 0;
  return {
    durable,
    get saveCalls() {
      return saveCalls;
    },
    async load() {
      if (failingLoads) throw new Error("record store load failed");
      return new Map([...durable].map(([k, v]) => [k, { ...v }]));
    },
    async save(owner, record) {
      saveCalls += 1;
      if (gate) await gate;
      if (failing) throw new Error("record store save failed");
      durable.set(owner, { ...record });
    },
    failSaves(fail) {
      failing = fail;
    },
    failLoads(fail) {
      failingLoads = fail;
    },
    pauseSaves() {
      if (gate) return;
      gate = new Promise<void>((resolve) => {
        open = resolve;
      });
    },
    releaseSaves() {
      const release = open;
      gate = null;
      open = null;
      release?.();
    },
    abandonHeldSaves() {
      gate = null;
      open = null;
    },
    wipe() {
      durable.clear();
    },
  };
}
