/**
 * An in-memory record store with failure and pause hooks, for tests and for
 * hosts with nothing durable to offer (such a host gets no durable On: every
 * restart starts with no records, so it refuses until the Account answers).
 * It models ownership too: one claim at a time, freed by release or `dropLease`.
 */

import { tombstoneRecord, type DurableModeRecord } from "./mode-machine.js";
import {
  ModeStoreOwnedError,
  assertMonotoneWrite,
  type ModeRecordStore,
  type ModeStoreLease,
} from "./record-store.js";

export interface MemoryModeRecordStore extends ModeRecordStore {
  /** What is "on disk" right now. Survives a simulated restart. */
  readonly durable: Map<string, DurableModeRecord>;
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
  /**
   * Make one owner's record unreadable, as a corrupt file is: the store sets
   * it aside and keeps a tombstone (history unknown) in its place.
   */
  quarantine(owner: string): void;
  /**
   * Free the ownership without a release call, as a crash does. Every
   * holder's lease dies with its process, so the next `claim` succeeds.
   */
  dropLease(): void;
  readonly saveCalls: number;
}

export function createMemoryModeRecordStore(
  initial?: Iterable<[string, DurableModeRecord]>,
): MemoryModeRecordStore {
  const durable = new Map<string, DurableModeRecord>(initial ?? []);
  let failing = false;
  let failingLoads = false;
  let gate: Promise<void> | null = null;
  let open: (() => void) | null = null;
  let saveCalls = 0;
  let holder: object | null = null;
  return {
    durable,
    get saveCalls() {
      return saveCalls;
    },
    async claim() {
      if (holder) throw new ModeStoreOwnedError();
      const mine = {};
      holder = mine;
      const lease: ModeStoreLease = {
        async release() {
          if (holder === mine) holder = null;
        },
      };
      return lease;
    },
    dropLease() {
      holder = null;
    },
    async load() {
      if (failingLoads) throw new Error("record store load failed");
      return new Map([...durable].map(([k, v]) => [k, { ...v }]));
    },
    async save(owner, record, expected) {
      saveCalls += 1;
      if (gate) await gate;
      if (failing) throw new Error("record store save failed");
      // Check and write with no await between them: one critical section.
      assertMonotoneWrite(durable.get(owner) ?? null, expected, record);
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
    quarantine(owner) {
      durable.set(owner, tombstoneRecord());
    },
  };
}
