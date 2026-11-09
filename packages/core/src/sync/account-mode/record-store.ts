import type { DurableModeRecord } from "./mode-machine.js";

/**
 * Where the records live: one per owner, outside the data database that a wipe
 * or rebuild can empty. The Node host keeps a file per owner; Lite keeps its
 * own IndexedDB database.
 *
 * One store has one owning runtime. `claim` takes that ownership with the
 * store's own primitive (a lock file on Node, a Web Lock on Lite) and rejects
 * with `ModeStoreOwnedError` while another runtime holds it. A runtime that
 * cannot claim the store never writes, and never admits legacy work.
 *
 * `save` is a compare-and-set: it writes `next` only if the stored record is
 * exactly `expected` (null = no record), and only if the write is monotone
 * (see `assertMonotoneWrite`). Otherwise it rejects with
 * `ModeStoreConflictError` and leaves the record as it was. The authority
 * counts that as a failed save.
 *
 * `save` resolves only when the record is durable, and rejects otherwise. The
 * authority never serves an answer that depends on a record until `save` has
 * resolved. `load` returns every stored record; one that cannot be read is
 * left out, so its owner is unknown until the Account answers again. `load`
 * deletes nothing and needs no ownership.
 */
export interface ModeRecordStore {
  claim(): Promise<ModeStoreLease>;
  load(): Promise<Map<string, DurableModeRecord>>;
  save(
    owner: string,
    next: DurableModeRecord,
    expected: DurableModeRecord | null,
  ): Promise<void>;
}

/** Ownership of a store. Dropping it, by release or by a crash, frees the store. */
export interface ModeStoreLease {
  release(): Promise<void>;
}

/** Another runtime owns this store. */
export class ModeStoreOwnedError extends Error {
  constructor(detail = "another runtime owns the account mode records") {
    super(detail);
    this.name = "ModeStoreOwnedError";
  }
}

/** A save was based on a record that is no longer the stored one, or lowers it. */
export class ModeStoreConflictError extends Error {
  constructor(detail = "the stored account mode record changed") {
    super(detail);
    this.name = "ModeStoreConflictError";
  }
}

export function sameDurableRecord(
  a: DurableModeRecord | null,
  b: DurableModeRecord | null,
): boolean {
  if (a === null || b === null) return a === b;
  return (
    a.switched === b.switched &&
    a.switchedAt === b.switchedAt &&
    a.cleanOffAt === b.cleanOffAt &&
    a.offFetchStartMono === b.offFetchStartMono &&
    a.bootId === b.bootId &&
    a.importPending === b.importPending &&
    (a.historyUnknown === true) === (b.historyUnknown === true) &&
    (a.generation ?? 0) === (b.generation ?? 0)
  );
}

/**
 * The rule every store applies, in its own transaction or critical section,
 * before it writes. `current` is what the store holds now.
 * - The write must be based on the current record (`expected`), so a writer
 *   that read an older record cannot overwrite a newer one.
 * - An On is never lowered to Off, and a cleared import flag is never raised
 *   again. The one exception is a reset: an Off whose generation is higher
 *   than the stored On's. A generation is never lowered by any write.
 * - A tombstone (`historyUnknown`) is never written by `save`: only a store's
 *   own quarantine path makes one, and an On is never replaced by one.
 * - Over a tombstone only an On with the import owed is written. An Off record
 *   is refused: the owner's history is unknown, so no Off can be minted.
 */
export function assertMonotoneWrite(
  current: DurableModeRecord | null,
  expected: DurableModeRecord | null,
  next: DurableModeRecord,
): void {
  if (!sameDurableRecord(current, expected)) {
    throw new ModeStoreConflictError(
      "the write is based on a record that is no longer stored",
    );
  }
  if (next.historyUnknown === true) {
    throw new ModeStoreConflictError(
      "a tombstone is written only by the store's own quarantine",
    );
  }
  if (current?.historyUnknown === true) {
    if (!next.switched || !next.importPending) {
      throw new ModeStoreConflictError(
        "an owner with unknown history can only be written as On with an import owed",
      );
    }
    return;
  }
  const generation = next.generation ?? 0;
  if (!Number.isSafeInteger(generation) || generation < 0) {
    throw new ModeStoreConflictError("a generation is a non-negative integer");
  }
  if (current !== null && generation < (current.generation ?? 0)) {
    throw new ModeStoreConflictError("a generation is never lowered");
  }
  if (current?.switched === true) {
    if (!next.switched) {
      // A reset is the one lowering: it needs a higher generation than the On.
      if (generation > (current.generation ?? 0)) return;
      throw new ModeStoreConflictError("an On record cannot be lowered");
    }
    if (!current.importPending && next.importPending) {
      throw new ModeStoreConflictError("a finished import cannot be reopened");
    }
  }
}
