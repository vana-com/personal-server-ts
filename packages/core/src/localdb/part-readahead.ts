import type { HeadPart } from "@opendatalabs/personal-server-ts-stream-sync";
import type { StreamSyncBlobs } from "../stream-sync/ports.js";
import type { Reservation } from "../stream-sync/send-gate.js";
import { holdMemory } from "./transfer-memory.js";

/**
 * The parts of a head, fetched ahead of the one the apply is on.
 *
 * Apply reads a head's parts in order and commits what it has read before it
 * waits for storage. Without read-ahead the part's GET, its decrypt and its
 * commit run one after another, so a first load takes the sum of the three and
 * the downlink is idle while the database writes. With read-ahead the GET and
 * the decrypt of the parts that follow run during the commit of this one, so
 * the load takes the longer of the two sides.
 *
 * How far ahead is not a number here. Two limits already bound it:
 *
 *  - Memory: a unit of parts reserves its bytes from the store's byte budget
 *    (`holdMemory`), as plain and as encrypted bytes, before its first GET
 *    starts. The reservation ends when the apply commits the unit, so a unit
 *    in hand or waiting for its commit stays counted. The budget is shared
 *    with uploads and with other readers.
 *  - The wire: every GET goes through the store's send gate, so the requests
 *    on the wire are the gate's window, whatever is queued behind it.
 *
 * The unit of admission is a frame's whole run of parts. A record longer than
 * a part spans several (`HeadPart.count` is 0 for a part that continues the
 * frame before it), and the apply cannot commit any of them until it has read
 * them all. A reservation per part would let the first parts of a long record
 * hold the budget while its later parts wait for it, and the commit that frees
 * the budget waits for those later parts. So a unit reserves once, for all of
 * its parts. A unit larger than the budget is admitted alone, once nothing
 * else is held (the budget's own rule for an oversized request), so a record
 * of any size proceeds; the memory it holds is the record's, as in a read that
 * has no read-ahead.
 *
 * That makes every wait of the reader end. A reservation waits for held units
 * that the apply has fetched, and the apply commits what it holds whenever the
 * next unit is not yet fetched, so it never waits for the budget while it
 * holds units; each commit gives its bytes back. Readers that share a budget
 * wait on each other in the same way, and none holds a unit while waiting for
 * a unit's worth of budget that only another waiting reader could free.
 *
 * Memory is held only for units in flight and fetched but uncommitted: a part
 * the apply has read is dropped from the reader at once, with its promise, so
 * a large head is not retained by the reader.
 *
 * `load` has the signature `framesOfParts` calls and is asked for parts in
 * order. A part is read once.
 */
export interface PartReader {
  readonly load: (part: HeadPart, index: number) => Promise<Uint8Array>;
  /**
   * Whether the unit of the part at `index` has been fetched, so reading it
   * waits for nothing and cannot fail. A part whose fetch failed is not
   * ready: the apply commits what it holds before it reads that part and
   * meets the error. Ready means fetched and decrypted; the apply still
   * verifies the part's hash and its records.
   */
  readonly ready: (index: number) => boolean;
  /**
   * The apply has committed the parts up to and including `index`: give back
   * the reservation of every unit that ends there or before. A unit stays
   * reserved from its first GET until its commit, since its rows are in memory
   * until then.
   */
  readonly committed: (index: number) => void;
  /** Stop fetching and give back every reservation. Safe to call twice. */
  readonly close: () => void;
}

/** The parts of one frame: its first part and the parts that continue it. */
interface Unit {
  /** Index of its first part in the read list. */
  readonly first: number;
  /** Index of its last part. */
  readonly last: number;
  hold?: Reservation;
  fetched: number;
  /** Fetches that have ended, whether they succeeded or failed. */
  settled: number;
  released: boolean;
}

interface Slot {
  /** Cleared once the apply has read the part, so the bytes are not kept.
   * `resolve` and `reject` stay until the fetch ends, then go too. */
  promise?: Promise<Uint8Array>;
  resolve?: (bytes: Uint8Array) => void;
  reject?: (error: unknown) => void;
  unit: Unit;
}

export function readPartsAhead(
  blobs: Pick<StreamSyncBlobs, "governor">,
  parts: readonly HeadPart[],
  fetch: (part: HeadPart) => Promise<Uint8Array>,
): PartReader {
  const units: Unit[] = [];
  for (let i = 0; i < parts.length; i++) {
    const open = units[units.length - 1];
    // A part that continues a frame joins the unit of the frame it continues.
    if (open !== undefined && parts[i]!.count === 0) {
      units[units.length - 1] = { ...open, last: i };
    } else {
      units.push({
        first: i,
        last: i,
        fetched: 0,
        settled: 0,
        released: false,
      });
    }
  }
  const slots: Slot[] = [];
  for (const unit of units) {
    for (let i = unit.first; i <= unit.last; i++) {
      const slot: Slot = { unit };
      slot.promise = new Promise((resolve, reject) => {
        slot.resolve = resolve;
        slot.reject = reject;
      });
      // An error is raised where the apply asks for the part; a part the apply
      // never asks for must not raise an unhandled rejection.
      slot.promise.catch(() => undefined);
      slots[i] = slot;
    }
  }
  let closed = false;
  // Units before this one are committed.
  let behind = 0;

  /**
   * The slot's settle functions, once. They refer to the slot's promise, and
   * with it to the bytes, so the slot keeps none after the part settles.
   */
  const end = (slot: Slot) => {
    const { resolve, reject } = slot;
    slot.resolve = slot.reject = undefined;
    return resolve === undefined || reject === undefined
      ? undefined
      : { resolve, reject };
  };
  const release = (unit: Unit) => {
    if (unit.released || unit.hold === undefined) return;
    unit.released = true;
    unit.hold();
  };
  /** The apply gave up this unit (close): free it when its fetches end. */
  const releaseWhenSettled = (unit: Unit) => {
    if (unit.settled === unit.last - unit.first + 1) release(unit);
  };

  void (async () => {
    for (let n = 0; n < units.length && !closed; n++) {
      const unit = units[n]!;
      let bytes = 0;
      let largest = 0;
      for (let i = unit.first; i <= unit.last; i++) {
        bytes += parts[i]!.bytes;
        largest = Math.max(largest, parts[i]!.bytes);
      }
      try {
        unit.hold = await holdMemory(blobs, 2 * bytes, largest);
      } catch (error) {
        // A reservation the store refuses is the part's own error, raised
        // where the apply reads it.
        for (let i = unit.first; i <= unit.last; i++)
          end(slots[i]!)?.reject(error);
        return;
      }
      if (closed) {
        release(unit);
        return;
      }
      for (let i = unit.first; i <= unit.last; i++) {
        const slot = slots[i]!;
        fetch(parts[i]!)
          .then(
            (data) => {
              unit.fetched++;
              end(slot)?.resolve(data);
            },
            (error) => end(slot)?.reject(error),
          )
          .finally(() => {
            unit.settled++;
            if (closed) releaseWhenSettled(unit);
          });
      }
    }
  })();

  return {
    async load(_part, index) {
      if (closed) throw new Error("apply: part read after close");
      const slot = slots[index];
      if (slot?.promise === undefined)
        throw new Error("apply: part read twice");
      const { promise } = slot;
      // Drop the reader's reference as the apply takes the bytes: a part that
      // is read and committed is then free, and so is its slot.
      slot.promise = undefined;
      return promise;
    },
    ready(index) {
      const unit = slots[index]?.unit;
      return unit !== undefined && unit.fetched === unit.last - unit.first + 1;
    },
    committed(index) {
      for (; behind < units.length && units[behind]!.last <= index; behind++)
        release(units[behind]!);
    },
    close() {
      closed = true;
      for (const unit of units) releaseWhenSettled(unit);
    },
  };
}
