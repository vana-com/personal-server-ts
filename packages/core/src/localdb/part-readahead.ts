import type { HeadPart } from "@opendatalabs/personal-server-ts-stream-sync";
import type { StreamSyncBlobs } from "../stream-sync/ports.js";
import type { Reservation } from "../stream-sync/send-gate.js";
import { holdMemory } from "./transfer-memory.js";

/**
 * The parts of a head, fetched ahead of the one the apply is on.
 *
 * Apply reads a head's parts in order and commits each one before it asks for
 * the next. Without read-ahead the part's GET, its decrypt and its commit run
 * one after another, so a first load takes the sum of the three and the
 * downlink is idle while the database writes. With read-ahead the GET and the
 * decrypt of the parts that follow run during the commit of this one, so the
 * load takes the longer of the two sides.
 *
 * How far ahead is not a number here. Two limits already bound it:
 *
 *  - Memory: a part reserves its bytes from the store's byte budget
 *    (`holdMemory`), as plain and as encrypted bytes, before its GET starts.
 *    The reservation ends when the apply commits the part, so a part in hand
 *    or waiting for its commit stays counted. The budget is shared with uploads, so read-ahead
 *    cannot take memory a transfer needs.
 *  - The wire: every GET goes through the store's send gate, so the requests
 *    on the wire are the gate's window, whatever is queued behind it.
 *
 * A reservation waits for budget while the reader holds earlier parts. That
 * cannot deadlock: the apply consumes held parts without a reservation of its
 * own, and each consumed part gives its bytes back, so every wait ends.
 * (`holdMemory` asks a holder to reserve only while it holds none; the parts
 * of a reader leave in order, which has the same effect.)
 *
 * `load` has the signature `framesOfParts` calls and is asked for parts in
 * order. A part is read once.
 */
export interface PartReader {
  readonly load: (part: HeadPart, index: number) => Promise<Uint8Array>;
  /**
   * Whether the part at `index` has been fetched, so reading it waits for
   * nothing and cannot fail. A part whose fetch failed is not ready: the apply
   * commits what it holds before it reads that part and meets the error.
   */
  readonly ready: (index: number) => boolean;
  /**
   * The apply has committed the parts up to and including `index`: give back
   * their reservations. A part stays reserved from its GET until its commit,
   * since its rows are in memory until then.
   */
  readonly committed: (index: number) => void;
  /** Stop fetching and give back every reservation. Safe to call twice. */
  readonly close: () => void;
}

export function readPartsAhead(
  blobs: Pick<StreamSyncBlobs, "governor">,
  parts: readonly HeadPart[],
  fetch: (part: HeadPart) => Promise<Uint8Array>,
): PartReader {
  type Slot = {
    promise: Promise<Uint8Array>;
    resolve: (bytes: Uint8Array) => void;
    reject: (error: unknown) => void;
    hold?: Reservation;
    settled: boolean;
    /** The part was fetched; a failed fetch is settled but not fetched. */
    fetched: boolean;
    released: boolean;
  };
  const slots: Slot[] = parts.map(() => {
    const slot = { settled: false, fetched: false, released: false } as Slot;
    slot.promise = new Promise((resolve, reject) => {
      slot.resolve = resolve;
      slot.reject = reject;
    });
    // An error is raised where the apply asks for the part; a part the apply
    // never asks for must not raise an unhandled rejection.
    slot.promise.catch(() => undefined);
    return slot;
  });
  let closed = false;
  let behind = 0;

  const release = (slot: Slot | undefined) => {
    if (slot === undefined || slot.released || slot.hold === undefined) return;
    slot.released = true;
    slot.hold();
  };

  void (async () => {
    for (let i = 0; i < parts.length && !closed; i++) {
      const part = parts[i]!;
      const slot = slots[i]!;
      try {
        slot.hold = await holdMemory(blobs, 2 * part.bytes, part.bytes);
      } catch (error) {
        // A reservation the store refuses is the part's own error, raised
        // where the apply reads it.
        slot.reject(error);
        return;
      }
      if (closed) {
        release(slot);
        return;
      }
      fetch(part).then((bytes) => {
        slot.fetched = true;
        slot.resolve(bytes);
      }, slot.reject);
      slot.promise
        .then(
          () => undefined,
          () => undefined,
        )
        .then(() => {
          slot.settled = true;
          if (closed) release(slot);
        });
    }
  })();

  return {
    async load(_part, index) {
      if (closed) throw new Error("apply: part read after close");
      return slots[index]!.promise;
    },
    ready: (index) => slots[index]?.fetched === true,
    committed(index) {
      // A long frame's skipped parts are released with the rest.
      for (; behind <= index; behind++) release(slots[behind]);
    },
    close() {
      closed = true;
      for (const slot of slots) if (slot.settled) release(slot);
    },
  };
}
