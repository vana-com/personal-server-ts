/**
 * The one holder of the per-owner account-mode record, and the lock the legacy
 * write seals share with the On latch.
 *
 * - `read` is synchronous and never waits: before the first answer it is
 *   `unknown` (reads and legacy writes pause), after it `streams` or `legacy`.
 *   It follows the saved record only, so the person's data stays readable
 *   while the Account cannot be reached.
 * - `legacyWriteDecision` is what a legacy write gets. It is `read`, except
 *   that an Off holds only while the owner's latest read of the Account
 *   worked. A host that could not read the Account posts `unknown`; that
 *   pauses legacy writes (retryable 503) until the next verified answer, and
 *   erases nothing: the record, its generation and an On stay as they were.
 *   A device that kept writing on a remembered Off could not tell that another
 *   device had switched the Account. The pause lasts only until a read works,
 *   and a restart starts from the saved record until its host reads.
 * - A load that fails leaves the authority unloaded: `read` stays `unknown`
 *   for every owner, `submitEvidence` saves nothing, and the next
 *   `submitEvidence` retries the load before judging the evidence.
 * - `submitEvidence` takes the lock exclusively, saves the new record, then
 *   publishes it. A save that fails throws and changes nothing in memory.
 * - `commitLegacy` takes the lock shared and reads the record inside it with no
 *   await before the write starts. An On therefore waits for every legacy
 *   write already running, and no legacy write starts after it. This is the
 *   commit fence: a check made before the lock is only an early refusal.
 * - A write run under `commitLegacy` or `commitRemoval` must not call either
 *   again: the inner call would wait behind a queued On that waits for it.
 */

import {
  SWITCHED_REFUSAL,
  UNKNOWN_DECISION,
  applyAnswer,
  normalizeOwner,
  type AccountModeRecord,
  type ModeDecision,
  type ModeRecordStore,
  type RefuseDecision,
} from "./record.js";
import { createRwLock } from "./rw-lock.js";

export type CommitResult<T> =
  { ok: true; value: T } | { ok: false; decision: RefuseDecision };

/** What a host says about one owner after asking the Account. */
export interface ModeEvidenceInput {
  owner: string;
  /**
   * `unknown` (or anything else): the host could not read the Account. It
   * changes no record; it pauses legacy writes for an Off until a verified
   * answer, and returns the decision.
   */
  state: "on" | "off" | "unknown";
  /** Absent means 0. */
  generation?: number;
}

export interface ModeAuthority {
  /** Settles once the saved records are loaded. Never rejects; boot may skip it. */
  readonly ready: Promise<void>;
  /** The mode that reads and listings follow: the saved record, nothing else. */
  read(owner: string): ModeDecision;
  /**
   * What a legacy write gets right now, with no lock: for an early refusal or
   * a worker that wants to stop. The commit fence (`commitLegacy`) is the
   * decision; this is never a permission.
   */
  legacyWriteDecision(owner: string): ModeDecision;
  submitEvidence(input: ModeEvidenceInput): Promise<ModeDecision>;
  /** Run `write` as a legacy write: only for an owner whose answer is Off. */
  commitLegacy<T>(
    owner: string,
    write: () => T | Promise<T>,
  ): Promise<CommitResult<T>>;
  /** Run a pure removal under the same lock, in every mode. */
  commitRemoval<T>(work: () => T | Promise<T>): Promise<T>;
  /** Wait for work in flight, then refuse new legacy writes. */
  close(): Promise<void>;
}

export interface ModeAuthorityOptions {
  store: ModeRecordStore;
  now?: () => number;
  /** Called after an answer that leaves the owner On (the import wake-up). */
  onOn?: (owner: string) => void;
  onWarning?: (message: string, detail?: unknown) => void;
}

export function createModeAuthority(
  options: ModeAuthorityOptions,
): ModeAuthority {
  const now = options.now ?? Date.now;
  const warn = options.onWarning ?? (() => {});
  const records = new Map<string, AccountModeRecord>();
  const lock = createRwLock();
  /**
   * Owners whose latest read of the Account failed. In memory only: a record
   * is history, this is what the host last saw, and a process that has seen
   * nothing yet has nothing to report.
   */
  const unreadable = new Set<string>();
  let loaded = false;
  let loadFailed = false;
  let closed = false;
  /** One retry in flight, shared so concurrent evidence does not reload twice. */
  let reloadInFlight: Promise<void> | null = null;

  async function attemptLoad(): Promise<void> {
    try {
      const saved = await options.store.load();
      records.clear();
      for (const [owner, record] of saved)
        records.set(normalizeOwner(owner), record);
      loaded = true;
      loadFailed = false;
    } catch (error: unknown) {
      // A failed load is a distinct state, not an empty record set: the
      // records stay unloaded, reads stay unknown, and evidence saves nothing
      // until a later submit retries the load.
      warn("account mode records could not be loaded", error);
      loadFailed = true;
    }
  }

  const ready = attemptLoad();

  async function retryLoadIfFailed(): Promise<void> {
    if (!loadFailed) return;
    if (!reloadInFlight) {
      reloadInFlight = attemptLoad().finally(() => {
        reloadInFlight = null;
      });
    }
    await reloadInFlight;
  }

  function read(owner: string): ModeDecision {
    const record =
      loaded && typeof owner === "string"
        ? records.get(normalizeOwner(owner))
        : undefined;
    if (!record) return UNKNOWN_DECISION;
    return record.answer === "on" ? { kind: "streams" } : { kind: "legacy" };
  }

  function legacyWriteDecision(owner: string): ModeDecision {
    const decision = read(owner);
    return decision.kind === "legacy" &&
      typeof owner === "string" &&
      unreadable.has(normalizeOwner(owner))
      ? UNKNOWN_DECISION
      : decision;
  }

  return {
    ready,
    read,
    legacyWriteDecision,
    async submitEvidence(input) {
      await ready;
      const owner = normalizeOwner(input.owner);
      if (input.state === "on" || input.state === "off") {
        const release = await lock.exclusive();
        try {
          // Retried under the lock, so the exclusive request is queued before
          // the load starts: an On still waits for legacy writes in flight,
          // and no legacy write starts after it.
          await retryLoadIfFailed();
          if (loadFailed) {
            // Still no records to judge against: save nothing, change nothing.
            return read(owner);
          }
          const prev = records.get(owner);
          const next = applyAnswer(
            prev,
            input.state,
            input.generation ?? 0,
            now(),
          );
          if (next !== prev) {
            await options.store.save(owner, next);
            records.set(owner, next);
          }
          // A verified answer, at any generation, ends the pause. A save
          // that threw above never reaches this line, so it ends nothing.
          unreadable.delete(owner);
        } finally {
          release();
        }
      } else {
        await retryLoadIfFailed();
        // Taking no lock is safe: a legacy write already running keeps its
        // shared hold, and every write that starts later reads this inside
        // its own hold.
        unreadable.add(owner);
      }
      const decision = legacyWriteDecision(owner);
      if (decision.kind === "streams") {
        try {
          options.onOn?.(owner);
        } catch (error) {
          warn("the On callback failed", error);
        }
      }
      return decision;
    },
    async commitLegacy(owner, write) {
      await ready;
      const release = await lock.shared();
      try {
        // No await between this read and the start of the write.
        const decision = closed ? UNKNOWN_DECISION : legacyWriteDecision(owner);
        if (decision.kind === "legacy") {
          return { ok: true, value: await write() };
        }
        return {
          ok: false,
          decision:
            decision.kind === "streams"
              ? SWITCHED_REFUSAL
              : (decision as RefuseDecision),
        };
      } finally {
        release();
      }
    },
    async commitRemoval(work) {
      const release = await lock.shared();
      try {
        return await work();
      } finally {
        release();
      }
    },
    async close() {
      closed = true;
      (await lock.exclusive())();
    },
  };
}
